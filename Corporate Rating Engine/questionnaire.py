"""questionnaire.py — the rating workbook's Cybersecurity Questionnaire, evaluated without Excel.

Source of truth is the workbook itself. tools/gen_questionnaire.py copies the questionnaire sheet's
cells verbatim (weights, answers, formulas as text) plus every lookup cell they reference into
questionnaire_model.json. This module re-evaluates those formulas for a client's answers, so the
posture score (H282), the maturity multiplier it bands into on the price sheet (C11 -> C12) and the
workbook's underwriting flags (I282 vs J282) come out exactly as the workbook computes them.

On top of the workbook it applies the condensed CONDITIONS OF COVER (the minimum controls needed to
incept). The posture only becomes a premium modifier once every applicable condition is met.

Public API
  assess(answers, context=None) -> posture, maturity, sections, workbook flags, conditions gate
  read_form(pdf_path)           -> answers + company details from a filled proposal-form PDF
  assess_form(pdf_path, ...)    -> read_form + assess in one call
  describe()                    -> question list (rows, choices, gating) + condition definitions
  selftest()                    -> re-computes the workbook's own example and diffs every cell
"""
import json
import os
import re
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODEL_PATH = Path(os.environ.get("QUESTIONNAIRE_MODEL", str(HERE / "questionnaire_model.json")))


# =============================================================================
# Excel formula evaluator — exactly the subset the questionnaire uses
# (IF, IFERROR, SUM, AND, OR, XLOOKUP, comparisons, arithmetic, %, &).
# Any other function raises, so a workbook change that adds one fails selftest loudly.
# =============================================================================
class XLError(Exception):
    """An Excel error value (#N/A, #VALUE!, ...). Raised while evaluating, stored as a cell value."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


_MISSING = object()

_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<str>"(?:[^"]|"")*")
  | (?P<ref>(?:(?:'(?:[^']|'')+'|[A-Za-z_][A-Za-z0-9_.]*)!)?\$?[A-Z]{1,3}\$?\d+(?::\$?[A-Z]{1,3}\$?\d+)?)(?![A-Za-z0-9_(])
  | (?P<num>\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\.\d+)
  | (?P<func>[A-Za-z_][A-Za-z0-9_.]*)\(
  | (?P<bool>TRUE|FALSE)(?![A-Za-z0-9_(])
  | (?P<op><>|>=|<=|[-+*/^&=<>%])
  | (?P<lp>\() | (?P<rp>\)) | (?P<comma>,)
""", re.X)

_REF = re.compile(r"^(?:(?:'((?:[^']|'')+)'|([A-Za-z_][A-Za-z0-9_.]*))!)?"
                  r"\$?([A-Z]{1,3})\$?(\d+)(?::\$?([A-Z]{1,3})\$?(\d+))?$")


def _col_idx(letters):
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n


def _col_letters(n):
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _tokenize(src):
    out, pos = [], 0
    while pos < len(src):
        m = _TOKEN.match(src, pos)
        if not m:
            raise SyntaxError("cannot tokenise formula at %r" % src[pos:pos + 25])
        pos = m.end()
        if m.lastgroup != "ws":
            out.append((m.lastgroup, m.group(m.lastgroup)))
    return out


def _split_ref(text):
    m = _REF.match(text)
    if not m:
        raise SyntaxError("bad reference %r" % text)
    sheet = m.group(1).replace("''", "'") if m.group(1) else m.group(2)
    c2 = m.group(5)
    return sheet, m.group(3), int(m.group(4)), c2, (int(m.group(6)) if c2 else None)


def _expand(sheet, c1, r1, c2, r2):
    if c2 is None:
        return [(sheet, "%s%d" % (c1, r1))]
    return [(sheet, "%s%d" % (_col_letters(c), r))
            for r in range(r1, r2 + 1) for c in range(_col_idx(c1), _col_idx(c2) + 1)]


class _Parser:
    CMP = ("=", "<>", "<", ">", "<=", ">=")

    def __init__(self, toks):
        self.toks, self.i = toks, 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else ("end", None)

    def take(self):
        t = self.peek()
        self.i += 1
        return t

    def is_op(self, *ops):
        k, v = self.peek()
        return k == "op" and v in ops

    def expr(self):
        n = self.concat()
        while self.is_op(*self.CMP):
            op = self.take()[1]
            n = ("cmp", op, n, self.concat())
        return n

    def concat(self):
        n = self.additive()
        while self.is_op("&"):
            self.take()
            n = ("cat", n, self.additive())
        return n

    def additive(self):
        n = self.term()
        while self.is_op("+", "-"):
            op = self.take()[1]
            n = ("bin", op, n, self.term())
        return n

    def term(self):
        n = self.power()
        while self.is_op("*", "/"):
            op = self.take()[1]
            n = ("bin", op, n, self.power())
        return n

    def power(self):
        n = self.unary()
        while self.is_op("^"):
            self.take()
            n = ("bin", "^", n, self.unary())
        return n

    def unary(self):
        if self.is_op("-"):
            self.take()
            return ("neg", self.unary())
        if self.is_op("+"):
            self.take()
            return self.unary()
        return self.postfix()

    def postfix(self):
        n = self.primary()
        while self.is_op("%"):
            self.take()
            n = ("pct", n)
        return n

    def primary(self):
        kind, val = self.take()
        if kind == "num":
            return ("lit", float(val))
        if kind == "str":
            return ("lit", val[1:-1].replace('""', '"'))
        if kind == "bool":
            return ("lit", val == "TRUE")
        if kind == "ref":
            return ("ref",) + _split_ref(val)
        if kind == "func":
            name = val.upper()
            if name.startswith("_XLFN."):
                name = name[6:]
            args = []
            if self.peek()[0] == "rp":
                self.take()
                return ("call", name, tuple(args))
            while True:
                if self.peek()[0] in ("comma", "rp"):
                    args.append(("missing",))
                else:
                    args.append(self.expr())
                k = self.take()[0]
                if k == "rp":
                    break
                if k != "comma":
                    raise SyntaxError("bad argument list in %s()" % name)
            return ("call", name, tuple(args))
        if kind == "lp":
            n = self.expr()
            if self.take()[0] != "rp":
                raise SyntaxError("missing )")
            return n
        raise SyntaxError("unexpected token %r" % (val,))


@lru_cache(maxsize=8192)
def _parse(src):
    p = _Parser(_tokenize(src))
    node = p.expr()
    if p.i != len(p.toks):
        raise SyntaxError("trailing tokens in %r" % src)
    return node


class _Range:
    __slots__ = ("cells",)

    def __init__(self, cells):
        self.cells = cells


def _num(v):
    if v is None or v is _MISSING:
        return 0.0
    if isinstance(v, XLError):
        raise v
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    try:
        return float(s[:-1]) / 100.0 if s.endswith("%") else float(s)
    except ValueError:
        raise XLError("#VALUE!")


def _truthy(v):
    if v is None or v is _MISSING:
        return False
    if isinstance(v, XLError):
        raise v
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    s = str(v).strip().upper()
    if s in ("TRUE", "FALSE"):
        return s == "TRUE"
    raise XLError("#VALUE!")


def _text(v):
    if v is None or v is _MISSING:
        return ""
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def _blank_like(v, other):
    if v is not None and v is not _MISSING:
        return v
    if isinstance(other, str):
        return ""
    if isinstance(other, bool):
        return False
    return 0.0


def _rank(v):
    if isinstance(v, bool):
        return (2, v)
    if isinstance(v, (int, float)):
        return (0, float(v))
    return (1, str(v).lower())  # Excel text comparison is case-insensitive


def _compare(op, a, b):
    for v in (a, b):
        if isinstance(v, XLError):
            raise v
    a, b = _blank_like(a, b), _blank_like(b, a)
    ka, kb = _rank(a), _rank(b)
    return {"=": ka == kb, "<>": ka != kb, "<": ka < kb, ">": ka > kb,
            "<=": ka <= kb, ">=": ka >= kb}[op]


class _Book:
    """Lazy, memoised evaluation of the extracted cells, with per-cell input overrides."""

    def __init__(self, sheets, inputs=None):
        self.sheets = sheets
        self.inputs = dict(inputs or {})
        self.cache = {}
        self.active = set()

    def value(self, sheet, coord):
        key = (sheet, coord)
        if key in self.inputs:
            return self.inputs[key]
        if key in self.cache:
            return self.cache[key]
        raw = self.sheets.get(sheet, {}).get(coord)
        if not (isinstance(raw, str) and raw.startswith("=")):
            return raw
        if key in self.active:
            raise XLError("#CIRC!")
        self.active.add(key)
        try:
            v = self._scalar(_parse(raw[1:]), sheet)
        except XLError as e:
            v = e
        finally:
            self.active.discard(key)
        self.cache[key] = v
        return v

    def _scalar(self, node, sheet):
        v = self._eval(node, sheet)
        if isinstance(v, _Range):
            if len(v.cells) != 1:
                raise XLError("#VALUE!")
            v = v.cells[0]
        if v is _MISSING:
            return None
        if isinstance(v, XLError):
            raise v
        return v

    def _eval(self, n, sheet):
        t = n[0]
        if t == "lit":
            return n[1]
        if t == "missing":
            return _MISSING
        if t == "ref":
            _, sh, c1, r1, c2, r2 = n
            sh = sh or sheet
            if c2 is None:
                v = self.value(sh, "%s%d" % (c1, r1))
                if isinstance(v, XLError):
                    raise v
                return v
            return _Range([self.value(s, c) for s, c in _expand(sh, c1, r1, c2, r2)])
        if t == "neg":
            return -_num(self._scalar(n[1], sheet))
        if t == "pct":
            return _num(self._scalar(n[1], sheet)) / 100.0
        if t == "bin":
            a, b = _num(self._scalar(n[2], sheet)), _num(self._scalar(n[3], sheet))
            op = n[1]
            if op == "+":
                return a + b
            if op == "-":
                return a - b
            if op == "*":
                return a * b
            if op == "/":
                if b == 0:
                    raise XLError("#DIV/0!")
                return a / b
            return a ** b
        if t == "cat":
            return _text(self._scalar(n[1], sheet)) + _text(self._scalar(n[2], sheet))
        if t == "cmp":
            return _compare(n[1], self._scalar(n[2], sheet), self._scalar(n[3], sheet))
        if t == "call":
            return self._call(n[1], n[2], sheet)
        raise SyntaxError("unknown node %r" % (t,))

    def _call(self, name, args, sheet):
        def ev(a):
            return self._scalar(a, sheet)

        if name == "IF":
            if _truthy(ev(args[0])):
                return ev(args[1]) if len(args) > 1 else True
            return ev(args[2]) if len(args) > 2 else False
        if name == "IFERROR":
            try:
                return ev(args[0])
            except XLError:
                return ev(args[1])
        if name == "SUM":
            total = 0.0
            for a in args:
                v = self._eval(a, sheet)
                if isinstance(v, _Range):
                    for c in v.cells:
                        if isinstance(c, XLError):
                            raise c
                        if isinstance(c, (int, float)) and not isinstance(c, bool):
                            total += c
                elif v is not _MISSING and v is not None:
                    total += _num(v)
            return total
        if name in ("AND", "OR"):
            vals = []
            for a in args:
                v = self._eval(a, sheet)
                if isinstance(v, _Range):
                    for c in v.cells:
                        if isinstance(c, XLError):
                            raise c
                        if isinstance(c, (bool, int, float)):
                            vals.append(bool(c))
                elif v is not _MISSING and v is not None:
                    vals.append(_truthy(v))
            if not vals:
                raise XLError("#VALUE!")
            return all(vals) if name == "AND" else any(vals)
        if name == "XLOOKUP":
            key = ev(args[0])
            look, ret = self._eval(args[1], sheet), self._eval(args[2], sheet)
            if not isinstance(look, _Range) or not isinstance(ret, _Range):
                raise XLError("#VALUE!")
            mode = ev(args[4]) if len(args) > 4 else None
            if mode not in (None, 0, 0.0):
                raise NotImplementedError("XLOOKUP match_mode %r" % (mode,))
            for i, c in enumerate(look.cells):
                if not isinstance(c, XLError) and _compare("=", c, key):
                    if i >= len(ret.cells):
                        raise XLError("#VALUE!")
                    v = ret.cells[i]
                    if isinstance(v, XLError):
                        raise v
                    return v
            if len(args) > 3 and args[3][0] != "missing":
                return ev(args[3])
            raise XLError("#N/A")
        raise NotImplementedError("Excel function %s() is not supported by questionnaire.py" % name)


# =============================================================================
# Model: questions, canonical answer values, flags, sections
# =============================================================================
_XL_LOOKUP = re.compile(r"XLOOKUP\(\s*\$?G\$?(\d+)\s*,\s*((?:'(?:[^']|'')+'|[A-Za-z_][\w.]*)!"
                        r"\$?[A-Z]{1,3}\$?\d+:\$?[A-Z]{1,3}\$?\d+)")
_G_EQ = re.compile(r'(?<![A-Z$])\$?G\$?(\d+)\s*=\s*"([^"]*)"')
_G_REF = re.compile(r"(?<![A-Z$])\$?G\$?(\d+)")
_FLAG = re.compile(r"(?<![A-Z$])G\d+\s*=")
_YES = {"yes", "y", "true", "1", "ja"}
_NO = {"no", "n", "false", "0", "nee"}


def _ckey(s):
    """Loose key for matching an answer to the workbook's value (dashes, spacing, '24x7', 'to')."""
    s = str(s).lower().replace("\u2013", "-").replace("\u2014", "-").replace("\u00a0", " ")
    s = re.sub(r"24\s*[x/]\s*7", "247", s)
    s = re.sub(r"(\d)\s*(?:-|to)\s*(\d)", r"\1-\2", s)
    return re.sub(r"[^a-z0-9]", "", s)


def _tokset(s):
    return set(re.findall(r"[A-Z]{3,}", str(s).upper()))


def _range_values(m, ref, default_sheet):
    sheet, c1, r1, c2, r2 = _split_ref(ref)
    sheet = sheet or default_sheet
    cells = m["sheets"].get(sheet, {})
    return [cells.get(c) for _, c in _expand(sheet, c1, r1, c2, r2)]


def _apply_corrections(m, cells):
    """Workbook corrections agreed with underwriting, applied on load until the workbook itself is
    revised. Each one is guarded, so a revised workbook that already has the fix is left alone."""
    done = []
    # Row 100 (outage at the client's own clients: time threshold) scored row 98's answer, so the
    # clients'-clients answer was ignored and row 98 counted twice. Score row 100's own answer.
    h100 = cells.get("H100")
    if isinstance(h100, str) and "XLOOKUP(G98," in h100:
        cells["H100"] = h100.replace("XLOOKUP(G98,", "XLOOKUP(G100,")
        if 100 in m["_q"]:
            m["_q"][100]["scored"] = True
        done.append("H100 scores row 100 (clients' clients outage threshold), not row 98")
    # Non-Sophos MDR detail questions (rows 259-262) all hang off row 258 ("any other MDR?");
    # row 260 is the follow-up to row 259.
    for row, parent in ((259, 258), (260, 259), (261, 258), (262, 258)):
        q = m["_q"].get(row)
        if q and (q.get("parent"), q.get("gate")) != (parent, "Yes"):
            q["parent"], q["gate"] = parent, "Yes"
            done.append("row %d follows row %d" % (row, parent))
    return done


@lru_cache(maxsize=1)
def _model():
    m = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    qs = m["questionnaire_sheet"]
    cells = m["sheets"][qs]
    m["_q"] = {q["row"]: q for q in m["questions"]}
    m["_corrections"] = _apply_corrections(m, cells)

    choices = {}

    def add(row, v):
        if v is None:
            return
        if isinstance(v, float) and v.is_integer():
            v = str(int(v))
        v = str(v)
        if not v.strip():
            return
        lst = choices.setdefault(row, [])
        if all(_ckey(x) != _ckey(v) for x in lst):
            lst.append(v)

    formulas = [v for v in cells.values() if isinstance(v, str) and v.startswith("=")]
    # Values the formulas actually compare against come first (exact spelling matters to Excel).
    for f in formulas:
        for mm in _XL_LOOKUP.finditer(f):
            for val in _range_values(m, mm.group(2), qs):
                add(int(mm.group(1)), val)
    for f in formulas:
        for mm in _G_EQ.finditer(f):
            add(int(mm.group(1)), mm.group(2))
    for q in m["questions"]:
        for o in q.get("options") or []:
            add(q["row"], str(o).strip())
    m["_choices"] = choices

    m["_flag_rows"] = sorted(int(c[1:]) for c, v in cells.items()
                             if c[:1] == "I" and c[1:].isdigit() and isinstance(v, str)
                             and v.startswith("=") and _FLAG.search(v))
    m["_sections"] = sorted((int(c[1:]), str(v).strip()) for c, v in cells.items()
                            if c[:1] == "B" and c[1:].isdigit() and re.match(r"^\s*Section\s+\d+", str(v)))
    return m


def _scored_text(row):
    return _model()["_q"].get(row, {}).get("text", "")


def _canon(row, value):
    """Map one raw answer to the exact value the workbook expects. Returns (value, recognised)."""
    m = _model()
    q = m["_q"][row]
    choices = m["_choices"].get(row, [])
    if value is None:
        return None, True
    if isinstance(value, bool):
        value = "Yes" if value else "No"
    if isinstance(value, (list, tuple, set)):
        items = [str(v).strip() for v in value if v is not None and str(v).strip()]
        if not items:
            return None, True
        want = set()
        for it in items:
            want |= _tokset(it)
        for c in choices:
            if _tokset(c) == want:
                return c, True
        if not q.get("scored"):
            return ", ".join(items), True
        return None, False
    s = str(value).strip()
    if not s:
        return None, True
    if q.get("yesno"):
        low = s.lower()
        if low in _YES:
            s = "Yes"
        elif low in _NO:
            s = "No"
    if not choices:
        return s, True
    k = _ckey(s)
    for c in choices:
        if _ckey(c) == k:
            return c, True
    if not q.get("scored") and not q.get("yesno"):
        return s, True
    return None, False


def normalise(answers):
    """{row|'R40'|'40': raw} -> ({row: workbook value}, [rejected answers with reasons])."""
    m = _model()
    out, rejected = {}, []
    for k, v in (answers or {}).items():
        try:
            row = int(str(k).strip().lstrip("Rr"))
        except ValueError:
            rejected.append({"key": k, "value": v, "reason": "not a questionnaire row"})
            continue
        if row not in m["_q"]:
            rejected.append({"key": k, "value": v, "reason": "no question on that row"})
            continue
        val, ok = _canon(row, v)
        if not ok:
            rejected.append({"row": row, "question": _scored_text(row), "value": v,
                             "reason": "expected one of: " + "; ".join(m["_choices"].get(row, []))})
            continue
        if val is not None:
            out[row] = val
    return out, rejected


def _applicable(q, answers):
    """A follow-up question only applies when its parent was answered with the gating value."""
    p, gate = q.get("parent"), q.get("gate")
    if not p or not gate:
        return True
    return answers.get(p) == gate


# =============================================================================
# Conditions of cover (condensed — the minimum to incept most corporate risks)
# Each check is (row, accepted answers, keyword that must appear in that row's question —
# selftest uses the keyword to catch a workbook revision that moves rows).
# =============================================================================
CONDITIONS = (
    {"id": "entities_minimum",
     "text": "The controls declared on the proposal form are at a minimum the level of all listed entities",
     "confirm": True},
    # Underwriter 2026-10-16: regular backups at least every 7 to 14 days meet this condition.
    {"id": "backups_weekly", "text": "Data backups are done at least weekly",
     # Underwriter 2026-10-16: weekly is the norm. Bi-weekly is a relaxation only for low-connectivity
     # risks (e.g. manufacturing) or little PII / PHR / employee data, decided by the underwriter.
     "all": ((40, ("Daily", "Weekly"), "backups performed"),)},
    {"id": "backups_isolated", "text": "A separate backup set is immutable or isolated from production",
     "all": ((46, ("Yes",), "immutable"),)},
    {"id": "password_policy", "text": "Password complexity and reuse policies are in place for all logins",
     "all": ((121, ("Yes",), "password complexity"),)},
    {"id": "physical_access", "text": "Critical systems are hosted in access-controlled areas",
     "all": ((90, ("Yes",), "access-controlled"),)},
    {"id": "offsite_backups", "text": "Critical systems are backed up offsite",
     "all": ((92, ("Yes",), "backed up offsite"),)},
    {"id": "edr", "text": "EDR or ETDR tools are deployed on all access devices",
     "all": ((152, ("Yes",), "edr"),)},
    {"id": "firewall",
     "text": "A two-way traditional firewall is active and configured for the business's network",
     "confirm": True,
     # Not asked on the form: inferred from perimeter controls that need a firewall in place,
     # together with the EDR and backup conditions. Otherwise the broker confirms it.
     "infer": {"all": ((141, ("Yes",), "rdp"), (182, ("Yes",), "vpn")),
               "any": ((140, ("Yes",), "dmz"), (161, ("Yes",), "intrusion")),
               "conditions": ("edr", "backups_weekly", "backups_isolated")}},
    {"id": "email_filtering",
     "text": "E-mail filtering blocks malicious attachments and suspicious file types, including executables",
     "all": ((143, ("Yes",), "malicious attachments"),)},
    {"id": "web_filtering",
     "text": "Web filtering blocks known malicious or suspicious downloads, including executables",
     "all": ((147, ("Yes",), "downloads"),)},
    {"id": "threat_intel", "text": "A cyber threat intelligence capability is in place",
     "all": ((66, ("Yes",), "threat intelligence"),)},
    {"id": "vuln_remediation", "text": "A defined process for remediating vulnerabilities is in place",
     "all": ((69, ("Yes",), "remediating vulnerabilities"),)},
    {"id": "high_risk_protocols", "text": "High-risk protocols (e.g. RDP, SMBv1) are disabled externally",
     "all": ((141, ("Yes",), "rdp"),)},
    {"id": "ir_plan_tested",
     "text": "The incident response plan is tested at least annually with executive participation",
     "all": ((108, ("Yes",), "executive participation"),)},
    {"id": "mfa_privileged", "text": "MFA is implemented for all privileged accounts",
     "all": ((126, ("Yes",), "privileged"),)},
    {"id": "mfa_vpn_remote", "text": "MFA and VPN are implemented for all remote logins into the network",
     "all": ((182, ("Yes",), "vpn"),)},
    {"id": "awareness_training",
     "text": "Formal security awareness training is provided to all employees at least annually",
     "all": ((170, ("Yes",), "awareness training"),)},
    {"id": "phishing_simulations", "text": "Phishing simulations are conducted regularly for all employees",
     "all": ((173, ("Yes",), "phishing simulation"),)},
    {"id": "payment_controls", "text": "Payment controls for Funds Protect authorised losses",
     "all": ((277, ("Yes",), "vetting"), (278, ("Yes",), "beneficiaries"),
             (279, ("Yes",), "amend"), (280, ("Yes",), "verification")),
     "when": "funds_protect"},
    {"id": "sophos_mdr",
     "text": "Sophos MDR Complete deployed on all access devices and entire network, with endpoints "
             "deployed or not deployed (or a comparable MDR Complete equivalent, validated by underwriting)",
     "any": (((256, ("Yes",), "sophos"),
              (257, ("Complete \u2013 Endpoints deployed", "Complete \u2013 Endpoints not deployed"),
               "service tier")),
             ((258, ("Yes",), "mdr"), (259, ("Yes",), "oem"), (260, ("Yes",), "incident response"),
              (261, ("Yes",), "root cause"), (262, ("Yes",), "cloud, network"))),
     # The non-Sophos group (index 1) only counts once underwriting validates the product.
     "validate_group": (1, "mdr_equivalent"),
     "when": "public_or_soe"},
)

COND_BY_ID = {c["id"]: c for c in CONDITIONS}


# =============================================================================
# MDR discount (price sheet: 'Sophos MDR Discount', a separate layer off the whole base premium).
# Labels follow the condition-of-cover wording; "workbook" is the price sheet's own label.
# Keep in step with MDR_OPTIONS in corporate-data.js.
# =============================================================================
MDR_TIERS = (
    {"id": "none", "label": "No MDR", "workbook": "No MDR", "discount": 0.0},
    {"id": "sophos_essentials_no_endpoints",
     "label": "Sophos MDR Essentials deployed on all access devices and entire network, with endpoints not deployed",
     "workbook": "MDR Essential without Sophos Endpoint Deployment", "discount": 0.10,
     "answer": "Essentials \u2013 Endpoints not deployed"},
    {"id": "sophos_essentials_endpoints",
     "label": "Sophos MDR Essentials deployed on all access devices and entire network, with endpoints deployed",
     "workbook": "MDR Essential with Sophos Endpoint Deployment", "discount": 0.15,
     "answer": "Essentials \u2013 Endpoints deployed"},
    {"id": "sophos_complete_no_endpoints",
     "label": "Sophos MDR Complete deployed on all access devices and entire network, with endpoints not deployed",
     "workbook": "MDR Complete without Sophos Endpoint Deployment", "discount": 0.20,
     "answer": "Complete \u2013 Endpoints not deployed"},
    {"id": "sophos_complete_endpoints",
     "label": "Sophos MDR Complete deployed on all access devices and entire network, with endpoints deployed",
     "workbook": "MDR Complete with Sophos Endpoint Deployment", "discount": 0.30,
     "answer": "Complete \u2013 Endpoints deployed"},
    {"id": "comparable_complete",
     "label": "Comparable MDR (non-Sophos), Complete equivalent, validated by underwriting",
     "workbook": None, "discount": 0.20},
)
MDR_BY_ID = {t["id"]: t for t in MDR_TIERS}
# Non-Sophos MDR: the most the rater will pass, and only after underwriting validates the product.
# Kept conservative on purpose: clients often misreport what MDR they have.
NON_SOPHOS_MAX_DISCOUNT = 0.20
NON_SOPHOS_ROWS = (259, 260, 261, 262)


def mdr_assessment(answers, context=None):
    """Which MDR discount tier the answers support, and how much of it the rater may pass.

    status: auto (Sophos tier read from the form), validation_required (non-Sophos, every MDR
    question Yes, discount held at 0 until underwriting validates), validated, manual (non-Sophos
    with gaps: no discount, assess by hand), none, information_required.
    """
    ctx = dict(context or {})
    validated = "mdr_equivalent" in set(ctx.get("confirmed") or ())
    none = MDR_BY_ID["none"]
    sophos, other = answers.get(256), answers.get(258)

    def out(tier, status, note, discount=None, **extra):
        d = {"provider": extra.pop("provider", "none"), "tier": tier["id"] if tier else None,
             "label": tier["label"] if tier else None,
             "workbook_tier": tier.get("workbook") if tier else None,
             "discount": (tier["discount"] if tier else 0.0) if discount is None else discount,
             "status": status, "note": note}
        d.update(extra)
        return d

    if sophos == "Yes":
        tier = next((t for t in MDR_TIERS if t.get("answer")
                     and _ckey(t["answer"]) == _ckey(answers.get(257) or "")), None)
        if tier is None:
            return out(None, "information_required", "Sophos MDR is declared but the service tier is not answered.",
                       discount=0.0, provider="sophos")
        return out(tier, "auto", "Set from the Sophos tier on the proposal form. Confirm it covers all access "
                   "devices and the entire network.", provider="sophos")
    if sophos is None:
        return out(None, "information_required", "The Sophos MDR question is not answered.", discount=0.0)
    if other == "Yes":
        checks = {str(r): answers.get(r) for r in NON_SOPHOS_ROWS}
        gaps = [r for r in NON_SOPHOS_ROWS if answers.get(r) != "Yes"]
        tier = MDR_BY_ID["comparable_complete"]
        if gaps:
            return out(None, "manual", "A non-Sophos MDR is declared but not every MDR question is Yes (rows %s). "
                       "No discount is suggested; assess it manually." % ", ".join(map(str, gaps)),
                       discount=0.0, provider="other", checks=checks)
        if not validated:
            return out(tier, "validation_required", "Every MDR question is Yes. Validate the provider and service "
                       "before passing a discount (at most %d%%); none is applied until then."
                       % round(NON_SOPHOS_MAX_DISCOUNT * 100), discount=0.0, provider="other",
                       checks=checks, eligible_discount=NON_SOPHOS_MAX_DISCOUNT)
        return out(tier, "validated", "Validated by underwriting as an MDR Complete equivalent.",
                   discount=NON_SOPHOS_MAX_DISCOUNT, provider="other", checks=checks)
    if other is None:
        return out(None, "information_required", "Whether another MDR service is used is not answered.",
                   discount=0.0)
    return out(none, "none", "No MDR service declared.")


def _check_group(answers, checks):
    return [_check(answers, c) for c in checks]


def _check_applicable(answers, check):
    """Like _check, but a follow-up whose gating parent answer rules it out counts as failed
    (e.g. the non-Sophos MDR rows when Sophos MDR is declared)."""
    q = _model()["_q"].get(check[0])
    if q is not None and q.get("parent") and answers.get(q["parent"]) is not None \
            and not _applicable(q, answers):
        return "failed"
    return _check(answers, check)


def _public_business_types():
    q = _model()["_q"].get(13) or {}
    return [o for o in q.get("options", []) if _ckey(o) not in ("private", "other")]


def _check(answers, check):
    row, accepted, _kw = check
    ans = answers.get(row)
    if ans is None:
        return "unanswered"
    return "ok" if _ckey(ans) in {_ckey(a) for a in accepted} else "failed"


def _condition_status(cond, answers, ctx):
    when = cond.get("when")
    if when == "funds_protect" and not ctx.get("funds_protect", True):
        return "not_applicable", "Funds Protect is not part of this quote"
    if when == "public_or_soe":
        if ctx.get("soe") or ctx.get("public_sector"):
            pass
        else:
            bt = answers.get(13)
            if bt is None:
                return "applicability_unknown", "Business type is needed to tell whether the Sophos MDR condition applies"
            if _ckey(bt) not in {_ckey(t) for t in _public_business_types()}:
                return "not_applicable", "Applies to public administration and state-owned entities only"
    confirmed = set(ctx.get("confirmed") or ())
    if cond.get("confirm"):
        if cond["id"] in confirmed:
            return "met", ""
        inf = cond.get("infer")
        if not inf:
            return "unconfirmed", "Not asked on the proposal form; needs the broker's confirmation"
        res_all = _check_group(answers, inf.get("all", ()))
        res_any = _check_group(answers, inf.get("any", ()))
        deps = {cid: _condition_status(COND_BY_ID[cid], answers, ctx)[0] for cid in inf.get("conditions", ())}
        any_ok = not res_any or "ok" in res_any
        if all(r == "ok" for r in res_all) and any_ok and all(s == "met" for s in deps.values()):
            return "met", "Inferred from the perimeter controls (rows %s) with the EDR and backup conditions met" % (
                ", ".join(str(c[0]) for c in tuple(inf.get("all", ())) + tuple(inf.get("any", ()))))
        if ("failed" in res_all or (res_any and all(r == "failed" for r in res_any))
                or any(s == "not_met" for s in deps.values())):
            return "unconfirmed", "Cannot be inferred from the form; needs the broker's confirmation"
        return "unanswered", "Answer the perimeter-control questions, or have the broker confirm it"
    if "all" in cond:
        res = [_check(answers, c) for c in cond["all"]]
        if all(r == "ok" for r in res):
            return "met", ""
        if "failed" in res:
            return "not_met", ""
        return "unanswered", ""
    groups = [[_check_applicable(answers, c) for c in g] for g in cond["any"]]
    vg = cond.get("validate_group")
    for i, g in enumerate(groups):
        if not all(r == "ok" for r in g):
            continue
        if vg and i == vg[0] and vg[1] not in confirmed:
            continue
        return "met", ""
    if vg and all(r == "ok" for r in groups[vg[0]]):
        return "unconfirmed", "A comparable MDR is declared; underwriting must validate it as an MDR Complete equivalent"
    if all("failed" in g for g in groups):
        return "not_met", ""
    return "unanswered", ""


def _condition_rows(cond):
    if "infer" in cond:
        return [c[0] for k in ("all", "any") for c in cond["infer"].get(k, ())]
    if "all" in cond:
        return [c[0] for c in cond["all"]]
    if "any" in cond:
        return [c[0] for g in cond["any"] for c in g]
    return []


def conditions(answers, context=None):
    ctx = dict(context or {})
    out = {"met": [], "not_met": [], "information_required": [], "not_applicable": []}
    for cond in CONDITIONS:
        status, note = _condition_status(cond, answers, ctx)
        item = {"id": cond["id"], "condition": cond["text"], "status": status,
                "rows": _condition_rows(cond),
                "answers": {r: answers.get(r) for r in _condition_rows(cond)}}
        if note:
            item["note"] = note
        bucket = {"met": "met", "not_met": "not_met", "not_applicable": "not_applicable"}.get(
            status, "information_required")
        out[bucket].append(item)
    if out["not_met"]:
        out["status"] = "conditions_not_met"
    elif out["information_required"]:
        out["status"] = "information_required"
    else:
        out["status"] = "ready"
    return out


# =============================================================================
# Assessment
# =============================================================================
def _clean(v):
    if isinstance(v, XLError):
        return None
    if isinstance(v, float):
        return round(v, 6)
    return v


# Rating basis (underwriter, 2026-10-15). The questionnaire posture sets the maturity band only when
# the client answered (nearly) all of our questions: our own form filled in completely, or a
# competitor form that asks the same things. Otherwise the client is rated Average (Moderate, x1.00)
# on the assumption that the minimum conditions are in place. Questions a form does not ask are
# found out through the conditions gate; they are never penalised in the band.
RATE_ON_ANSWERS_MIN = 0.9
AVERAGE_BAND = {"band": "Moderate", "multiplier": 1.0}


def rating_band(multiplier, band, completeness_pct, context=None):
    """The band the premium uses. context rating_basis: 'answers' or 'average' forces either basis."""
    basis = (context or {}).get("rating_basis")
    pct = round((completeness_pct or 0.0) * 100)
    if basis == "answers" or (basis != "average" and (completeness_pct or 0.0) >= RATE_ON_ANSWERS_MIN):
        return {"band": band, "multiplier": multiplier, "basis": "answers",
                "note": "Band from the questionnaire posture (%d%% of applicable questions answered)." % pct}
    return dict(AVERAGE_BAND, basis="average", questionnaire_band=band, questionnaire_multiplier=multiplier,
                note="Only %d%% of our applicable questions are answered, so the client is rated Average on the "
                     "assumption that the minimum conditions are in place. The questionnaire band (%s) is "
                     "indicative only." % (pct, band))


# Conditions of cover are assumed in place for the posture (underwriter, 2026-10-16). A quote that
# lists conditions of cover is only bound once the client meets them, so the posture is scored as if
# the condition rows were answered Yes. The gate still reports the conditions the answers do not meet;
# they become the 'subject to' list on the quote. MDR conditions are never assumed, because MDR
# answers also drive the MDR discount. context: assume_conditions=False turns this off;
# quote_conditions=[ids] limits it to the conditions the quote actually lists.
def _assumable(cond, ctx):
    if "all" not in cond or "infer" in cond:
        return False
    when = cond.get("when")
    if when == "funds_protect" and not ctx.get("funds_protect", True):
        return False
    if when == "public_or_soe":
        return False
    return True


def assumed_condition_answers(norm, context=None):
    """{row: {"answered": value, "assumed": value, "condition": id}} for condition rows not met."""
    ctx = dict(context or {})
    if ctx.get("assume_conditions", True) is False:
        return {}
    wanted = ctx.get("quote_conditions")
    out = {}
    for cond in CONDITIONS:
        if wanted is not None and cond["id"] not in wanted:
            continue
        if not _assumable(cond, ctx):
            continue
        for check in cond["all"]:
            # Only rows the client answered against the condition. Unanswered rows stay blank: they
            # count against completeness and are asked for through the gate, never guessed.
            if _check(norm, check) == "failed":
                # the weakest accepted answer (e.g. 'Weekly' rather than 'Daily' for backups)
                out[check[0]] = {"answered": norm.get(check[0]), "assumed": check[1][-1],
                                 "condition": cond["id"]}
    return out


def _posture_of(m, answers):
    qs = m["questionnaire_sheet"]
    book = _Book(m["sheets"], {(qs, "G%d" % r): answers.get(r) for r in m["_q"]})
    v = book.value(qs, m.get("posture_cell", "H282"))
    return None if isinstance(v, XLError) else float(_num(v))


def assess(answers, context=None):
    """Score a client's answers exactly as the workbook would, then apply the conditions gate.

    answers: {row: value} — "Yes"/"No"/True/False, a dropdown value, or a list for multi-select rows.
    context: {"funds_protect": bool (default True), "soe": bool, "public_sector": bool,
              "confirmed": [condition ids confirmed by the broker/underwriter]}
    """
    m = _model()
    qs, ps = m["questionnaire_sheet"], m["price_sheet"]
    norm, rejected = normalise(answers)
    assumed = assumed_condition_answers(norm, context)
    scored = dict(norm)
    scored.update({r: a["assumed"] for r, a in assumed.items()})
    inputs = {(qs, "G%d" % r): scored.get(r) for r in m["_q"]}  # unanswered = blank, never the example
    book = _Book(m["sheets"], inputs)

    posture_v = book.value(qs, m.get("posture_cell", "H282"))
    posture = None if isinstance(posture_v, XLError) else float(_num(posture_v))
    multiplier = _clean(book.value(ps, "C12"))
    band = _clean(book.value(ps, "D12"))

    sections = []
    cells = m["sheets"][qs]
    for r, name in m["_sections"]:
        w = cells.get("C%d" % r)
        sc = _clean(book.value(qs, "H%d" % r))
        sections.append({"row": r, "section": name, "weight": w, "score": sc,
                         "pct": round(sc / w, 4) if isinstance(w, (int, float)) and w and isinstance(sc, (int, float)) else None})

    failing = []
    for r in m["_flag_rows"]:
        if book.value(qs, "I%d" % r) != 1:
            failing.append({"row": r, "question": _scored_text(r), "answer": norm.get(r)})

    unanswered, n_app, n_ans = [], 0, 0
    for q in m["questions"]:
        if not q.get("scored") or not _applicable(q, norm):
            continue
        n_app += 1
        if norm.get(q["row"]) is not None:
            n_ans += 1
        else:
            unanswered.append({"row": q["row"], "section": q.get("section"), "question": q["text"],
                               "choices": m["_choices"].get(q["row"], [])})

    gate = conditions(norm, context)
    rating = rating_band(multiplier, band, (n_ans / n_app) if n_app else 0.0, context)
    # Quoted subject to conditions: the modifier stands when every unmet condition was assumed in place.
    assumed_ids = {a["condition"] for a in assumed.values()}
    subject_to = [c["id"] for c in gate["not_met"]]
    modifier = None
    if gate["status"] == "ready":
        modifier = rating["multiplier"]
    elif (gate["status"] == "conditions_not_met" and set(subject_to) <= assumed_ids
          and not gate["information_required"]):
        modifier = rating["multiplier"]
    as_answered = _posture_of(m, norm) if assumed else posture
    return {
        "ok": posture is not None,
        "posture": round(posture, 6) if posture is not None else None,
        "posture_as_answered": round(as_answered, 6) if as_answered is not None else None,
        "assumed_for_conditions": {str(r): a for r, a in sorted(assumed.items())},
        "subject_to": subject_to,
        "maturity": {"multiplier": multiplier, "band": band},
        "rating_band": rating,
        "premium_modifier": modifier,
        "mdr": mdr_assessment(norm, context),
        "status": gate["status"],
        "conditions": gate,
        "sections": sections,
        "workbook_check": {"flags_met": _clean(book.value(qs, m.get("flag_total_cell", "I282"))),
                           "flags_expected": _clean(book.value(qs, m.get("flag_expected_cell", "J282"))),
                           "message": _clean(book.value(qs, "H283")),
                           "failing": failing},
        "completeness": {"answered": n_ans, "applicable": n_app,
                         "pct": round(n_ans / n_app, 4) if n_app else 0.0},
        "unanswered": unanswered,
        "rejected": rejected,
        "answers": {str(k): v for k, v in sorted(norm.items())},
    }


# =============================================================================
# Proposal-form PDF reader (fields are read by POSITION-derived mapping, not by field name —
# several field names on the form are misspelt or out of order)
# =============================================================================
def _fitz():
    try:
        import pymupdf as fitz  # noqa: F401
    except ImportError:  # older PyMuPDF
        import fitz  # noqa: F401
    return fitz


def _is_on(v):
    if isinstance(v, bool):
        return v
    return isinstance(v, str) and v.strip() not in ("", "Off", "off")


_COMPANY = (("company_name", r"^name of organi[sz]ation"), ("website", r"website"),
            ("annual_revenue", r"^annual rev"), ("employees", r"employees"),
            ("business_description", r"business description"), ("it_security_spend", r"security spend"),
            ("registration_no", r"^registration"), ("vat_no", r"^vat\b"),
            ("established", r"establishment"), ("principal_address", r"principal address"),
            ("principal_email", r"principal email"))


def _money(s):
    if s is None:
        return None
    t = str(s).strip().lower().replace(",", "").replace(" ", "").replace("zar", "")
    t = t[1:] if t.startswith("r") else t
    mult = 1.0
    for suf, f in (("billion", 1e9), ("bn", 1e9), ("million", 1e6), ("mil", 1e6), ("m", 1e6), ("k", 1e3)):
        if t.endswith(suf):
            t, mult = t[: -len(suf)], f
            break
    try:
        return float(t) * mult
    except ValueError:
        return None


def read_form(pdf_path):
    """Read a filled proposal-form PDF into {row: answer} plus company / limit / declaration details."""
    m = _model()
    form = m.get("form") or {}
    fitz = _fitz()
    doc = fitz.open(pdf_path)
    values = {}
    for page in doc:
        for w in page.widgets() or []:
            values.setdefault(w.field_name, []).append((w.field_type_string, w.field_value))
    if not values:
        return {"ok": False, "error": "This PDF has no fillable fields, so it is not the fillable proposal "
                                      "form (it may be printed or scanned). Use the document mapper instead."}

    def checked(name):
        return any(_is_on(v) for t, v in values.get(name, []) if t in ("CheckBox", "RadioButton"))

    def text(name):
        for t, v in values.get(name, []):
            if isinstance(v, bool) or v is None:
                continue
            s = str(v).strip()
            if s and s.lower() not in ("choose an item", "off"):
                return s
        return None

    expected = set()
    for f in form.get("fields", {}).values():
        if f["kind"] == "yn":
            expected |= {f["yes"], f["no"]}
        elif f["kind"] == "choice":
            expected.add(f["field"])
        else:
            expected |= set(f.get("fields", {}))
    version_match = round(len(expected & set(values)) / len(expected), 3) if expected else 0.0

    answers, conflicts = {}, []
    for row_s, f in form.get("fields", {}).items():
        row = int(row_s)
        if f["kind"] == "yn":
            y, n = checked(f["yes"]), checked(f["no"])
            if y and n:
                conflicts.append({"row": row, "question": _scored_text(row)})
            elif y:
                answers[row] = "Yes"
            elif n:
                answers[row] = "No"
        elif f["kind"] == "choice":
            v = text(f["field"])
            if v:
                answers[row] = v
        else:
            picked = [label for name, label in f.get("fields", {}).items() if checked(name)]
            if picked:
                answers[row] = picked

    details = {}
    for row_s, names in (form.get("details") or {}).items():
        vals = [v for v in (text(n) for n in names) if v]
        if vals:
            details[row_s] = " | ".join(vals)

    company, limits, decl = {}, {}, {}
    for name in values:
        low = name.strip().lower()
        for key, pat in _COMPANY:
            if key not in company and re.search(pat, low):
                v = text(name)
                if v:
                    company[key] = v
        mq = re.match(r"option\s*(\d)\s*(quote|deduct)", low)
        if mq:
            v = text(name)
            if v:
                slot = limits.setdefault(mq.group(1), {})
                slot["limit" if mq.group(2) == "quote" else "deductible"] = _money(v)
                slot["limit_raw" if mq.group(2) == "quote" else "deductible_raw"] = v
        if re.match(r"name of director", low):
            decl["name"] = text(name)
        elif low == "position":
            decl["position"] = text(name)
        elif low.startswith("date1"):
            decl["date"] = text(name)
    for k in ("annual_revenue", "it_security_spend"):
        if k in company:
            company[k + "_zar"] = _money(company[k])
    if 13 in answers:
        company["business_type"] = answers[13]

    filled = sum(1 for lst in values.values() for t, v in lst
                 if (t in ("CheckBox", "RadioButton") and _is_on(v)) or
                 (t in ("Text", "ComboBox") and v not in (None, "") and str(v).strip().lower() != "choose an item"))
    return {"ok": True, "answers": answers, "details": details, "company": company,
            "limits": [dict(option=int(k), **v) for k, v in sorted(limits.items())],
            "declaration": decl, "declaration_signed": bool(decl.get("name") and decl.get("date")),
            "conflicts": conflicts, "fields_filled": filled, "form_version_match": version_match}


def assess_form(pdf_path, answers=None, context=None):
    """Read a filled proposal form, overlay any explicit answers, and assess it."""
    form = read_form(pdf_path)
    if not form.get("ok"):
        return form
    merged = dict(form["answers"])
    for k, v in (answers or {}).items():
        merged[int(str(k).lstrip("Rr"))] = v
    ctx = dict(context or {})
    if form.get("declaration_signed"):
        ctx["confirmed"] = list(set(ctx.get("confirmed") or []) | {"entities_minimum"})
    result = assess(merged, ctx)
    result["form"] = {k: form[k] for k in ("company", "limits", "details", "declaration",
                                            "declaration_signed", "conflicts", "fields_filled",
                                            "form_version_match")}
    if form["conflicts"]:
        result["status"] = "information_required" if result["status"] == "ready" else result["status"]
    return result


def describe():
    m = _model()
    return {
        "source": m.get("generated_from"),
        "questions": [dict({k: q.get(k) for k in ("row", "section", "subsection", "text", "scored",
                                                  "flag", "parent", "gate", "yesno")},
                           choices=m["_choices"].get(q["row"], [])) for q in m["questions"]],
        "conditions": [{"id": c["id"], "condition": c["text"], "rows": _condition_rows(c),
                        "when": c.get("when"), "confirm": bool(c.get("confirm"))} for c in CONDITIONS],
        "mdr_tiers": [{k: t.get(k) for k in ("id", "label", "workbook", "discount", "answer")} for t in MDR_TIERS],
        "non_sophos_max_discount": NON_SOPHOS_MAX_DISCOUNT,
        "corrections": m.get("_corrections", []),
    }


# =============================================================================
# Self-test: the evaluator must reproduce every cached cell of the workbook's own example
# =============================================================================
def _same(got, want):
    if isinstance(got, XLError):
        got = got.code
    if isinstance(want, (int, float)) and not isinstance(want, bool) and isinstance(got, (int, float)):
        return abs(float(got) - float(want)) <= 1e-9 * max(1.0, abs(float(want)))
    return got == want


def selftest():
    m = _model()
    qs = m["questionnaire_sheet"]
    book = _Book(m["sheets"], {(qs, "G%d" % q["row"]): q.get("default") for q in m["questions"]})
    checked, mismatches = 0, []
    for sheet, cells in m.get("cached", {}).items():
        for coord, want in cells.items():
            got = book.value(sheet, coord)
            checked += 1
            if not _same(got, want):
                mismatches.append({"cell": "%s!%s" % (sheet, coord), "workbook": want,
                                   "evaluated": got.code if isinstance(got, XLError) else got})

    drift = []
    for c in CONDITIONS:
        checks = (list(c.get("all", ())) + [x for g in c.get("any", ()) for x in g]
                  + [x for k in ("all", "any") for x in c.get("infer", {}).get(k, ())])
        for row, _acc, kw in checks:
            if kw.lower() not in _scored_text(row).lower():
                drift.append({"condition": c["id"], "row": row, "keyword": kw, "question": _scored_text(row)})

    # Workbook quirks worth knowing: scored answers that never reach the posture, and score cells
    # that read a different question's answer.
    referenced = set()
    for sheet, cells in m["sheets"].items():
        for v in cells.values():
            if isinstance(v, str) and v.startswith("="):
                for kind, tok in _tokenize(v[1:]):
                    if kind == "ref":
                        sh, c1, r1, c2, r2 = _split_ref(tok)
                        referenced.update(_expand(sh or sheet, c1, r1, c2, r2))
    cells = m["sheets"][qs]
    dead, crossed = [], []
    for q in m["questions"]:
        h = cells.get("H%d" % q["row"])
        if not (isinstance(h, str) and h.startswith("=")):
            continue
        grefs = {int(x) for x in _G_REF.findall(h)}
        if grefs and (qs, "H%d" % q["row"]) not in referenced:
            dead.append({"row": q["row"], "question": q["text"][:90]})
        if grefs and q["row"] not in grefs:
            crossed.append({"row": q["row"], "question": q["text"][:90], "reads_rows": sorted(grefs)})
    return {"cells_checked": checked, "mismatches": mismatches, "condition_row_drift": drift,
            "unscored_answers": dead, "cross_wired": crossed,
            "posture": _clean(book.value(qs, "H282")), "flags": _clean(book.value(qs, "I282"))}


if __name__ == "__main__":
    print(json.dumps(selftest(), indent=1, default=str))
