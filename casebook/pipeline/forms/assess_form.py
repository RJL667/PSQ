#!/usr/bin/env python3
"""One call: a proposal / risk form in, ONE JSON record out.

    python3 casebook/pipeline/forms/assess_form.py <form> [options] [-o out.json]

Record: family + route, answers {row: {value, conf, source}}, posture band, conditions of cover in the
exact template wording (after the underwriting_nuances rules), PCI / CBI-SOE / MDR flags, short broker
questions, an SME-rater feed, and per-step timings.

Readers are REUSED, never rewritten:
  fillable own corporate form  -> questionnaire.read_form (field positions, exact)
  fillable iTOO v1             -> formdb/map_reader.py + itoo_v1_map.json
  fillable old own form (v0)   -> formdb/textmap_reader.py + phishield_v0_map.json (via extract_questions)
  scanned own corporate form   -> a structured read: --model-json (router / extract_model output, mapped to
                                  our rows by question text) or --answers (checked {row: value} JSON)
  anything else                -> reported as an unmapped family (gap), never guessed
Scoring: questionnaire.assess. PCI: formdb/pci_check.py. Turnover / SOE / CBI: formdb/revenue_check.py.
No model calls are made by default. --ocr runs casebook/tools/form_ocr.sh (live rater ingest, read-only)
for a scan's text (family + company name only: plain OCR text loses tick marks).
"""
import argparse
import difflib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/work")
CB = ROOT / "casebook"
FDB = CB / "formdb"
for p in (ROOT / "Corporate Rating Engine", FDB, FDB / "model_extract"):
    sys.path.insert(0, str(p))
import questionnaire as Q  # noqa: E402

try:
    import pymupdf as fitz
except ImportError:  # older PyMuPDF
    import fitz

T = {}


def timed(name):
    class _T:
        def __enter__(self):
            self.t = time.perf_counter()

        def __exit__(self, *a):
            T[name] = round(T.get(name, 0) + time.perf_counter() - self.t, 3)
    return _T()


# --------------------------------------------------------------------------------------------------
# Template wording (conditions_template.md is the only source of condition text)
# --------------------------------------------------------------------------------------------------
TEMPLATE_KEYS = {
    "entities_minimum": "at a minimum the level of all listed entities",
    "sophos_mdr": "Sophos MDR", "backups_both": "Data backups are done at least weekly",
    "password_policy": "Password complexity", "physical_access": "access-controlled areas",
    "offsite_backups": "backed up offsite", "edr": "ETDR", "firewall": "Two-Way Traditional Firewall",
    "email_filtering": "e-mail filtering", "web_filtering": "web-filtering",
    "threat_intel": "threat intelligence", "vuln_remediation": "remediating vulnerabilities",
    "high_risk_protocols": "High-risk protocols", "ir_plan_tested": "incident response plan",
    "mfa_privileged": "for all privileged accounts", "mfa_vpn_remote": "MFA and VPN",
    "awareness_training": "awareness training", "phishing_simulations": "Phishing simulations",
    "payment_controls": "Fraud payment controls"}
# Wording used in sent instructions where the template has no single line (one backup leg, MDR for
# public admin, the vulnerability-programme condition from the nuances file).
EXTRA = {
    "backups_weekly": "Data backups are done at least weekly.",
    "backups_isolated": "A separate backup set is immutable or completely isolated from production.",
    "vuln_program": "A formal, proactive vulnerability management program is in place.",
    "sophos_mdr_public": ("Sophos MDR Complete deployed on all access devices and entire network, with endpoints "
                          "deployed, or comparative Managed, Detection and Response program in place; if so, "
                          "please specify.")}


def template():
    lines = [l[2:].strip() for l in (CB / "conditions_template.md").read_text().splitlines() if l.startswith("- ")]
    out = {}
    for cid, key in TEMPLATE_KEYS.items():
        hit = [l for l in lines if key.lower() in l.lower()]
        out[cid] = hit[0] if hit else None
    out.update(EXTRA)
    return out


# --------------------------------------------------------------------------------------------------
# Readers
# --------------------------------------------------------------------------------------------------
def kinds(pdf):
    import router
    return router.classify(fitz.open(pdf))


def page_text(pdf, n=3):
    return " ".join(p.get_text() for i, p in enumerate(fitz.open(pdf)) if i < n)


def read_own_fillable(pdf):
    r = Q.read_form(pdf)
    if not r.get("ok") or not r["answers"] or r.get("form_version_match", 0) < 0.6:
        return None
    ans = {row: {"value": v, "conf": 0.99, "source": "form field"} for row, v in r["answers"].items()}
    return {"family": "phishield_corporate", "reader": "questionnaire.read_form", "answers": ans,
            "left_blank": True, "company": r["company"], "details": r["details"], "limits": r["limits"],
            "declaration_signed": r["declaration_signed"],
            "conflicts": [dict(c, why="Yes and No both ticked") for c in r["conflicts"]],
            "confirmed": []}


MAP_CONF = {"high": 0.95, "medium": 0.8, "low": 0.6}


def read_itoo(pdf):
    import map_reader as MR
    m = json.load(open(FDB / "itoo_v1_map.json"))
    vals = MR.read_fields(pdf)
    keys = set(vals) | {MR._key(w.field_name) for p in fitz.open(pdf) for w in (p.widgets() or [])}
    if not all(MR._key(f) in keys for f in m["fingerprint"]):
        return None
    a, ev = MR.apply(m, vals)
    ans, conflicts = {}, []
    for row, v in a.items():
        e = ev.get(row, {})
        ans[row] = {"value": v, "conf": MAP_CONF.get(e.get("conf"), 0.8) if "relaxed" not in e else 0.6,
                    "source": e.get("field") or ("relaxation: " + e["relaxed"] if "relaxed" in e else "map")}
    for row, e in ev.items():
        if "conflict" in e:
            conflicts.append({"row": row, "why": e["conflict"]})
    company = {"company_name": MR.get(vals, "Name of Insured")}
    return {"family": "itoo_v1", "reader": "map_reader + itoo_v1_map", "answers": ans, "left_blank": False,
            "company": company, "details": {}, "declaration_signed": None, "conflicts": conflicts,
            "confirmed": MR.confirmed(m, vals)}


def read_v0(pdf):
    m = json.load(open(FDB / "phishield_v0_map.json"))
    txt = " ".join(p.get_text() for p in fitz.open(pdf))
    if not all(f.lower() in txt.lower() for f in m["fingerprint"]):
        return None
    import extract_questions as EQ
    import textmap_reader as TM
    a, ev = TM.apply(m, EQ.extract(pdf))
    ans = {int(r): {"value": v, "conf": MAP_CONF.get(ev.get(r, {}).get("conf"), 0.8),
                    "source": (ev.get(r, {}).get("q") or "combined")[:90]} for r, v in a.items()}
    conflicts = [{"row": int(r), "why": "two mapped questions disagree"} for r, e in ev.items() if e.get("disagree")]
    return {"family": "phishield_v0", "reader": "textmap_reader + phishield_v0_map", "answers": ans,
            "left_blank": True, "company": {"company_name": a.get(5)}, "details": {},
            "declaration_signed": None, "conflicts": conflicts, "confirmed": []}


def _yn(m):
    sel = [str(s).strip().lower() for s in (m.get("selected") or []) if s]
    sel = ["yes" if s in ("y", "yes", "ja") else "no" if s in ("n", "no", "nee") else s for s in sel]
    if "yes" in sel and "no" in sel:
        return "CONFLICT"
    if "yes" in sel:
        return "Yes"
    if "no" in sel:
        return "No"
    t = str(m.get("answer_text") or "").strip().lower()
    return {"yes": "Yes", "y": "Yes", "no": "No", "n": "No"}.get(t)


def map_model_own(mjson):
    """Map a structured read (extract_model format) of OUR form onto questionnaire rows by question text.
    Order-aware greedy one-to-one pairing; ties go to the row at the same relative position."""
    import compare as C
    rows = [q for q in Q.describe()["questions"] if q.get("yesno") or q["choices"]]
    mqs = [m for m in json.load(open(mjson)).get("questions", [])
           if m.get("kind") in ("yes_no", "choice", "multi")]
    if not mqs:
        return {}, []
    rn = {q["row"]: C.norm(q["text"]) for q in rows}
    rank = {q["row"]: i / max(1, len(rows) - 1) for i, q in enumerate(rows)}
    pairs = []
    for j, m in enumerate(mqs):
        raw = m.get("question") or ""
        # a shared lead-in ('Do you have documented procedures in place for the following: Vetting ...')
        # hides the row text: also try the part after the last colon
        cands = {C.norm(raw)}
        if ":" in raw:
            cands.add(C.norm(raw.rsplit(":", 1)[1]))
        cands.discard("")
        mj = j / max(1, len(mqs) - 1)
        for q in rows:
            if not cands or not rn[q["row"]]:
                continue
            s = 0.0
            for mt in cands:
                sm = difflib.SequenceMatcher(None, mt, rn[q["row"]])
                if sm.real_quick_ratio() < 0.72 or sm.quick_ratio() < 0.72:
                    continue  # cheap upper bounds first: the full ratio is the slow part
                s = max(s, sm.ratio())
            if s >= 0.72:
                pairs.append((s - 0.08 * abs(rank[q["row"]] - mj), s, q, j))
    pairs.sort(key=lambda x: -x[0])
    used_r, used_m, ans, conflicts = set(), set(), {}, []
    for _, s, q, j in pairs:
        if q["row"] in used_r or j in used_m:
            continue
        m = mqs[j]
        if q["choices"] and set(q["choices"]) <= {"Yes", "No"}:
            v = _yn(m)
        else:
            sel = [str(x) for x in (m.get("selected") or []) if x] or [str(m.get("answer_text") or "")]
            v = None
            for c in q["choices"]:
                if any(C.ratio(C.norm(c), C.norm(x)) > 0.8 or C.norm(x).startswith(C.norm(c)) for x in sel if x):
                    v = c
                    break
        used_r.add(q["row"]); used_m.add(j)
        if v == "CONFLICT":
            conflicts.append({"row": q["row"], "why": "Yes and No both marked on the scan"})
            continue
        if v is None:
            continue
        conf = round((m.get("confidence") or 0.5) * (0.6 + 0.4 * s), 3)
        ans[q["row"]] = {"value": v, "conf": conf, "source": "scan p%s: %s" % (m.get("page"), (m.get("question") or "")[:70])}
    return ans, conflicts


def read_scan(pdf, model_json=None, answers_json=None, ocr=False):
    out = {"family": None, "reader": None, "answers": {}, "left_blank": True, "company": {}, "details": {},
           "declaration_signed": None, "conflicts": [], "confirmed": []}
    text = ""
    if ocr:
        with timed("ocr_ingest"):
            o = str(Path("/tmp") / ("af_%d.ingest.json" % time.time_ns()))
            subprocess.run(["bash", str(CB / "tools/form_ocr.sh"), pdf, o], capture_output=True, text=True, timeout=400)
            try:
                ing = json.load(open(o))
                text = ing.get("text") or ""
                out["ocr"] = {"ok": ing.get("ok"), "unread_pages": ing.get("ocr_pages"),
                              "ocr_seconds": ing.get("ocr_seconds")}
                Path(o).unlink()
            except Exception as e:
                out["ocr"] = {"ok": False, "error": str(e)[:200]}
    if model_json:
        with timed("map_scan_read"):
            mq = json.load(open(model_json)).get("questions", [])
            text = text or " ".join((m.get("question") or "") + " " + (m.get("section") or "") for m in mq)
            name = next((m.get("answer_text") for m in mq if re.search(r"(?i)name of organi[sz]ation", m.get("question") or "")), None)
            if name:
                out["company"]["company_name"] = name
    if re.search(r"(?i)phishield\s+cyber|organisation overview|business continuity & incident management", text) \
            or answers_json:
        out["family"] = "phishield_corporate_scan"
    if answers_json:
        a = json.load(open(answers_json))
        out["answers"] = {int(str(k).lstrip("Rr")): {"value": v, "conf": 0.9, "source": "checked read (" +
                          Path(answers_json).name + ")"} for k, v in a.items()}
        out["reader"] = "checked answers file"
    elif model_json and out["family"]:
        with timed("map_scan_read"):
            out["answers"], out["conflicts"] = map_model_own(model_json)
        out["reader"] = "structured scan read mapped by question text"
    if not out["family"]:
        out["family"] = "unmapped_scan"
    return out


# --------------------------------------------------------------------------------------------------
# Rules on top of questionnaire.assess (underwriting_nuances.md)
# --------------------------------------------------------------------------------------------------
def _v(ans, row):
    a = ans.get(row)
    return a["value"] if a else None


def apply_rules(res, ans, ctx, form, tpl):
    """Turn the assess() gate into the quote's conditions of cover + broker questions."""
    c = res["conditions"]
    bymeta = {x["id"]: x for k in ("met", "not_met", "information_required", "not_applicable") for x in c[k]}
    status = {cid: x["status"] for cid, x in bymeta.items()}
    conds, qs, notes = [], [], []

    def add(cid, text=None, note=None, why=None):
        conds.append({"id": cid, "text": text or tpl.get(cid), "note": note, "why": why})

    # entities_minimum: only on group submissions (parent with subsidiaries / several entities)
    # A parent that does NOT include subsidiaries (row 21 No) is a single-entity quote (Oct 2026 corporate renewal).
    group = _v(ans, 21) == "Yes" or bool(ctx.get("group"))
    if group:
        add("entities_minimum", why="group submission (parent / subsidiaries)")
    blank = {x["id"] for x in c["not_met"] if x.get("left_blank")}
    not_met = [x["id"] for x in c["not_met"]]

    # backups: one or both legs
    bw, bi = "backups_weekly" in not_met, "backups_isolated" in not_met
    if bw and bi and not ({"backups_weekly", "backups_isolated"} & blank):
        add("backups_both")
    else:
        if bw:
            if "backups_weekly" in blank:
                n = "please confirm the frequency, as it wasn't filled out on the form"
                add("backups_weekly", tpl["backups_weekly"].rstrip(".") + " (" + n + ").", n)
                qs.append("The frequency of their data backups, as it wasn't filled out on the form.")
            else:
                add("backups_weekly")
        if bi:
            if "backups_isolated" in blank:
                n = "please confirm, as it wasn't answered on the form"
                add("backups_isolated", tpl["backups_isolated"].rstrip(".") + " (" + n + ").", n)
                qs.append("Whether a separate backup set is immutable or isolated from production, as it wasn't answered on the form.")
            else:
                add("backups_isolated")

    for cid in ("password_policy", "physical_access", "offsite_backups", "edr", "web_filtering",
                "ir_plan_tested", "mfa_privileged", "mfa_vpn_remote", "awareness_training",
                "phishing_simulations", "payment_controls"):
        if cid in not_met:
            note = None
            if cid == "edr" and ctx.get("existing_sme"):
                note = ("as an existing client, please confirm with the broker/client that the current policy's minimum "
                        "requirement is in place: a comprehensive, paid-for internet security software subscription, "
                        "installed and up to date on all computer systems and access devices, including "
                        "antivirus/anti-malware with real-time endpoint detection and response")
                qs.append("That the current policy's minimum requirement for endpoint protection is in place (existing client).")
            if cid in blank and not note:
                note = "left blank on the form; please confirm"
                qs.append("Confirm: %s (left blank on the form)." % tpl[cid].rstrip("."))
            add(cid, (tpl[cid].rstrip(".") + " (" + note + ").") if note else None, note)

    # e-mail filtering: SPF + DKIM + DMARC all in place meets it
    if "email_filtering" in not_met:
        dm = _v(ans, 134)
        dm = " ".join(dm) if isinstance(dm, list) else str(dm or "")
        if all(k in dm.upper() for k in ("SPF", "DKIM", "DMARC")):
            notes.append("E-mail filtering condition met through SPF, DKIM and DMARC (nuances 29.10.2026).")
        else:
            add("email_filtering")

    # cyber threat intelligence: never imposed (scanner provides CTI)
    if "threat_intel" in not_met:
        notes.append("Cyber threat intelligence answered No: not imposed (scanner provides CTI).")

    # vulnerability management: defined process alone is not enough
    if "vuln_remediation" in not_met:
        if "vuln_remediation" in blank and _v(ans, 234) != "Yes":
            # sent instructions (Oct 2026 public-administration conversion): a blank remediation answer with no formal programme -> programme wording
            add("vuln_program", note="remediation process left blank on the form")
            qs.append("How vulnerabilities are found and remediated, if there is no formal program (e.g. how often they "
                      "scan and how quickly critical vulnerabilities are patched).")
        else:
            add("vuln_remediation")
    elif _v(ans, 69) == "Yes" and _v(ans, 234) != "Yes" and _v(ans, 235) != "Yes" and (_v(ans, 234) or _v(ans, 235)):
        add("vuln_program", note="the form states a defined process for remediating vulnerabilities; confirm how it is quantified")
        qs.append("Whether a formal, proactive vulnerability management program is in place, or how the stated remediation "
                  "process is quantified (scan frequency, time to patch critical vulnerabilities).")

    # high-risk protocols / RDP
    if "high_risk_protocols" in not_met:
        if _v(ans, 182) == "No":
            add("high_risk_protocols")
            qs.append("Whether RDP or other high-risk protocols (e.g. SMBv1) can be reached from outside the network, and if so, "
                      "whether only through VPN plus MFA. The form answers No to both disabling them externally and to VPN "
                      "and MFA for remote access, so this is likely to remain a condition of cover.")
        else:
            n = ("please confirm whether these can be reached from outside the network at all, and if so, whether only "
                 "through VPN plus MFA")
            add("high_risk_protocols", tpl["high_risk_protocols"].rstrip(".") + " (" + n + ").", n)
            qs.append("Whether RDP or other high-risk protocols (e.g. SMBv1) can be reached from outside the network, and if so, "
                      "whether only through VPN plus MFA.")

    # firewall: never a condition from the form; vendor table evidence or a broker question
    if status.get("firewall") not in ("met", None):
        fw = " ".join(str(v) for k, v in (form.get("details") or {}).items() if str(k) in ("223",))
        if fw.strip():
            notes.append("Firewall named in the security tools table (%s): counted as in place." % fw[:60])
        else:
            qs.append("Confirm that a two-way firewall is active and configured for the business's network.")

    # MDR: public admin / SOE carries the Sophos MDR condition
    if status.get("sophos_mdr") in ("not_met", "unanswered", "unconfirmed", "applicability_unknown") and \
            (ctx.get("soe") or str(ctx.get("industry") or "").startswith("Public Administration")):
        add("sophos_mdr_public", tpl["sophos_mdr_public"])
        qs.append("Whether Sophos MDR Complete, or a comparable MDR program, is in place, and if so, which one.")

    # questions the form never asked (competitor forms): ask, never assume
    # Sent instructions put a minimum condition the form does not answer (competitor form never asks it, or
    # a conflicting answer was dropped) on the quote as a condition of cover, and ask the broker to confirm.
    for x in c["information_required"]:
        if x["id"] in ("entities_minimum", "firewall", "sophos_mdr", "threat_intel"):
            continue
        if x.get("left_blank"):
            continue
        base = (tpl.get(x["id"]) or x["condition"]).rstrip(".")
        n = "not answered on the form; please confirm"
        add(x["id"], base + " (" + n + ").", n, why="information required")
        qs.append("Not answered on the form: %s." % base)
    for cf in form.get("conflicts") or []:
        qs.append("Conflicting answer on row %s (%s): please confirm." % (cf["row"], cf.get("why")))
    return conds, qs, notes


def pci_flag(pdf, ans, fillable):
    if fillable:
        try:
            import pci_check
            r = pci_check.check(pdf)
            return {k: r.get(k) for k in ("decision", "reason", "pci_benefit", "client_question", "note", "form_type")}
        except Exception as e:
            return {"decision": "ask", "reason": "pci_check failed: %s" % e}
    if _v(ans, 72) == "No":
        return {"decision": "not_needed", "reason": "Card payments not accepted (scan read).",
                "pci_benefit": "PCI Fines and Penalties N/A"}
    if _v(ans, 72) == "Yes":
        return {"decision": "ask", "reason": "Card payments accepted; card storage not read from the scan.",
                "pci_benefit": "Confirm with the client before quoting PCI"}
    return {"decision": "ask", "reason": "Card questions not read.", "pci_benefit": "Confirm with the client before quoting PCI"}


def revenue_flag(pdf, company, industry, fillable):
    import revenue_check as RC
    name = company.get("company_name")
    if fillable:
        try:
            r = RC.check(pdf, client=name, industry=industry)
            return {k: r.get(k) for k in ("soe", "soe_reasons", "decision", "turnover_for_rating", "turnover_source",
                                          "flags", "public_search", "user_confirm", "cbi_auto_include", "cbi_hint")}
        except Exception as e:
            return {"error": str(e)[:200]}
    soe = bool((name and RC.SOE_NAME_RE.search(name)) or (industry and RC.SOE_INDUSTRY_RE.search(industry)))
    return {"soe": soe, "decision": "pending_public_check" if soe else "use_form",
            "public_search": "required" if soe else "recommended",
            "flags": ["SOE: turnover must be checked against AFS or a public figure; CBI depends on grant share."] if soe else []}


def RC_rand(v):
    return "R{:,.0f}".format(v)


SME_MAP = (("q1-1", 152), ("q1-3", 143), ("q1-4", 147), ("q2-1", 40), ("q2-2", 50), ("q3", 45),
           ("q4", 238), ("q5", 170), ("q6-1", 277), ("q6-2", 278), ("q6-3", 279), ("q7", 280))


def sme_feed(ans, gate_status):
    out = {}
    for key, row in SME_MAP:
        v = _v(ans, row)
        if key == "q2-1":
            v = None if v is None else v in ("Daily", "Weekly")
        elif key == "q3":
            vs = [_v(ans, r) for r in (45, 46, 92)]
            v = True if "Yes" in vs else (False if vs and all(x == "No" for x in vs) else None)
        elif key == "q1-3":
            dm = _v(ans, 134)
            dm = " ".join(dm) if isinstance(dm, list) else str(dm or "")
            v = True if (v == "Yes" or all(k in dm.upper() for k in ("SPF", "DKIM", "DMARC"))) else (False if v == "No" else None)
        elif key == "q2-2":
            v = True if v == "Yes" else None  # quarterly drills Yes implies yearly; No proves nothing
        elif key == "q4":
            t = _v(ans, 237)
            v = True if (v == "Yes" or _v(ans, 158) == "Yes" or t in ("Within 24 hours", "24 to 72 hours", "3 to 7 days")) \
                else (False if v == "No" and t in ("More than 30 days",) else None)
        else:
            v = None if v is None else v == "Yes"
        out[key] = v
    fw = gate_status.get("firewall")
    out["q1-2"] = True if fw == "met" else None
    out["q8"] = None  # prior cover: not on the corporate form, ask the broker
    return dict(sorted(out.items()))


# --------------------------------------------------------------------------------------------------
def run(pdf, model_json=None, answers_json=None, ocr=False, industry=None, soe=None, existing_sme=False,
        funds_protect=True, group=False):
    T.clear()
    t0 = time.perf_counter()
    pdf = str(Path(pdf).resolve())
    with timed("classify"):
        pk = kinds(pdf)
    widgets = sum(k["widgets"] for k in pk)
    scan_pages = [k["page"] for k in pk if k["kind"] == "scan"]
    fillable = widgets > 0
    form = None
    with timed("read"):
        if fillable:
            for fn in (read_own_fillable, read_itoo, read_v0):
                form = fn(pdf)
                if form:
                    break
            if not form:
                form = {"family": "unmapped_fillable", "reader": None, "answers": {}, "left_blank": False,
                        "company": {}, "details": {}, "declaration_signed": None, "conflicts": [], "confirmed": []}
    if not fillable:
        form = read_scan(pdf, model_json, answers_json, ocr)
    elif answers_json:  # checked overrides on top of a fillable read
        for k, v in json.load(open(answers_json)).items():
            form["answers"][int(str(k).lstrip("Rr"))] = {"value": v, "conf": 0.9, "source": "checked override"}
    ans = form["answers"]
    ctx = {"funds_protect": funds_protect, "confirmed": list(form.get("confirmed") or [])}
    if form.get("left_blank"):
        ctx["left_blank"] = True
    if form.get("declaration_signed"):
        ctx["confirmed"].append("entities_minimum")
    with timed("revenue_soe"):
        rev = revenue_flag(pdf, form.get("company") or {}, industry, fillable and form["family"] != "unmapped_fillable")
    is_soe = bool(soe) if soe is not None else bool(rev.get("soe"))
    if is_soe:
        ctx["soe"] = True
    if industry:
        ctx["industry"] = industry
    with timed("assess"):
        res = Q.assess({r: a["value"] for r, a in ans.items()}, ctx)
    tpl = template()
    status = {x["id"]: x["status"] for k in ("met", "not_met", "information_required", "not_applicable")
              for x in res["conditions"][k]}
    with timed("rules"):
        conds, qs, notes = apply_rules(res, ans, dict(ctx, existing_sme=existing_sme, group=group), form, tpl)
    with timed("pci"):
        pci = pci_flag(pdf, ans, fillable)
    if pci.get("decision") == "ask":
        qs.append(pci.get("client_question") or "Please confirm whether you store, process or transmit any payment card data.")
    for f in rev.get("flags") or []:
        qs.append(f)
    low = [r for r, a in ans.items() if a["conf"] < 0.7 and any(r in (x.get("rows") or [])
           for x in res["conditions"]["not_met"] + res["conditions"]["met"])]
    for r in low:
        if str(ans[r]["source"]).startswith("relaxation"):
            # an underwriter-taught position (compensating control), not a read problem: underwriter note only
            notes.append("Relaxation applied on row %s (%s): confirm it holds under the mandate." % (r, ans[r]["source"][12:80]))
            continue
        qs.append("Low-confidence read on condition row %s (%s): %s; please check the form." % (r, ans[r]["source"][:50], ans[r]["value"]))
    if form["family"].startswith("unmapped"):
        qs.insert(0, "Form family not mapped: read and map it by hand, or ask the broker for our proposal form.")
    if not fillable and not ans:
        qs.insert(0, "Scanned form with no structured read: pass --model-json (router / extract_model) or --answers.")
    seen, bq = set(), []
    for q in qs:
        if q not in seen:
            seen.add(q); bq.append(q)
    tv = rev.get("turnover_for_rating") or (form.get("company") or {}).get("annual_revenue_zar")
    if any(c["id"] == "ir_plan_tested" for c in conds) and tv and tv < 150e6:
        notes.append("IR plan condition: turnover %s is small; drop it if the business is owner-run (executive "
                     "participation implicit, nuances)." % RC_rand(tv))
    T["total"] = round(time.perf_counter() - t0, 3)
    rb = res.get("rating_band") or {}
    return {
        "form": Path(pdf).name, "family": form["family"], "reader": form["reader"],
        "pages": len(pk), "scan_pages": scan_pages, "fillable": fillable,
        "company": form.get("company"), "limits_requested": form.get("limits"),
        "declaration_signed": form.get("declaration_signed"),
        "answers": {str(r): a for r, a in sorted(ans.items())},
        "answered_rows": len(ans),
        "posture": {"score": res.get("posture"), "questionnaire_band": (res.get("maturity") or {}).get("band"),
                    "rating_band": rb.get("band"), "basis": rb.get("basis"), "multiplier": rb.get("multiplier"),
                    "completeness": res.get("completeness"),
                    "note": "Posture bands are not calibrated: price at Moderate (Average); the scored band is information only."},
        "conditions": conds,
        "conditions_text": [c["text"] for c in conds],
        "rule_notes": notes,
        "gate": {k: [x["id"] for x in res["conditions"][k]] for k in ("met", "not_met", "information_required", "not_applicable")},
        "flags": {"pci": pci, "revenue_soe_cbi": rev, "soe": is_soe, "mdr": res.get("mdr")},
        "broker_questions": bq,
        "sme_uw_answers": sme_feed(ans, status),
        "timings_s": dict(T),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("form")
    ap.add_argument("--model-json", help="structured scan read (extract_model / router scan_model.json)")
    ap.add_argument("--answers", help="checked {row: value} JSON (scan read by hand, or overrides)")
    ap.add_argument("--ocr", action="store_true", help="read a scan's text through the live rater ingest (read-only)")
    ap.add_argument("--industry", help="rated industry, e.g. 'Public Administration > ...'")
    ap.add_argument("--soe", action="store_true", default=None)
    ap.add_argument("--existing-sme", action="store_true", help="renewal of an in-force SME client")
    ap.add_argument("--no-funds-protect", action="store_true")
    ap.add_argument("--group", action="store_true", help="several entities on one form")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    rec = run(a.form, a.model_json, a.answers, a.ocr, a.industry, a.soe, a.existing_sme, not a.no_funds_protect, a.group)
    s = json.dumps(rec, indent=1, ensure_ascii=False, default=str)
    if a.out:
        Path(a.out).write_text(s)
        print(json.dumps({k: rec[k] for k in ("form", "family", "answered_rows", "conditions_text", "broker_questions",
                                                "timings_s")}, indent=1, ensure_ascii=False, default=str))
        print("posture:", rec["posture"]["questionnaire_band"], rec["posture"]["completeness"], "| pci:",
              rec["flags"]["pci"].get("decision"), "| soe:", rec["flags"]["soe"], "| saved", a.out)
    else:
        print(s)


if __name__ == "__main__":
    main()
