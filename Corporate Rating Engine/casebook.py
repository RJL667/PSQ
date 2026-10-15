"""casebook.py — past deals as test cases for the corporate rater.

Each case is one folder under CASEBOOK_DIR (default: <DB_PATH dir>/casebook):

  <case_id>/case.json     client, insurer, form type, and what was actually quoted
  <case_id>/docs/         the proposal form(s) and the issued quote / terms, any format
  <case_id>/text/         extracted text of each non-fillable document (written by process)
  <case_id>/result.json   what the rater made of the case (written by process)
  <case_id>/review.json   underwriter answers / corrections that override what was read
  learnings.jsonl         one line per correction: the labelled examples for form mapping

A folder copied onto the server by hand (just files, no case.json) is adopted by scan():
loose files move into docs/ and the folder name becomes the client name.
"""
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from werkzeug.utils import secure_filename

import document_extract
import questionnaire

ALLOWED_EXT = {"pdf", "docx", "xlsx", "xlsm", "txt", "md", "csv",
               "png", "jpg", "jpeg", "tif", "tiff", "bmp", "webp"}
ROLES = ("proposal", "quote", "other")
DECISIONS = ("quoted", "quoted_subject_to", "declined", "referred")
# What the rater's gate status means for the decision a real underwriter could have made.
RATER_DECISIONS = {
    "ready": ("quoted",),
    "conditions_not_met": ("quoted_subject_to", "declined"),
    "information_required": ("referred", "quoted_subject_to"),
}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$")


class CaseError(ValueError):
    pass


# --------------------------------------------------------------------------- storage
def root():
    base = os.environ.get("CASEBOOK_DIR")
    if base:
        p = Path(base)
    else:
        db = os.environ.get("DB_PATH")
        p = (Path(db).resolve().parent if db else Path(__file__).resolve().parent) / "casebook"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write(path, obj):
    path = Path(path)
    tmp = path.with_name("." + path.name + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    os.replace(tmp, path)


def _slug(s):
    s = re.sub(r"[^A-Za-z0-9]+", "-", str(s or "")).strip("-").lower()
    return s[:40] or "case"


def case_dir(case_id):
    if not case_id or not _ID.match(case_id):
        raise CaseError("Invalid case id")
    d = root() / case_id
    if d.resolve().parent != root().resolve():
        raise CaseError("Invalid case id")
    if not (d / "case.json").is_file():
        raise CaseError("Case not found")
    return d


def _load(case_id):
    d = case_dir(case_id)
    return d, _read(d / "case.json", {})


# --------------------------------------------------------------------------- metadata
_ACTUAL_KEYS = ("decision", "maturity_band", "premium", "cover", "excess", "conditions", "notes")
_INPUT_KEYS = ("subIndustry", "turnover", "cover", "excess", "mdr", "fpAdjustableAmount", "riskBursary")
_TOP_KEYS = ("client", "insurer", "form_type", "broker", "quoted_on", "notes")


def _num(v):
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)):
        return v
    s = re.sub(r"[^\d.\-]", "", str(v))
    try:
        return float(s) if s else None
    except ValueError:
        return None


def _merge_meta(case, patch):
    patch = patch or {}
    for k in _TOP_KEYS:
        if k in patch:
            case[k] = (str(patch[k]).strip() if patch[k] is not None else "")
    if isinstance(patch.get("actual"), dict):
        act = dict(case.get("actual") or {})
        for k in _ACTUAL_KEYS:
            if k not in patch["actual"]:
                continue
            v = patch["actual"][k]
            if k in ("premium", "cover", "excess"):
                v = _num(v)
            elif k == "decision":
                v = v if v in DECISIONS else None
            elif k == "conditions":
                v = [str(x).strip() for x in (v or []) if str(x).strip()]
            act[k] = v
        case["actual"] = act
    if isinstance(patch.get("rating_inputs"), dict):
        ri = dict(case.get("rating_inputs") or {})
        for k in _INPUT_KEYS:
            if k in patch["rating_inputs"]:
                v = patch["rating_inputs"][k]
                ri[k] = (_num(v) if k in ("turnover", "cover", "excess", "fpAdjustableAmount")
                     else bool(v) if k == "riskBursary" else v)
        case["rating_inputs"] = ri
    if isinstance(patch.get("context"), dict):
        case["context"] = {k: patch["context"][k] for k in ("funds_protect", "soe", "public_sector")
                           if k in patch["context"]}
    return case


def create(meta=None):
    meta = meta or {}
    client = (meta.get("client") or "").strip()
    if not client:
        raise CaseError("Client name is required")
    case_id = "%s-%s-%s" % (datetime.now().strftime("%Y%m%d"), _slug(client), uuid.uuid4().hex[:4])
    d = root() / case_id
    (d / "docs").mkdir(parents=True)
    case = {"id": case_id, "created_at": _now(), "source": "upload", "documents": {},
            "actual": {}, "rating_inputs": {}, "context": {}, "status": "new"}
    _merge_meta(case, meta)
    _write(d / "case.json", case)
    return case


def update_meta(case_id, patch):
    d, case = _load(case_id)
    _merge_meta(case, patch)
    case["updated_at"] = _now()
    _write(d / "case.json", case)
    return case


# --------------------------------------------------------------------------- documents
def _unique(folder, name):
    p = folder / name
    stem, suf, n = p.stem, p.suffix, 1
    while p.exists():
        n += 1
        p = folder / ("%s_%d%s" % (stem, n, suf))
    return p


def add_document(case_id, filename, data, role="other"):
    d, case = _load(case_id)
    name = secure_filename(filename or "")
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_EXT:
        raise CaseError("Unsupported file type: .%s" % (ext or "?"))
    docs = d / "docs"
    docs.mkdir(exist_ok=True)
    dest = _unique(docs, name)
    if hasattr(data, "save"):
        data.save(str(dest))
    else:
        dest.write_bytes(data)
    case.setdefault("documents", {})[dest.name] = role if role in ROLES else "other"
    case["status"] = "new"
    _write(d / "case.json", case)
    return {"name": dest.name, "role": case["documents"][dest.name], "bytes": dest.stat().st_size}


def set_role(case_id, name, role):
    d, case = _load(case_id)
    if not (d / "docs" / secure_filename(name)).is_file():
        raise CaseError("Document not found")
    case.setdefault("documents", {})[secure_filename(name)] = role if role in ROLES else "other"
    _write(d / "case.json", case)
    return case["documents"]


def _docs(d, case):
    out = []
    folder = d / "docs"
    if folder.is_dir():
        for f in sorted(folder.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                out.append({"name": f.name, "role": (case.get("documents") or {}).get(f.name, _guess_role(f.name)),
                            "bytes": f.stat().st_size})
    return out


def _guess_role(name):
    low = name.lower()
    if re.search(r"quot|terms|schedule|offer|indicat", low):
        return "quote"
    if re.search(r"proposal|application|questionnaire|assessment|form", low):
        return "proposal"
    return "other"


def document_path(case_id, name):
    d, _ = _load(case_id)
    p = d / "docs" / secure_filename(name)
    if not p.is_file():
        raise CaseError("Document not found")
    return p


# --------------------------------------------------------------------------- folder drops
def scan():
    """Adopt folders copied in by hand, and tidy loose files into docs/. Returns adopted ids."""
    adopted = []
    for d in sorted(root().iterdir()):
        if not d.is_dir() or d.name.startswith((".", "_")):
            continue
        case_file = d / "case.json"
        loose = [f for f in d.iterdir() if f.is_file() and not f.name.startswith(".")
                 and f.name not in ("case.json", "result.json", "review.json")]
        if case_file.is_file() and not loose:
            continue
        if not _ID.match(d.name):
            continue
        case = _read(case_file) if case_file.is_file() else None
        if case is None:
            case = {"id": d.name, "created_at": _now(), "source": "folder", "client": d.name.replace("_", " "),
                    "documents": {}, "actual": {}, "rating_inputs": {}, "context": {}, "status": "new"}
            adopted.append(d.name)
        docs = d / "docs"
        docs.mkdir(exist_ok=True)
        for f in loose:
            ext = f.suffix.lower().lstrip(".")
            if ext not in ALLOWED_EXT:
                continue
            dest = _unique(docs, secure_filename(f.name) or f.name)
            os.replace(f, dest)
            case.setdefault("documents", {})[dest.name] = _guess_role(dest.name)
            case["status"] = "new"
        _write(case_file, case)
    return adopted


def list_cases():
    scan()
    out = []
    for d in sorted(root().iterdir(), reverse=True):
        case = _read(d / "case.json") if d.is_dir() else None
        if not case:
            continue
        res = _read(d / "result.json", {}) or {}
        a = res.get("assessment") or {}
        cmp_ = res.get("comparison") or {}
        out.append({
            "id": case.get("id", d.name), "client": case.get("client"), "insurer": case.get("insurer"),
            "form_type": case.get("form_type"), "created_at": case.get("created_at"),
            "status": case.get("status"), "documents": len(_docs(d, case)),
            "processed_at": res.get("processed_at"),
            "rater_status": a.get("status"), "rater_band": (a.get("maturity") or {}).get("band"),
            "actual_decision": (case.get("actual") or {}).get("decision"),
            "verdict": cmp_.get("verdict"),
            "completeness": (a.get("completeness") or {}).get("pct"),
        })
    return out


def get(case_id):
    d, case = _load(case_id)
    return {"case": case, "documents": _docs(d, case),
            "result": _read(d / "result.json"), "review": _read(d / "review.json", {}) or {}}


# --------------------------------------------------------------------------- processing
def _read_document(d, f, role):
    """Fillable proposal PDF -> structured answers. Anything else -> extracted text for mapping."""
    entry = {"doc": f.name, "role": role}
    if f.suffix.lower() == ".pdf":
        try:
            form = questionnaire.read_form(str(f))
        except Exception as exc:  # noqa: BLE001
            form = {"ok": False, "error": str(exc)}
        if form.get("ok") and (form.get("answers") or form.get("form_version_match", 0) >= 0.5):
            entry.update(kind="fillable_form", answers=len(form["answers"]),
                         version_match=form.get("form_version_match"),
                         conflicts=form.get("conflicts") or [], fields_filled=form.get("fields_filled"))
            return entry, form
    try:
        ext = document_extract.extract(str(f), f.name)
    except Exception as exc:  # noqa: BLE001
        ext = {"ok": False, "error": str(exc)}
    if not ext.get("ok"):
        entry.update(kind="unreadable", error=ext.get("error"))
        return entry, None
    tdir = d / "text"
    tdir.mkdir(exist_ok=True)
    (tdir / (f.name + ".txt")).write_text(ext.get("text") or "", encoding="utf-8")
    entry.update(kind="text", format=ext.get("format"), pages=ext.get("pages"), chars=ext.get("chars"),
                 needs_ocr=bool(ext.get("needs_ocr")), notes=ext.get("notes") or [],
                 needs_mapping=(role == "proposal"))
    return entry, None


def process(case_id):
    d, case = _load(case_id)
    readings, answers, sources, form_meta = [], {}, {}, {}
    for doc in _docs(d, case):
        entry, form = _read_document(d, d / "docs" / doc["name"], doc["role"])
        readings.append(entry)
        if form:
            for row, v in (form.get("answers") or {}).items():
                if int(row) not in answers:
                    answers[int(row)] = v
                    sources[int(row)] = doc["name"]
            if not form_meta:
                form_meta = {k: form.get(k) for k in ("company", "limits", "details", "declaration",
                                                       "declaration_signed", "conflicts")}
                form_meta["doc"] = doc["name"]

    review = _read(d / "review.json", {}) or {}
    for k, v in (review.get("answers") or {}).items():
        if v in (None, ""):
            continue
        row = int(str(k).lstrip("Rr"))
        answers[row] = v
        sources[row] = "review"

    ctx = dict(case.get("context") or {})
    ctx.update(review.get("context") or {})
    confirmed = set(ctx.get("confirmed") or []) | set(review.get("confirmed") or [])
    if form_meta.get("declaration_signed"):
        confirmed.add("entities_minimum")
    ctx["confirmed"] = sorted(confirmed)

    assessment = None
    if answers:
        try:
            assessment = questionnaire.assess(answers, ctx)
        except Exception as exc:  # noqa: BLE001
            assessment = {"ok": False, "error": "Assessment error: %s" % exc}
        if form_meta.get("conflicts") and assessment.get("status") == "ready":
            assessment["status"] = "information_required"

    by_source = {}
    for s in sources.values():
        by_source[s] = by_source.get(s, 0) + 1
    result = {
        "processed_at": _now(),
        "readings": readings,
        "form": form_meta or None,
        "answer_sources": by_source,
        "sources": {str(k): v for k, v in sorted(sources.items())},
        "needs_mapping": [r["doc"] for r in readings if r.get("needs_mapping")],
        "assessment": assessment,
        "comparison": compare(assessment, case.get("actual")),
    }
    _write(d / "result.json", result)
    case["status"] = "processed" if assessment and assessment.get("ok") else "needs_answers"
    case["processed_at"] = result["processed_at"]
    _write(d / "case.json", case)
    return result


def _norm(s):
    return re.sub(r"\s+", " ", str(s or "")).strip().lower()


def compare(assessment, actual):
    """Where the rater and the real quote agree or differ. Premium is compared on the casebook screen,
    which runs the same pricing engine as the rater in the browser."""
    actual = {k: v for k, v in (actual or {}).items() if v not in (None, "", [])}
    if not actual:
        return {"verdict": "no_actual", "checks": []}
    if not assessment or not assessment.get("ok"):
        return {"verdict": "not_assessed", "checks": []}
    checks = []
    if actual.get("maturity_band"):
        got = (assessment.get("maturity") or {}).get("band")
        checks.append({"check": "maturity_band", "rater": got, "actual": actual["maturity_band"],
                       "match": _norm(got) == _norm(actual["maturity_band"])})
    if actual.get("decision"):
        st = assessment.get("status")
        allowed = RATER_DECISIONS.get(st, ())
        checks.append({"check": "decision", "rater": st, "actual": actual["decision"],
                       "match": actual["decision"] in allowed, "consistent_with": list(allowed)})
    if actual.get("conditions") is not None and "conditions" in actual:
        gate = assessment.get("conditions") or {}
        rater_ids = {c["id"] for c in (gate.get("not_met") or []) + (gate.get("information_required") or [])}
        act_ids = {str(c) for c in actual["conditions"]}
        checks.append({"check": "conditions", "rater": sorted(rater_ids), "actual": sorted(act_ids),
                       "only_rater": sorted(rater_ids - act_ids), "only_actual": sorted(act_ids - rater_ids),
                       "match": rater_ids == act_ids})
    if not checks:
        verdict = "partial"
    elif all(c["match"] for c in checks):
        verdict = "match"
    else:
        verdict = "mismatch"
    return {"verdict": verdict, "checks": checks, "actual_premium": actual.get("premium")}


# --------------------------------------------------------------------------- review + learnings
def save_review(case_id, review, reviewer=""):
    """Store underwriter answers / confirmations. Every answer that differs from what the documents
    gave becomes a labelled example in learnings.jsonl. Re-process afterwards."""
    d, case = _load(case_id)
    review = review or {}
    old = _read(d / "review.json", {}) or {}
    res = _read(d / "result.json", {}) or {}
    read_answers = ((res.get("assessment") or {}).get("answers") or {})
    read_sources = res.get("sources") or {}

    answers = {}
    for k, v in (review.get("answers") or {}).items():
        try:
            row = int(str(k).lstrip("Rr"))
        except ValueError:
            continue
        answers[str(row)] = v
    new = {"answers": answers,
           "confirmed": sorted({str(c) for c in (review.get("confirmed") or [])}),
           "context": {k: v for k, v in (review.get("context") or {}).items()
                       if k in ("funds_protect", "soe", "public_sector")},
           "notes": str(review.get("notes") or old.get("notes") or ""),
           "reviewer": reviewer or review.get("reviewer") or "",
           "updated_at": _now()}

    lines = []
    for row, v in answers.items():
        prev_review = (old.get("answers") or {}).get(row)
        if v == prev_review:
            continue
        src = read_sources.get(row)
        was = read_answers.get(row) if src and src != "review" else None
        if v == was:
            continue
        lines.append({"ts": new["updated_at"], "case": case_id, "client": case.get("client"),
                      "insurer": case.get("insurer"), "form_type": case.get("form_type"),
                      "row": int(row), "question": _question_text(int(row)),
                      "read": was, "read_from": src if src != "review" else None,
                      "corrected": v, "reviewer": new["reviewer"]})
    _write(d / "review.json", new)
    if lines:
        with open(root() / "learnings.jsonl", "a", encoding="utf-8") as fh:
            for ln in lines:
                fh.write(json.dumps(ln, ensure_ascii=False, default=str) + "\n")
    return {"review": new, "learnings_added": len(lines)}


_QTEXT = None


def _question_text(row):
    global _QTEXT
    if _QTEXT is None:
        try:
            _QTEXT = {q["row"]: q.get("text") for q in questionnaire.describe()["questions"]}
        except Exception:  # noqa: BLE001
            _QTEXT = {}
    return _QTEXT.get(row)


def learnings(limit=500):
    p = root() / "learnings.jsonl"
    rows = []
    if p.is_file():
        for ln in p.read_text(encoding="utf-8").splitlines():
            try:
                rows.append(json.loads(ln))
            except ValueError:
                continue
    by_row, by_form = {}, {}
    for r in rows:
        by_row[r["row"]] = by_row.get(r["row"], 0) + 1
        key = "%s / %s" % (r.get("insurer") or "?", r.get("form_type") or "?")
        by_form[key] = by_form.get(key, 0) + 1
    top = sorted(by_row.items(), key=lambda kv: -kv[1])[:25]
    return {"total": len(rows),
            "most_corrected": [{"row": r, "question": _question_text(r), "corrections": n} for r, n in top],
            "by_form": by_form,
            "recent": rows[-limit:][::-1]}
