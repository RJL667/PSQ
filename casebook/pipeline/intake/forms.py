"""Read fillable proposal-form PDFs (AcroForm fields) and enrich an intake record.

Usage:
  python3 casebook/pipeline/intake/forms.py <intake.json> <attachments_dir>   -> enriched record on stdout

Needs pypdf (installed in this workspace). Scanned / flattened forms return no fields;
those fall back to read_file OCR (slow, ~6 s per form) and are flagged in open_questions.
"""
import glob
import json
import os
import re
import sys

try:
    from pypdf import PdfReader
except ImportError:  # noqa: BLE001
    PdfReader = None

NAME_KEYS = re.compile(r"^(name of insured|policyholder details|company name|insured name|name of (the )?applicant)$", re.I)
TO_CUR = re.compile(r"current turnover|annual revenue current|estimated turnover|turnover current", re.I)
TO_PREV = re.compile(r"previous tu[nr]+over|annual revenue last|turnover last", re.I)
LIMIT_KEYS = re.compile(r"cover limit|limit of indemnity|indemnity required|^dropdown7$", re.I)  # Dropdown7 = our Business form cover limit
NATURE_KEYS = re.compile(r"^nature of business$|business description|business activit", re.I)
MAIN_IND = ["Agriculture", "Mining", "Construction", "Manufacturing", "Transportation", "Wholesale", "Retail",
            "Finance", "Services", "Public Admin"]


def money(s):
    s = re.sub(r"[^\d.,]", "", str(s or "")).replace(",", "")
    try:
        return float(s) if s else None
    except ValueError:
        return None


def read_form(path):
    if PdfReader is None:
        return {"file": os.path.basename(path), "error": "pypdf missing"}
    try:
        fl = PdfReader(path).get_fields() or {}
    except Exception as e:  # noqa: BLE001
        return {"file": os.path.basename(path), "error": str(e)[:80]}
    vals = {}
    for k, v in fl.items():
        val = v.get("/V") if isinstance(v, dict) else v
        if val in (None, "", "/Off") or isinstance(val, dict):
            continue
        vals[k.strip()] = str(val).strip()
    out = {"file": os.path.basename(path), "filled_fields": len(vals)}
    for k, v in vals.items():
        if NAME_KEYS.match(k) and "insured" not in out:
            out["insured"] = v.rstrip(" .")
        elif TO_CUR.search(k) and money(v):
            out["turnover"] = money(v)
        elif TO_PREV.search(k) and money(v):
            out["turnover_prev"] = money(v)
        elif LIMIT_KEYS.search(k) and money(v):
            out.setdefault("limits", []).append(money(v))
        elif NATURE_KEYS.search(k):
            out["nature_of_business"] = v
        elif v == "/On" and any(k.lower().startswith(m.lower()) for m in MAIN_IND):
            out["main_industry"] = k
    if "turnover" not in out and "turnover_prev" in out:
        out["turnover"] = out["turnover_prev"]
    return out


def enrich(rec, att_dir):
    forms = [read_form(p) for p in sorted(glob.glob(os.path.join(att_dir, "*.pdf")))
             if any(a["type"] == "proposal_form" and a["name"] == os.path.basename(p) for a in rec.get("attachments", []))]
    forms = [f for f in forms if f.get("filled_fields")]
    rec["forms"] = forms
    if not forms:
        rec["open_questions"].append("Proposal form has no fillable fields: OCR it (read_file) before rating")
        return rec
    ents = [f for f in forms if f.get("turnover")]
    if rec["turnover"] is None and ents:
        rec["turnover"] = sum(f["turnover"] for f in ents)
        rec["turnover_source"] = "proposal form" + (" (sum of %d entities)" % len(ents) if len(ents) > 1 else "")
    if len(forms) > 1:
        rec["entities"] = [{"insured": f.get("insured"), "turnover": f.get("turnover")} for f in forms]
        rec["open_questions"].append("%d entities on separate forms: confirm one combined policy or separate quotes" % len(forms))
    if not rec["requested_limits"]:
        lims = sorted({x for f in forms for x in f.get("limits", []) if 1e6 <= x <= 500e6})
        if lims:
            rec["requested_limits"] = lims
            rec["limits_source"] = "proposal form"
            rec["open_questions"].append("Limit read from the form's cover-limit dropdown: confirm it is the cover limit, "
                                          "not the Funds Protect limit")
    if not any(rec["industry"].values()):
        f = next((f for f in forms if f.get("nature_of_business") or f.get("main_industry")), None)
        if f:
            rec["industry"]["main"] = f.get("main_industry")
            rec["industry"]["description"] = f.get("nature_of_business")
    if rec["insured"] and forms[0].get("insured") and len(forms) == 1:
        rec["insured"] = forms[0]["insured"]
    # re-route on the enriched figures (same rules as intake.py)
    t, lims = rec["turnover"], rec["requested_limits"]
    flags = []
    if t is not None and t >= 250e6:
        route, why = "corporate", "turnover >= R250M"
    elif "corporate" in rec["route_reason"]:
        route, why = rec["product_route"], rec["route_reason"]
    else:
        route, why = "sme", "turnover below R250M" if t is not None else "default (turnover not stated)"
        if t is not None and t > 200e6:
            flags.append("SME rater cannot rate: turnover above R200M")
        if lims and max(lims) > 15e6:
            flags.append("SME rater cannot rate: cover above R15M")
        if flags:
            route, why = "corporate", why + "; " + "; ".join(flags)
    rec.update(product_route=route, route_reason=why, rater_flags=flags)
    rec["mailbox_folder"] = ("Corporate Quotes/" if (route == "corporate" or rec["issued_wording_likely"] == "corporate")
                             else "SME Quotes/") + rec["mailbox_folder"][-7:]
    drop = {"Annual turnover not stated": rec["turnover"] is not None,
            "Requested cover limit(s) not stated": bool(rec["requested_limits"]),
            "Industry / business description not stated": any(rec["industry"].values())}
    rec["open_questions"] = [q for q in rec["open_questions"] if not drop.get(q)]
    return rec


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    print(json.dumps(enrich(json.load(open(sys.argv[1])), sys.argv[2]), indent=1, default=str))
