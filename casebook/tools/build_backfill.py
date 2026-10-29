"""Build quote-store records from our own quote instruction emails (historic + October).

Input: saved thread files (threads/*.json and quote_check/pending/*.json) plus the
Veilguard-priced register (quote_check/pending/register.json).
Output: one JSON record per quoted limit, ready to POST to the rater's /api/quotes.

Usage: python3 tools/build_backfill.py > /tmp/backfill.jsonl
"""
import base64
import glob
import hashlib
import json
import re
import sys
from datetime import datetime

def _own_email():
    """Own mailbox address, kept out of git: env CASEBOOK_OWN_EMAIL or .secrets/casebook_own_email."""
    import os
    from pathlib import Path
    v = os.environ.get("CASEBOOK_OWN_EMAIL")
    if v:
        return v.strip()
    for d in Path(__file__).resolve().parents:
        f = d / ".secrets" / "casebook_own_email"
        if f.exists():
            return f.read_text().strip()
    return ""


OWN = _own_email()
LIMIT_RE = re.compile(r"R\s?([\d]+(?:[.,]\d+)?)\s*M(?:il+ion)?\s+Cover\s*@\s*R\s?([\d,]+(?:\.\d+)*)", re.I)
AMT = r"R\s?[\d][\d.,]*\s*(?:BM|[MBK]\b|million|billion|bn)?"
TO_RE = re.compile(r"(" + AMT + r")\s*T/O|(?:T/O|turn-?over)(?:\s+of)?\s*(" + AMT + r")", re.I)
IND_RE = re.compile(r"Main/Sub-Industry:?\s*([^,()\-][^,()]*?)\s*-\s*>\s*([^,()]+?)\s*(?:,|\))", re.I)
# "(R27.6M t/o, Services – Social Services, without RM fee)" / "(R136M T/O, Services – Business Services, ...)"
IND2_RE = re.compile(r"T/O,\s*([A-Z][A-Za-z ,&]+?)\s*[–-]\s*([A-Z][^,()]+?)\s*,", re.I)
QT_RE = re.compile(r"(QT\d{6,})")


def money(s):
    """'R1,14B' -> 1.14e9, 'R127,278,020' -> 127278020, 'R7.5M' -> 7.5e6."""
    if not s:
        return None
    s = s.strip().upper().replace(" ", "").lstrip("R")
    mult = 1
    for suf, m in (("BILLION", 1e9), ("BN", 1e9), ("BM", 1e9), ("B", 1e9), ("MILLION", 1e6), ("M", 1e6), ("K", 1e3)):
        if s.endswith(suf):
            mult, s = m, s[: -len(suf)]
            break
    if mult > 1 and re.fullmatch(r"\d+,\d{1,2}", s):
        s = s.replace(",", ".")
    # Typo 'R32.001.85' (dot as thousands separator): keep only the last dot as decimal point.
    if re.fullmatch(r"\d{1,3}(\.\d{3})+\.\d{2}", s):
        s = s.replace(".", "", s.count(".") - 1)
    s = s.replace(",", "")
    try:
        return float(s) * mult
    except ValueError:
        return None


def body(m):
    d = ((m.get("payload") or {}).get("body") or {}).get("data")
    if not d:
        return ""
    try:
        return base64.urlsafe_b64decode(d + "==").decode("utf-8", "replace").replace("\r\n", "\n")
    except Exception:  # noqa: BLE001
        return ""


def headers(m):
    return {h["name"]: h["value"] for h in (m.get("payload") or {}).get("headers", [])}


def attachments(m):
    return [a.get("filename") or a.get("name") or "" for a in (m.get("attachments") or [])]


def cut_signature(t):
    for marker in ("\nKind Regards", "\nKind regards", "\nREF_PERSON_8 is an Authorised", "\nPhishield UMA (Pty) Ltd is an"):
        i = t.find(marker)
        if i > 0:
            t = t[:i]
    # drop quoted earlier mail
    for marker in ("\nFrom: ", "\n________________________________"):
        i = t.find(marker)
        if i > 0:
            t = t[:i]
    return t.strip()


def bullets_after(t, anchor_re):
    m = re.search(anchor_re, t, re.I)
    if not m:
        return []
    out = []
    for line in t[m.end():].split("\n"):
        s = line.strip()
        if not s:
            continue
        if s[:1] in "*-•·":
            out.append(s.lstrip("*-•· ").strip())
        elif out:
            break
    return out


def sections(t, limits):
    """Split the benefits block into per-limit sections ('R15M Cover:' headers)."""
    out = {}
    hdr = list(re.finditer(r"^\s*R\s?([\d.,]+)\s*M\s+Cover\s*:\s*$", t, re.M | re.I))
    for i, h in enumerate(hdr):
        end = hdr[i + 1].start() if i + 1 < len(hdr) else len(t)
        out[money(h.group(1) + "M")] = t[h.end():end]
    return out


def amount_in(sec, label):
    m = re.search(label + r"[^\n]*?\bis\s+(R\s?[\d.,]+\s*[MK]?|N/A)", sec, re.I)
    if not m:
        return None
    return "N/A" if m.group(1).upper() == "N/A" else money(m.group(1))


def company_from(subject, files):
    for f in files:
        m = re.match(r"Cyber Protect (?:Corporate|Business) Quotation - (.+?) - R[\d.,]+ Million", f or "")
        if m:
            return re.sub(r"\s*-\s*QT\d{6,}\s*$", "", m.group(1).strip())
    s = re.sub(r"^((RE|FW|FWD|AW)\s*:\s*|EXTERNAL\s*)+", "", subject or "", flags=re.I)
    s = re.sub(r"^(Cyber Protect Business Renewal Notice|Phishield Cyber Protect Business Policy Renewal)\s*[-|:]\s*",
               "", s, flags=re.I)
    s = re.sub(r"\s*-\s*\[External Email\]\s*$", "", s)
    # Subject noise around the client name: 'Quote: X - Cyber', 'Follow-Up | X', 'Corporate Quote : X',
    # 'X - QT0000000', 'X - Cyber Quote Request'.
    s = re.sub(r"^(Quote|Follow-Up|Corporate Quote|Cyber Protect Business Renewal Notification|"
               r"Cyber Protect Business|Policy Renewal|New Quote Request|Request to Quote)\s*[:|\-]\s*", "", s, flags=re.I)
    s = re.sub(r"\s*-\s*QT\d{6,}\s*$", "", s)
    s = re.sub(r"\s*[-|:]\s*(Cyber( Liability| Insurance| Quote( Request| Enquiry)?)?|Requesting Cyber.*)\s*$", "", s, flags=re.I)
    return s.strip(" -|:")[:120] or "Unknown"


LIM_IN_LINE = re.compile(r"R\s?(\d+(?:[.,]\d+)?)\s*(?:M\b|Mil+ion\b)", re.I)
PA_RE = re.compile(r"R\s?(\d[\d,]*\.\d{2})\s*p\.?/?a\b", re.I)
HEAD_CUT = re.compile(r"(?:Please )?note the following|Benefits Included", re.I)


def older_limits(t):
    """Older instruction layouts: 'R10M Cover: R182,772.81 p/a.', a 'R25M Cover:' header followed by
    'With MDR Complete - without Sophos endpoints it's R241,894.40 p/a.' lines, 'R25M @ R86,856.60 p/a',
    or a table 'R20 Million Cover Limit / R30,168.13 p/a'. Returns [(limit, premium, variant)]."""
    head = HEAD_CUT.split(t)[0]
    out, cur = [], None
    for line in head.split("\n"):
        s = line.strip().lstrip("*-•· ").strip()
        if not s:
            continue
        pa = PA_RE.findall(s)
        lm = LIM_IN_LINE.search(s.split("@")[0] if pa else s)
        if lm and (not pa or lm.start() < s.find(pa[0])):
            cur = money(lm.group(1).replace(",", ".") + "M")
        for prem in pa:
            if cur:
                variant = PA_RE.sub("", s).strip(" .:@–-")
                out.append((cur, money(prem), variant if re.search(r"MDR|Sophos|Funds Protect|endpoint", variant, re.I) else ""))
    return out


# The policy wording a quote is ISSUED on decides the product, not how it was priced:
# SME +20% (or any SME-derived price) issued on the corporate wording is a corporate quote.
PROD_RE = re.compile(r"\bon (?:our|the) (SME|corporate)(?:[ -]community[ -]rated)? (?:product|policy|wording)", re.I)
AMT_POS_RE = re.compile(r"R\s?(\d[\d,.]*\d)")


def option_products(t, limits):
    """Product per quoted option: the last 'on our/the X product|policy' phrase before the option's
    premium; if none precedes it, the first one within 400 characters after it; else corporate."""
    phrases = [(m.start(), m.group(1).lower()) for m in PROD_RE.finditer(t)]
    amts = [(m.start(), money("R" + m.group(1))) for m in AMT_POS_RE.finditer(t)]
    used, out = set(), []
    for _, prem in limits:
        pos = next((q for q, v in amts if q not in used and v and prem and abs(v - prem) < 0.01), None)
        prod = None
        if pos is not None:
            used.add(pos)
            before = [k for q, k in phrases if q < pos]
            after = [k for q, k in phrases if pos < q < pos + 400]
            prod = before[-1] if before else (after[0] if after else None)
        # No phrase near the option: the instruction's first product phrase anywhere, else corporate.
        out.append(prod or (phrases[0][1] if phrases else "corporate"))
    return out


SME_OPT_RE = re.compile(r"R\s?([\d]+(?:[.,]\d+)?)\s*M(?:il+ion)?\s+cover\s*@\s*R\s?([\d,]+(?:\.\d+)*)", re.I)


def extra_sme_options(t, limits):
    """'Also quote a R15M option on the SME product ...: R15M cover @ R58,524 p/a.' sits after the
    benefits block, so the head-only limit scan misses it."""
    have = {(l, p) for l, p in limits}
    out = []
    for m in PROD_RE.finditer(t):
        if m.group(1).lower() != "sme":
            continue
        for a, b in SME_OPT_RE.findall(t[m.end(): m.end() + 300]):
            lp = (money(a + "M"), money(b))
            if lp not in have:
                have.add(lp)
                out.append(lp)
    return out


# Per-option corrections a parser cannot infer from the email text.
OVERRIDES = {
    # 'renew the existing cover limit @ R109,649.67' on the SME product; existing cover is R25M
    # (the R200M in the line above is the reinsurer mandate's turnover cap).
    "EM-20260218-3850e3-Opt1": {"cover": 25_000_000.0},
}
DROP = {
    # 'The R132,624.00 p/a in the request is ...' explains a broker figure; it is not a quoted option.
    "EM-20261028-238d5f-Opt2",
}


def parse_instruction(text):
    t = cut_signature(text)
    variants = []
    if LIMIT_RE.search(t):
        head = t.split("Note the following")[0]
        limits = [(money(a + "M"), money(b)) for a, b in LIMIT_RE.findall(head)] or \
            [(money(a + "M"), money(b)) for a, b in LIMIT_RE.findall(t)]
    else:
        old = older_limits(t)
        if not old:
            return None
        limits = [(l, p) for l, p, _ in old]
        variants = [v for _, _, v in old]
        head = HEAD_CUT.split(t)[0]
    extras = extra_sme_options(t, limits)
    if extras:
        limits = limits + extras
        if variants:
            variants = variants + [""] * len(extras)
    products = option_products(t, limits)
    product = products[0] if products else "corporate"
    tm = TO_RE.search(t)
    turnover = money(tm.group(1) or tm.group(2)) if tm else None
    if turnover and turnover < 100_000:
        turnover *= 1e6  # 'R311 t/o' means R311M
    im = IND_RE.search(t) or IND2_RE.search(t.split("\n")[0] + " " + head[:400])
    secs = sections(t, limits)
    excess_all = [money(x) for x in re.findall(r"excess is\s+(R\s?[\d.,]+\s*[MK]?)", t, re.I)]
    conds = bullets_after(t, r"following conditions of cover[^\n]*\n")
    endorse = bullets_after(t, r"Note the following benefits and endorsements[^\n]*\n")
    return {"text": t, "product": product, "products": products, "n_extra": len(extras), "turnover": turnover,
            "main_industry": im.group(1).strip() if im else None,
            "sub_industry": im.group(2).strip() if im else None,
            "limits": limits, "variants": variants, "sections": secs, "excess_all": excess_all,
            "conditions": conds, "endorsements_head": endorse,
            "without_rm": bool(re.search(r"without (the )?RM fee|excluding the RM fee", t, re.I))}


def records_for_thread(d, source="backfill_email", fname=""):
    msgs = sorted(d.get("messages", []), key=lambda m: int(m.get("internalDate") or 0))
    subject = ""
    for m in msgs:
        subject = subject or headers(m).get("Subject", "")
    all_files = [f for m in msgs for f in attachments(m)]
    instr = []
    for i, m in enumerate(msgs):
        hd = headers(m)
        if OWN not in hd.get("From", ""):
            continue
        p = parse_instruction(body(m))
        if p:
            instr.append((i, m, hd, p))
    recs = []
    for k, (i, m, hd, p) in enumerate(instr):
        later = msgs[i + 1:]
        later_instr_limits = {l for (j, _, _, q) in instr[k + 1:] for l, _ in q["limits"]}
        approved_msg = next((x for x in later if OWN in headers(x).get("From", "")
                             and re.match(r"\s*(Hi [^\n]*\n+\s*)?Happy\b", body(x), re.I)), None)
        date = hd.get("Date") or datetime.utcfromtimestamp(int(m.get("internalDate", 0)) / 1000).isoformat() + "Z"
        base = "EM-" + date[:10].replace("-", "") + "-" + hashlib.sha1(m["id"].encode()).hexdigest()[:6]
        company = company_from(subject, all_files)
        for n, (limit, prem) in enumerate(p["limits"], 1):
            variant = p["variants"][n - 1] if p.get("variants") else ""
            sec = p["sections"].get(limit, "")
            exc = money(m2.group(1)) if (m2 := re.search(r"excess is\s+(R\s?[\d.,]+\s*[MK]?)", sec, re.I)) else \
                (p["excess_all"][n - 1] if len(p["excess_all"]) == len(p["limits"]) else
                 (p["excess_all"][0] if len(set(p["excess_all"])) == 1 else None))
            mil = ("%g" % (limit / 1e6)) if limit else ""
            qts = sorted({q for x in later for f in attachments(x) if re.search(r"- R%s Million -" % re.escape(mil), f)
                          for q in QT_RE.findall(f)})
            status = "instructed"
            if limit in later_instr_limits:
                status = "superseded"
            elif approved_msg is not None and qts:
                status = "approved"
            elif qts:
                status = "quoted"
            elif approved_msg is not None:
                status = "approved"
            hist = [{"at": date, "status": "instructed", "by": "backfill", "note": "instruction email"}]
            if qts:
                hist.append({"at": date, "status": "quoted", "by": "backfill", "note": "admin quote " + ", ".join(qts)})
            if status in ("approved", "superseded"):
                hist.append({"at": headers(approved_msg).get("Date", date) if status == "approved" and approved_msg else date,
                             "status": status, "by": "backfill", "note": "from email thread"})
            recs.append({
                "quote_ref": f"{base}-Opt{n}", "base_ref": base, "option_no": n,
                "product": p["products"][n - 1], "source": source, "pricing_method": "historical",
                "company_name": company, "turnover": p["turnover"],
                "main_industry": p["main_industry"], "sub_industry": p["sub_industry"],
                "cover": limit, "excess": exc,
                "fp_authorised": amount_in(sec, r"Funds Protect authorised") if sec else None,
                "fp_unauthorised": amount_in(sec, r"Funds Protect unauthorised") if sec else None,
                "quoted_premium": prem,
                "final_premium": round(prem * 1.06, 2) if (prem and p["without_rm"]) else None,
                "premium_ex_rm": prem if p["without_rm"] else None,
                "conditions": p["conditions"], "endorsements": [l for l in sec.split("\n") if l.strip()] if sec else p["endorsements_head"],
                "basis": {"without_rm_fee": p["without_rm"], "thread_file": fname, "subject": subject,
                          **({"variant": variant} if variant else {})},
                "mdr": (re.search(r"MDR\s+(Complete|Essentials)", variant, re.I).group(0)
                        if re.search(r"MDR\s+(Complete|Essentials)", variant, re.I) else None),
                "instruction_text": p["text"], "instruction_sent_at": date,
                "thread_id": d.get("id"), "message_id": m.get("id"),
                "admin_quote_number": ", ".join(qts) or None,
                "admin_quote_files": [f for f in all_files if any(q in f for q in qts)] or None,
                "status": status, "status_history": hist, "created_by": "backfill", "created_at": date,
            })
    return recs


def main():
    seen_threads, out = set(), []
    files = sorted(glob.glob("threads/*.json")) + sorted(glob.glob("quote_check/pending/*.json"))
    for f in files:
        if f.endswith("register.json"):
            continue
        try:
            d = json.load(open(f))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(d, dict) or not d.get("id") or d["id"] in seen_threads:
            continue
        seen_threads.add(d["id"])
        out += records_for_thread(d, fname=f)
    # Veilguard-priced quotes (October): tag their source and method.
    reg = json.load(open("quote_check/pending/register.json"))
    vg_threads = {e["thread_id"]: e for e in reg}
    for r in out:
        e = vg_threads.get(r["thread_id"])
        if e:
            r["company_name"] = e.get("entity") or r["company_name"]
            r["source"] = "backfill_veilguard"
            r["pricing_method"] = "engine" if e["key"] in ("cpr0000274", "kzn_crcp0000182") else "sme_plus_20"
            r["notes"] = f"Veilguard register: {e['key']}; {e.get('status', '')}"
    out = [r for r in out if r["quote_ref"] not in DROP]
    for r in out:
        r.update(OVERRIDES.get(r["quote_ref"], {}))
    for r in out:
        print(json.dumps(r, default=str))
    print(json.dumps({"_summary": {"threads": len(seen_threads), "records": len(out)}}), file=sys.stderr)


if __name__ == "__main__":
    main()
