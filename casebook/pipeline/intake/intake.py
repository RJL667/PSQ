"""One-call intake: saved Outlook thread JSON -> intake record (JSON on stdout).

Usage:
    python3 casebook/pipeline/intake/intake.py <thread.json> [--all-messages]

Stdlib only. Reads the broker request (the first message in the thread that is not
our own mail, plus any later external messages before our first reply) and returns:
broker, insured, new/renewal, requested limits, turnover, industry, current insurer
and premium, attachments by type, product route, mailbox month folder, open questions.
"""
import base64
import html
import json
import re
import sys
from datetime import datetime, timezone

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
INTERNAL_DOMAINS = ("phishield",)

# ---------------------------------------------------------------- helpers

def headers(m):
    return {h["name"]: h["value"] for h in (m.get("payload") or {}).get("headers", [])}


def body(m):
    p = m.get("payload") or {}
    d = (p.get("body") or {}).get("data")
    if not d:
        for part in p.get("parts") or []:
            d = (part.get("body") or {}).get("data")
            if d:
                break
    if not d:
        return m.get("snippet") or ""
    try:
        t = base64.urlsafe_b64decode(d + "==").decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return m.get("snippet") or ""
    if "<html" in t[:500].lower() or "<div" in t[:2000].lower():
        t = re.sub(r"<br\s*/?>|</p>|</div>|</tr>", "\n", t, flags=re.I)
        t = html.unescape(re.sub(r"<[^>]+>", " ", t))
    return t.replace("\r\n", "\n")


def ts(m):
    return int(m.get("internalDate") or 0) / 1000.0


def money(s):
    """'R1,14B' -> 1.14e9, 'R127 278 020.00' -> 127278020, 'R7.5M' / 'R7.5 Million' -> 7.5e6."""
    if not s:
        return None
    s = s.strip().upper().replace("\u00a0", " ").lstrip("R").strip()
    mult = 1
    m = re.search(r"\s*(BILLION|BN|B|MILLION|MIL|M|K)\b\.?$", s)
    if m:
        mult = {"BILLION": 1e9, "BN": 1e9, "B": 1e9, "MILLION": 1e6, "MIL": 1e6, "M": 1e6, "K": 1e3}[m.group(1)]
        s = s[: m.start()].strip()
    s = s.replace(" ", "")
    if mult > 1 and re.fullmatch(r"\d+,\d{1,2}", s):
        s = s.replace(",", ".")
    if re.fullmatch(r"\d{1,3}(\.\d{3})+(\.\d{2})?", s) and s.count(".") > 1:
        s = s.replace(".", "", s.count(".") - 1)
    s = s.replace(",", "")
    try:
        return float(s) * mult
    except ValueError:
        return None


def own(m):
    return OWN.lower() in headers(m).get("From", "").lower()


def strip_noise(t):
    """Drop disclaimers, signatures and long legal footers but keep forwarded content."""
    t = re.sub(r"\[cid:[^\]]*\]|<https?://[^>]*>|https?://\S+", " ", t)
    out = []
    for line in t.split("\n"):
        if re.search(r"Authorised Financial Services Provider|intended recipient|antivirus|"
                     r"views and opinions|Consider the environment|confidential, private|"
                     r"renewal or continuation of your polic|POPIA|Disclaimer", line, re.I):
            continue
        out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------------- field extractors

AMT = r"R\s?\d[\d\s.,]*\d(?:\s*(?:billion|bn|million|mil|m|b|k)\b\.?)?|R\s?\d(?:\s*(?:billion|bn|million|mil|m|b|k)\b)?"
TURNOVER_RE = re.compile(
    r"(?:annual\s+)?(?:turn[\s-]?over|T/O|revenue|gross\s+income|annual\s+income)"
    r"\s*(?:\([^)]*\))?\s*(?:of|is|:|-|=|–|approx\.?|approximately|±|\+/-)*\s*(" + AMT + r")", re.I)
TURNOVER_RE2 = re.compile(r"(" + AMT + r")\s*(?:annual\s+)?(?:turn[\s-]?over|T/O|revenue)", re.I)
INDUSTRY_RE = re.compile(r"(?:main\s+)?industry\s*[:\-–]\s*([^\n]{2,80})", re.I)
SUBIND_RE = re.compile(r"sub[\s-]?industry\s*[:\-–]\s*([^\n]{2,80})", re.I)
BUSDESC_RE = re.compile(r"(?:business\s+description|nature\s+of\s+business|occupation)\s*[:\-–]?\s*([^\n]{3,80})", re.I)
CLIENT_RE = re.compile(r"^\s*(?:client|insured|company|entity|client\s+name|insured\s+name|name\s+of\s+insured)"
                       r"\s*(?:name)?\s*[:\-–]\s*([^\n]{3,120})", re.I | re.M)
LIMIT_LINE_RE = re.compile(r"(limit|cover|options?|quote|indemnity|sum\s+insured|R\s?\d+\s*(?:m|mil|million)\b)", re.I)
LIMIT_RE = re.compile(r"R\s?(\d{1,4}(?:[.,]\d{1,2})?)\s*(?:m\b|mil\b|million\b|mill\b)", re.I)
LIMIT_RE_FULL = re.compile(r"R\s?(\d{1,3}(?:[ ,]\d{3}){2,3})(?:\.00)?(?!\d)")
PREM_RE = re.compile(r"(?:current\s+|existing\s+|annual\s+|renewal\s+)?premium\s*(?:of|is|:|-|–|=)?\s*(" + AMT + r")", re.I)
RENEW_RE = re.compile(r"renewal|\brenew\b|\bexpir|hernuwing|"
                      r"lapses", re.I)
OWNPOL_RE = re.compile(r"\b(CYB/R\d{5,}|CPR\d{5,}|CRCP\d{5,}|CRR\d{5,}|CPC\d{5,})\b")
POLICY_RE = re.compile(r"\b(CYB/R\d{5,}|CPR\d{5,}|CRCP\d{5,}|CRR\d{5,}|CPC\d{5,}|CYB/\w+)\b")
INSURERS = ["Bryte", "Phishield", "iTOO", "Hollard", "Santam", "Old Mutual", "OMI", "Chubb", "AIG", "Allianz",
            "Guardrisk", "Lombard", "Camargue", "Infiniti", "Sanlam", "Discovery", "Momentum", "Renasa",
            "Zurich", "Beazley", "Coalition", "Westport", "Constantia", "Centriq", "Mutual & Federal", "Aon",
            "Volkswagen", "Lloyd", "Hiscox", "QBE", "Travelers", "Juslan", "Stalwart", "Cover Holdings"]
INSURER_RE = re.compile(r"(?:current(?:ly)?\s+(?:insured\s+(?:with|by)|insurer|underwriter|with)|"
                        r"existing\s+insurer|incumbent|insured\s+with|underwritten\s+by|placed\s+with)\s*[:\-–]?\s*"
                        r"([A-Z][A-Za-z&' ]{2,40})", re.I)

ATT_TYPES = [
    ("proposal_form", r"proposal|application|questionnaire|\bform\b|risk\s*assess|submission|RAQ|declaration|signed"),
    ("schedule", r"schedule|policy\s*doc|wording|certificate|renewal\s*(notice|invite|terms)|quotation|quote|QT\d{6}"),
    ("afs", r"\bAFS\b|financial\s*statement|annual\s*financial|annual\s*report|financials|audited|management\s*accounts"),
    ("claims", r"claim|loss\s*(run|history)"),
]


def classify_attachment(name):
    for kind, rx in ATT_TYPES:
        if re.search(rx, name or "", re.I):
            return kind
    return "other"


def company_from_subject(subject):
    s = subject or ""
    s = re.sub(r"^((RE|FW|FWD|AW|TR)\s*:\s*|\[?EXTERNAL\]?\s*:?\s*)+", "", s, flags=re.I)
    parts = [p.strip() for p in re.split(r"\s*\|\s*", s) if p.strip()]
    if len(parts) > 1:
        cand = [p for p in parts if not re.search(
            r"cyber|renewal|notification|quote|request|\d{2}\.\d{2}\.\d{4}|^CYB/|^CPR|^CRCP|^CRR|^QT\d|"
            r"turnover|annual|REF_PERSON|quattro|juslan", p, re.I)]
        if cand:
            return cand[0]
    s = re.sub(r"^(Annual Turnover to .*?:\s*)", "", s, flags=re.I)
    s = re.sub(r"^(Corporate Quote|Quote Request|New Quote Request|Request to Quote|Quote|Follow-Up|"
               r"New Cyber Query|Cyber Quote Request|Cyber Protect Business(?: Renewal Notification| Policy Renewal)?|"
               r"Policy Renewal|Cyber Liability|Cyber Insurance|Cyber|BUSINESS INSURANCE)\s*[:|\-–/]\s*", "", s, flags=re.I)
    s = re.sub(r"^(Corporate Quote|Quote Request|Quote|Cyber)\s*[:|\-–/]\s*", "", s, flags=re.I)
    s = re.sub(r"\s*[-|:/–]\s*(Corporate\s+)?(Cyber( Liability| Insurance| Protect| Quote( Request| Enquiry)?)?|"
               r"(Cyber\s+)?Quote( Request)?|Requesting Cyber.*|QT\d{6,}|\d{4} renewal|renewal)\s*$", "", s, flags=re.I)
    s = re.sub(r"\s*[-|:/–]\s*(Corporate\s+)?(Cyber( Liability| Insurance| Quote( Request)?)?|Quote( Request)?)\s*$",
               "", s, flags=re.I)
    s = re.sub(r":\s*Corporate Cyber quote request$", "", s, flags=re.I)
    return s.strip(" -|:/") or None


def norm_entity(s):
    s = (s or "").lower()
    s = re.sub(r"\((pty|proprietary)\)|\bltd\b|\blimited\b|\binc\b|\bnpc\b|\bsoc\b|\bt/a\b.*|[^a-z0-9 ]", " ", s)
    return " ".join(w for w in s.split() if w not in ("the", "pty", "and", "group", "holdings")) or ""


def find_limits(text):
    lims = set()
    for line in text.split("\n"):
        if not LIMIT_LINE_RE.search(line):
            continue
        if re.search(r"excess|deductible|retention|sub-?limit|first\s+amount", line, re.I):
            continue
        if re.search(r"turn[\s-]?over|T/O|revenue|income|premium|excess|deductible", line, re.I) and \
                not re.search(r"limit|cover|option", line, re.I):
            continue
        # strip turnover / premium figures inside mixed lines
        clean = re.sub(r"(turn[\s-]?over|T/O|revenue|premium|excess)[^\n,;]*", " ", line, flags=re.I)
        for a in LIMIT_RE.findall(clean):
            v = money(a.replace(",", ".") + "M")
            if v and 1e6 <= v <= 500e6:
                lims.add(v)
        if re.search(r"limit|cover|indemnity|sum insured", clean, re.I):
            for a in LIMIT_RE_FULL.findall(clean):
                v = money(a)
                if v and 1e6 <= v <= 500e6 and v % 500_000 == 0:
                    lims.add(v)
    # "R20, R25, R50 and R100 Million"
    for m in re.finditer(r"((?:R\s?\d{1,3}(?:[.,]\d)?\s*(?:,|&|and|/|or)\s*)+R\s?\d{1,3}(?:[.,]\d)?)\s*(?:m\b|mil|million)", text, re.I):
        for a in re.findall(r"R\s?(\d{1,3}(?:[.,]\d)?)", m.group(1)):
            v = money(a.replace(",", ".") + "M")
            if v and 1e6 <= v <= 500e6:
                lims.add(v)
    return sorted(lims)


def find_turnover(text):
    for rx in (TURNOVER_RE, TURNOVER_RE2):
        for m in rx.finditer(text):
            v = money(m.group(1))
            if v is None:
                continue
            if v < 10_000:  # 'R311 t/o' means R311M
                v *= 1e6
            if v >= 100_000:
                return v
    return None


# ---------------------------------------------------------------- main record

def intake(d):
    msgs = sorted(d.get("messages", []), key=ts)
    if not msgs:
        return {"error": "empty thread"}
    first_own = next((i for i, m in enumerate(msgs) if own(m)), len(msgs))
    req_msgs = [m for m in msgs[:first_own] if not own(m)] or [m for m in msgs if not own(m)][:1] or msgs[:1]
    req = req_msgs[0]
    h = headers(req)
    subject = h.get("Subject", "")
    text = "\n".join(strip_noise(body(m)) for m in req_msgs)
    snippet_all = subject + "\n" + text

    frm = h.get("From", "")
    sender_email = (re.search(r"<([^>]+)>", frm) or re.search(r"(\S+@\S+)", frm))
    sender_email = sender_email.group(1) if sender_email else frm
    domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
    internal = any(x in domain for x in INTERNAL_DOMAINS) or domain == OWN.split("@")[-1].lower()
    broker_m = re.search(r"\b([A-Z][A-Za-z&]+(?:\s[A-Z][A-Za-z&]+){0,3})\s+(?:Insurance\s+(?:Brokers?|Advisors?)|Brokers?|"
                         r"Financial\s+Services|Risk\s+(?:Services|Solutions))\b", text)
    broker = {"from": frm, "domain": domain, "via_internal": internal,
              "firm": broker_m.group(0).strip() if broker_m else (domain.split(".")[0] if domain and not internal else None)}

    insured = None
    m = CLIENT_RE.search(text)
    if m:
        insured = re.sub(r"\s{2,}.*$", "", m.group(1)).strip(" .:")
    if not insured:
        insured = company_from_subject(subject)

    # Our own renewal = renewal word in the request subject, or our policy number in the subject and a renewal
    # word in the body. A renewal with another insurer is NEW business to us (competitor_renewal).
    first_body = strip_noise(body(req))[:3000]
    own_pol = OWNPOL_RE.search(subject)
    is_renewal = bool(RENEW_RE.search(subject)) or bool(own_pol and RENEW_RE.search(first_body))
    competitor_renewal = (not is_renewal) and bool(RENEW_RE.search(first_body))
    policy = POLICY_RE.search(snippet_all)
    insurer = None
    if is_renewal or competitor_renewal:
        if is_renewal and (re.search(r"Cyber Protect Business (Renewal|Policy Renewal)|Phishield", subject) or own_pol) or \
                (policy and re.match(r"CYB/R|CPR|CRCP|CRR", policy.group(1))):
            insurer = "Phishield (own renewal)"
        else:
            im = INSURER_RE.search(text)
            if im:
                insurer = im.group(1).strip()
            else:
                for name in INSURERS:
                    if re.search(r"\b" + re.escape(name) + r"\b", text) and name not in ("Bryte", "Phishield"):
                        insurer = name
                        break
    pm = PREM_RE.search(text) if (is_renewal or competitor_renewal) else None
    premium = money(pm.group(1)) if pm else None

    limits = find_limits(snippet_all)
    turnover = find_turnover(snippet_all)
    ind = INDUSTRY_RE.search(text)
    sub = SUBIND_RE.search(text)
    desc = BUSDESC_RE.search(text)
    industry = {"main": ind.group(1).strip(" .") if ind and not re.match(r"sub", ind.group(0), re.I) else None,
                "sub": sub.group(1).strip(" .") if sub else None,
                "description": desc.group(1).strip(" .") if desc else None}

    atts = []
    for mm in msgs[:first_own] or msgs[:1]:
        for a in mm.get("attachments") or []:
            if a.get("inline") or re.match(r"(image|RSImage|Outlook-)\S*\.(png|jpe?g|gif)$", a.get("filename") or "", re.I):
                continue
            atts.append({"name": a.get("filename"), "type": classify_attachment(a.get("filename")),
                         "messageId": mm.get("id"), "attachmentId": a.get("attachmentId"),
                         "size": a.get("size"), "kind": a.get("kind")})
    by_type = {}
    for a in atts:
        by_type.setdefault(a["type"], []).append(a["name"])

    asks_corporate = bool(re.search(r"corporate", snippet_all, re.I)) and not re.search(r"\bSME\b", subject)
    asks_sme = bool(re.search(r"\bSME\b|business\s+product|cyber\s+protect\s+business", snippet_all, re.I))
    flags = []
    if turnover is not None and turnover >= 250e6:
        route = "corporate"
        why = "turnover >= R250M"
    elif asks_corporate:
        route = "corporate"
        why = "broker asks for corporate"
    elif turnover is None and limits and max(limits) > 15e6:
        route = "corporate"
        why = "turnover unknown, limit above SME R15M ceiling"
    else:
        route = "sme"
        why = "turnover below R250M" if turnover is not None else "default (turnover not stated)"
    if route == "sme":
        if turnover is not None and turnover > 200e6:
            flags.append("SME rater cannot rate: turnover above R200M")
        if limits and max(limits) > 15e6:
            flags.append("SME rater cannot rate: cover above R15M")
    if flags and route == "sme":
        route = "corporate"
        why += "; " + "; ".join(flags)

    received = datetime.fromtimestamp(ts(req), tz=timezone.utc)
    # Issued wording: since late 2025 almost every quote (incl. SME +20% prices) is issued on the corporate
    # wording, so corporate is the default; SME only when the broker names the SME product and it is SME-ratable.
    wording = "sme" if (route == "sme" and not flags and re.search(r"\bSME\b", text)) else "corporate"
    # Mailbox month = month of the latest message in the thread (the register files by last activity).
    latest = datetime.fromtimestamp(max(ts(m) for m in msgs), tz=timezone.utc)
    folder = ("Corporate Quotes/" if wording == "corporate" else "SME Quotes/") + latest.strftime("%Y-%m")

    questions = []
    if turnover is None:
        questions.append("Annual turnover not stated")
    if not limits:
        questions.append("Requested cover limit(s) not stated")
    if not (industry["main"] or industry["sub"] or industry["description"]):
        questions.append("Industry / business description not stated")
    if "proposal_form" not in by_type:
        questions.append("No proposal form attached" + (" (check attached mail items)" if any(a["kind"] == "item" for a in atts) else ""))
    if is_renewal and not insurer:
        questions.append("Renewal: current insurer not stated")
    if is_renewal and premium is None:
        questions.append("Renewal: current premium not stated")
    if not insured:
        questions.append("Insured entity name unclear")

    return {
        "thread_id": d.get("id"),
        "request_message_id": req.get("id"),
        "received_utc": received.strftime("%Y-%m-%dT%H:%MZ"),
        "subject": subject,
        "broker": broker,
        "insured": insured,
        "type": "Renewal" if is_renewal else "New",
        "policy_number": policy.group(1) if policy else None,
        "requested_limits": limits,
        "turnover": turnover,
        "industry": industry,
        "current_insurer": insurer,
        "current_premium": premium,
        "attachments": atts,
        "attachments_by_type": by_type,
        "product_route": route,
        "issued_wording_likely": wording,
        "competitor_renewal": competitor_renewal,
        "route_reason": why,
        "rater_flags": flags,
        "mailbox_folder": folder,
        "open_questions": questions,
    }


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    d = json.load(open(argv[1]))
    print(json.dumps(intake(d), indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
