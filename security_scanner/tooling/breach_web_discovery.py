#!/usr/bin/env python3
"""
Web breach-discovery prototype (SCN candidate: augment the thin HIBP "previous
breach" checker).

HaveIBeenPwned's /breaches?domain= only fires when a company is itself a
*catalogued, named* breach victim, so it reads 0 for the vast majority of South
African companies even when they have been breached. This tool corroborates a
breach from open, keyless web sources and — crucially — dates it, because a
RECENT confirmed breach materially changes cyber posture.

Two stages — "we fetch, Claude judges":

  STAGE 1 (retrieval, free / keyless): pull dated candidates from open sources —
    1. Google News RSS   — dated press coverage (disclosure timeline)
    2. ransomware.live   — confirmed ransomware-victim leak-site listings + dates
  with a deterministic headline gate (company name AND a breach term must both
  appear in the HEADLINE; body-only mentions dropped) so noise never reaches
  stage 2. (HIBP stays a separate source in the live scanner, cross-referenced.)

  STAGE 2 (judgment, Claude Sonnet 5, gated on ANTHROPIC_API_KEY): the model reads
  the retrieved candidates and confirms which describe a REAL breach of THIS
  company, clusters same-incident coverage into distinct incidents, extracts the
  actual INCIDENT date (not just the article date), and grades confidence. If no
  key / SDK / on any error it degrades gracefully to the deterministic verdict —
  the tool never hard-fails on the LLM layer.

Verdict tiers: confirmed | reported | possible | none.  Judgment source is
reported in the output ("judgment": "claude-sonnet-5" | "deterministic").

Usage:
    python breach_web_discovery.py "Takealot" takealot.com
    python breach_web_discovery.py "Dis-Chem" dischem.co.za --json
    python breach_web_discovery.py "Takealot" takealot.com --alias "Takealot Fulfilment"

Reporting-only by design. Wiring recency into the score is a SEPARATE, gated
step (financial-model anchoring: one channel, no double-count, manual lock).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote
from xml.etree import ElementTree as ET

try:
    import requests
except ImportError:  # pragma: no cover
    print("requests not installed", file=sys.stderr); sys.exit(2)

UA = "Mozilla/5.0 (compatible; PhishieldBreachScan/1.0; +https://veilguard.phishield.com)"
TIMEOUT = 15
CLAUDE_MODEL = "claude-sonnet-5"  # LLM judgment layer; gated on env ANTHROPIC_API_KEY

# Breach lexicon — terms that, in a HEADLINE alongside the company name, denote a
# real security incident (not "how to prevent breaches" filler). Deliberately
# excludes the bare word "hack" (growth-hack / life-hack noise).
_BREACH_RE = re.compile(
    r"\b(data breach|breach(?:ed|es)?|hacked|hackers|ransomware|data leak|leaked|"
    r"leak of|cyber[- ]?attack|cyberattack|exposed (?:data|records|clients)|"
    r"records (?:exposed|stolen|leaked)|information regulator|popia (?:fine|breach)|"
    r"stolen data|data (?:theft|compromised)|compromised (?:data|records)|"
    r"clients (?:hacked|exposed))\b",
    re.I,
)
# Titles that are clearly advisory / educational, not an incident report.
_ADVISORY_RE = re.compile(r"\b(how to|tips|best practice|webinar|guide to|prevent|protect yourself|explainer)\b", re.I)
# Records-affected figure, e.g. "3.6m records", "over 3.6 million", "1,200,000".
_RECORDS_RE = re.compile(r"([\d.,]+)\s*(m|million|k|thousand|billion|bn)?\s*(?:records|clients|customers|users|accounts|people)", re.I)
# Generic corporate suffixes stripped when deriving the company's core tokens.
_SUFFIXES = {"ltd", "pty", "proprietary", "limited", "group", "holdings", "inc",
             "incorporated", "sa", "rsa", "plc", "co", "company", "corporation",
             "corp", "the", "and", "&"}

# Google News reports the OUTLET NAME (e.g. "MyBroadband"), not its domain, and
# the link is a news.google.com redirect — so reputability is matched on the
# normalised outlet name.
REPUTABLE_NAMES = {
    "mybroadband", "itweb", "news24", "business day", "businesslive", "business live",
    "techcentral", "moneyweb", "daily maverick", "iol", "times live", "timeslive",
    "ewn", "eyewitness news", "sabc", "moonstone", "techradar", "bleeping computer",
    "bleepingcomputer", "the record", "therecord", "hacker news", "hackernews",
    "securityweek", "security week", "reuters", "bbc", "guardian", "wired", "zdnet",
    "dark reading", "darkreading", "infosecurity", "cyber daily", "cyberdaily",
}


def is_reputable(outlet: str) -> bool:
    o = _norm(outlet)
    return any(rn in o for rn in REPUTABLE_NAMES)


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9 ]", " ", (s or "").lower())


def company_tokens(name: str) -> list[str]:
    """Distinctive tokens a headline must contain to be *about* this company."""
    toks = [t for t in _norm(name).split() if t and t not in _SUFFIXES and len(t) > 1]
    return toks or _norm(name).split()


def title_is_about(title: str, tokens: list[str]) -> bool:
    """All core company tokens present in the headline (order-independent)."""
    nt = _norm(title)
    return bool(tokens) and all(t in nt for t in tokens)


def extract_records(title: str) -> str | None:
    m = _RECORDS_RE.search(title)
    if not m:
        return None
    return m.group(0).strip()


# --- sources ---------------------------------------------------------------

def fetch_google_news(query: str) -> list[dict]:
    url = ("https://news.google.com/rss/search?q=" + quote(query)
           + "&hl=en-ZA&gl=ZA&ceid=ZA:en")
    out: list[dict] = []
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=TIMEOUT)
        if r.status_code != 200:
            return out
        root = ET.fromstring(r.content)
        for item in root.iterfind(".//item"):
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub = (item.findtext("pubDate") or "").strip()
            src_el = item.find("{*}source")
            source = (src_el.text.strip() if src_el is not None and src_el.text else "")
            try:
                dt = parsedate_to_datetime(pub) if pub else None
                if dt and dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except Exception:
                dt = None
            out.append({"title": title, "url": link, "date": dt, "outlet": source})
    except Exception:
        pass
    return out


def fetch_ransomware_live(keyword: str) -> list[dict]:
    url = "https://api.ransomware.live/v2/searchvictims/" + quote(keyword)
    out: list[dict] = []
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=TIMEOUT)
        if r.status_code != 200:
            return out
        for v in (r.json() or []):
            raw = v.get("attackdate") or v.get("discovered") or ""
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00")) if raw else None
                if dt and dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except Exception:
                dt = None
            out.append({
                "victim": v.get("victim") or "",
                "group": v.get("group") or v.get("group_name") or "",
                "date": dt, "country": v.get("country") or "",
                "victim_domain": (v.get("domain") or "").lower().strip(),
                "url": v.get("claim_url") or v.get("url") or "",
                "description": (v.get("description") or "")[:240],
            })
    except Exception:
        pass
    return out


# --- orchestration ---------------------------------------------------------

def _domain_stem(domain: str) -> str:
    return re.sub(r"^www\.", "", (domain or "").lower()).split(".")[0]


def _parse_loose_date(s: str):
    """'YYYY' / 'YYYY-MM' / 'YYYY-MM-DD' -> aware UTC datetime; None if empty/bad."""
    s = (s or "").strip()[:10]
    for fmt in ("%Y-%m-%d", "%Y-%m", "%Y"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _incident_dates(incidents: list) -> list:
    out = []
    for inc in incidents:
        d = _parse_loose_date(inc.get("incident_date") or inc.get("disclosure_date") or "")
        if d:
            out.append(d)
    return sorted(out)


# JSON shape Sonnet 5 returns (structured outputs — additionalProperties:false and
# every field required, so the API enforces the schema and we never guess-parse).
_JUDGE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["verdict", "incidents"],
    "properties": {
        "verdict": {"type": "string", "enum": ["confirmed", "reported", "possible", "none"]},
        "incidents": {
            "type": "array",
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["title", "incident_date", "disclosure_date", "records_affected",
                             "breach_type", "confidence", "source_refs"],
                "properties": {
                    "title": {"type": "string"},
                    "incident_date": {"type": "string"},
                    "disclosure_date": {"type": "string"},
                    "records_affected": {"type": "string"},
                    "breach_type": {"type": "string", "enum": [
                        "ransomware", "data_leak", "credential_breach", "insider_error",
                        "third_party", "unknown"]},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                    "source_refs": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
    },
}


def judge_with_claude(company: str, domain: str, news_hits: list, rw_hits: list):
    """LLM judgment layer ("we fetch, Claude judges"). Given the deterministically-
    retrieved candidates, Sonnet 5 confirms which describe a REAL breach of THIS
    company, clusters same-incident coverage into one entry, extracts the actual
    incident date, and grades confidence. Returns None -> deterministic fallback when
    ANTHROPIC_API_KEY is absent, the SDK is missing, or on any API error — the scanner
    must never hard-fail on the LLM layer."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic
    except ImportError:
        return None
    lines = []
    for i, h in enumerate(news_hits):
        d = h["date"].date().isoformat() if h["date"] else "?"
        lines.append(f"[N{i}] {d} | {h['outlet'] or '?'} | {h['title']}")
    for j, v in enumerate(rw_hits):
        d = v["date"].date().isoformat() if v["date"] else "?"
        lines.append(f"[R{j}] {d} | ransomware leak-site ({v['group'] or '?'}) | "
                     f"victim={v['victim']} {v['victim_domain']}")
    if not lines:
        return {"verdict": "none", "incidents": []}
    prompt = (
        "You are a cyber-insurance breach analyst. Below are candidate open-web results "
        f"for a company.\n\nCompany: {company}\nDomain: {domain or '(unknown)'}\n\n"
        "Candidates (N = news headline, R = ransomware leak-site listing):\n"
        + "\n".join(lines) +
        "\n\nDecide which candidates describe a REAL data-breach or security incident of "
        "THIS SPECIFIC company — not a different company with a similar name, not generic "
        "security advice, not routine business or financial news. Cluster candidates that "
        "describe the SAME incident into one entry. For each distinct real incident give: "
        "title; incident_date (when the breach actually OCCURRED if the coverage states or "
        "implies it, as YYYY-MM-DD or YYYY-MM, else \"\"); disclosure_date (when first "
        "publicly reported, else \"\"); records_affected (e.g. \"3.6M\", else \"\"); "
        "breach_type; confidence (high = a leak-site listing or two or more reputable "
        "outlets; low = a single ambiguous mention); and source_refs (the candidate "
        "indices you relied on, e.g. [\"N0\",\"R1\"]). Then an overall verdict: confirmed "
        "| reported | possible | none. If NO candidate is a real incident for this "
        "company, return an empty incidents list and verdict \"none\"."
    )
    try:
        client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
        resp = client.messages.create(
            model=CLAUDE_MODEL, max_tokens=4096,
            thinking={"type": "disabled"},  # structured extraction — cheapest, deterministic
            output_config={"format": {"type": "json_schema", "schema": _JUDGE_SCHEMA}},
            messages=[{"role": "user", "content": prompt}],
        )
        text = next((b.text for b in resp.content if getattr(b, "type", "") == "text"), "")
        return json.loads(text)
    except Exception as e:  # any SDK/API/parse failure -> deterministic fallback
        print(f"[judge_with_claude] falling back to deterministic: {e}", file=sys.stderr)
        return None


def discover(company: str, domain: str = "", aliases: list[str] | None = None) -> dict:
    aliases = aliases or []
    stem = _domain_stem(domain)
    # Token set the headline must match — the company name, or an alias, or the
    # domain brand. Each candidate token-list is tried; any match qualifies.
    token_lists = [company_tokens(company)] + [company_tokens(a) for a in aliases]
    if stem and stem not in {t for tl in token_lists for t in tl}:
        token_lists.append([stem])

    def about(title: str) -> bool:
        return any(title_is_about(title, tl) for tl in token_lists)

    q_company = company if " " not in company else f'"{company}"'
    news_query = (f'{q_company} (data breach OR hacked OR ransomware OR "data leak" '
                  f'OR cyberattack OR "information regulator")')
    news = fetch_google_news(news_query)
    time.sleep(0.4)

    # keep only headlines about this company that carry a breach term (and aren't advisory)
    news_hits = []
    seen = set()
    for n in news:
        t = n["title"]
        if not about(t) or not _BREACH_RE.search(t):
            continue
        if _ADVISORY_RE.search(t) and not re.search(r"\b(breach|hacked|ransomware|leak)\b", t, re.I):
            continue
        key = _norm(t)[:80]
        if key in seen:
            continue
        seen.add(key)
        outlet = n["outlet"] or (n["title"].rsplit(" - ", 1)[-1] if " - " in n["title"] else "")
        news_hits.append({
            "title": t, "url": n["url"], "date": n["date"], "outlet": outlet,
            "records": extract_records(t),
        })

    # ransomware leak-site listings (confirmed victims). Match victim name to company.
    # A leak-site listing counts only on a NAME match (company tokens in the
    # victim name) or an EXACT victim-domain match — never a loose description
    # mention, which would false-positive on any dump that name-drops the company.
    rw_hits = []
    for kw in {company, stem} - {""}:
        for v in fetch_ransomware_live(kw):
            if about(v["victim"]) or (stem and _domain_stem(v["victim_domain"]) == stem):
                rw_hits.append(v)
        time.sleep(0.4)
    # de-dupe ransomware hits
    rw_seen, rw_dedup = set(), []
    for v in rw_hits:
        k = (v["group"], (v["date"] or "").__str__())
        if k in rw_seen:
            continue
        rw_seen.add(k); rw_dedup.append(v)
    rw_hits = rw_dedup

    # Deterministic timeline + verdict — the fallback, and the source of the
    # reputable-outlet count that also feeds Claude's confidence prompt.
    det_dated = sorted([h["date"] for h in news_hits if h["date"]]
                       + [v["date"] for v in rw_hits if v["date"]])
    n_rep = sum(1 for h in news_hits if is_reputable(h["outlet"]))
    if rw_hits or n_rep >= 2:
        det_verdict, det_conf = "confirmed", "high"
    elif n_rep == 1 or len(news_hits) >= 2:
        det_verdict, det_conf = "reported", "medium"
    elif news_hits:
        det_verdict, det_conf = "possible", "low"
    else:
        det_verdict, det_conf = "none", "none"

    # LLM judgment layer (Sonnet 5): authoritative when it runs; deterministic otherwise.
    claude = judge_with_claude(company, domain, news_hits, rw_hits)
    incidents: list = []
    if claude is not None:
        judgment = CLAUDE_MODEL
        verdict = claude.get("verdict") or det_verdict
        incidents = claude.get("incidents") or []
        dated = _incident_dates(incidents) or det_dated
        confidence = {"confirmed": "high", "reported": "medium",
                      "possible": "low", "none": "none"}.get(verdict, det_conf)
    else:
        judgment, verdict, confidence, dated = "deterministic", det_verdict, det_conf, det_dated

    now = datetime.now(timezone.utc)
    most_recent = dated[-1] if dated else None
    earliest = dated[0] if dated else None
    months_since = round((now - most_recent).days / 30.44, 1) if most_recent else None
    recent_flag = bool(most_recent and months_since is not None and months_since <= 24
                       and verdict in ("confirmed", "reported"))

    return {
        "company": company, "domain": domain,
        "judgment": judgment,
        "verdict": verdict, "confidence": confidence,
        "recent_material_breach": recent_flag,
        "most_recent_breach": most_recent.date().isoformat() if most_recent else None,
        "earliest_signal": earliest.date().isoformat() if earliest else None,
        "months_since_most_recent": months_since,
        "incidents": incidents,
        "news_hits": [{**h, "date": h["date"].date().isoformat() if h["date"] else None} for h in news_hits],
        "ransomware_hits": [{**v, "date": v["date"].isoformat() if v["date"] else None} for v in rw_hits],
        "reputable_source_count": n_rep,
        "sources_checked": ["google_news_rss", "ransomware.live"] + ([CLAUDE_MODEL] if claude is not None else []),
    }


def _print_human(res: dict) -> None:
    bar = "=" * 68
    print(bar)
    print(f"  Breach web-discovery — {res['company']}  ({res['domain'] or 'no domain'})")
    print(bar)
    v = res["verdict"].upper()
    print(f"  Verdict:     {v}   (confidence: {res['confidence']})   [judged by: {res.get('judgment', 'deterministic')}]")
    if res["recent_material_breach"]:
        print(f"  [!] RECENT breach ({res['months_since_most_recent']} months ago) - materially affects posture")
    print(f"  Timeline:    earliest {res['earliest_signal'] or '—'}  |  most recent {res['most_recent_breach'] or '—'}")
    print(f"  Reputable press hits: {res['reputable_source_count']}   Leak-site hits: {len(res['ransomware_hits'])}")
    if res.get("incidents"):
        print("\n  Distinct incidents (LLM-clustered & dated):")
        for inc in res["incidents"]:
            when = inc.get("incident_date") or inc.get("disclosure_date") or "?"
            rec = f", {inc['records_affected']} records" if inc.get("records_affected") else ""
            print(f"    • [{when}] {inc.get('title', '?')} "
                  f"({inc.get('breach_type', '?')}, {inc.get('confidence', '?')} conf{rec})")
    if res["ransomware_hits"]:
        print("\n  Ransomware leak-site listings (confirmed):")
        for v in res["ransomware_hits"]:
            print(f"    • [{v['date'] or '?'}] group={v['group'] or '?'}  {v['url']}")
    if res["news_hits"]:
        print("\n  Press coverage (headline = company + breach term):")
        for h in res["news_hits"]:
            rec = f"  [~{h['records']}]" if h["records"] else ""
            print(f"    • [{h['date'] or '?'}] {h['title']}{rec}")
    if res["verdict"] == "none":
        print("\n  No corroborated breach evidence found in open web sources.")
    print(bar)


def main() -> None:
    ap = argparse.ArgumentParser(description="Web breach-discovery prototype")
    ap.add_argument("company")
    ap.add_argument("domain", nargs="?", default="")
    ap.add_argument("--alias", action="append", default=[], help="extra name the company is known by")
    ap.add_argument("--json", action="store_true", help="emit structured JSON")
    args = ap.parse_args()
    try:  # keep the box/bullets legible on Windows' cp1252 console
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    res = discover(args.company, args.domain, args.alias)
    if args.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        _print_human(res)


if __name__ == "__main__":
    main()
