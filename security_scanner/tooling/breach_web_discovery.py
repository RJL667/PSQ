#!/usr/bin/env python3
"""
Web breach-discovery prototype (SCN candidate: augment the thin HIBP "previous
breach" checker).

HaveIBeenPwned's /breaches?domain= only fires when a company is itself a
*catalogued, named* breach victim, so it reads 0 for the vast majority of South
African companies even when they have been breached. This tool corroborates a
breach from open, keyless web sources and — crucially — dates it, because a
RECENT confirmed breach materially changes cyber posture.

Two stages — cheap deterministic corroboration + a real research pass:

  STAGE 1 (retrieval, free / keyless):
    1. Google News RSS   — dated press coverage, behind a strict headline gate
       (company name AND a breach term must BOTH appear in the headline, so
       namesakes and generic security news are dropped)
    2. ransomware.live   — leak-site victim listings, matched on victim name or an
       exact victim-domain hit. A listing is direct evidence of compromise and
       therefore floors the verdict at "confirmed".
  (HIBP stays a separate source in the live scanner, cross-referenced there.)

  STAGE 2 (judgment — the vendored deep-search answer engine, ../websearch):
  rather than judging only the headlines we scraped, this RESEARCHES the question:
  multi-provider fan-out (DuckDuckGo / Wikipedia / Mojeek + Gemini Google-Search
  grounding), fuses with RRF, **fetches and reads the top sources**, iterates on
  the remaining gaps, and synthesizes a cited answer. A second cheap Gemini call
  renders that answer into the incident schema. This typically recovers the date
  the breach actually OCCURRED and its root cause — neither of which a headline
  scrape can give (e.g. Dis-Chem: occurred ~2022-04-28, 3.68M records, via the
  third-party provider Grapevine — versus a first *article* date of 2022-05-11).

  Needs GOOGLE_API_KEY (Google AI Studio). Without it — or on any failure — the
  tool degrades to the deterministic verdict; it never hard-fails.

Verdict tiers: confirmed | reported | possible | none.  The judgment source is
reported in the output ("judgment": "deepsearch" | "deterministic").

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
from pathlib import Path
from urllib.parse import quote
from xml.etree import ElementTree as ET

try:
    import requests
except ImportError:  # pragma: no cover
    print("requests not installed", file=sys.stderr); sys.exit(2)

UA = "Mozilla/5.0 (compatible; PhishieldBreachScan/1.0; +https://veilguard.phishield.com)"
TIMEOUT = 15
# Judgment layer: the vendored deep-search answer engine (websearch/) + one cheap
# Gemini structured-output call. Both ride the single GOOGLE_API_KEY.
GEMINI_EXTRACT_MODEL = os.environ.get("GEMINI_EXTRACT_MODEL", "gemini-2.5-flash")
_GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models"

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
    """All core company tokens present in the headline as WHOLE WORDS.

    Word-boundary, not substring: a plain ``in`` test makes short company tokens
    match anything containing them. Observed live on mip.co.za, where the token
    "mip" substring-matched nine unrelated ransomware victims — bMIProjects.de,
    ekonoMIPoolen.se, MIPa.com.br, luMIPlan.com, MIPS Technologies, MIPe.com,
    euroMIP.fr — none of them the insured. Same failure mode as the Dehashed
    staff-attribution fix (SCN-036), same remedy.
    """
    nt = _norm(title)
    return bool(tokens) and all(
        re.search(rf"\b{re.escape(t)}\b", nt) for t in tokens)


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



def _gemini_extract(answer: str, sources: list, company: str, domain: str):
    """Turn the engine's cited prose answer into the scanner's incident schema.

    One cheap, non-grounded Gemini call with a native ``responseSchema`` (no search,
    no page reads — the evidence is already gathered), so it rides the same
    GOOGLE_API_KEY and adds a fraction of a cent. Returns None on any failure."""
    key = (os.environ.get("GOOGLE_API_KEY", "")
           or os.environ.get("GEMINI_API_KEY", "")).strip()
    if not key or not answer.strip():
        return None
    src_lines = "\n".join(
        f"[{i}] {s.get('title') or '?'} — {s.get('url') or '?'}"
        for i, s in enumerate(sources[:12], 1))
    prompt = (
        "You are a cyber-insurance breach analyst. Below is a researched, cited answer "
        f"about whether a company has suffered a data breach.\n\nCompany: {company}\n"
        f"Domain: {domain or '(unknown)'}\n\n--- RESEARCHED ANSWER ---\n{answer[:12000]}\n\n"
        f"--- SOURCES ---\n{src_lines}\n\n"
        "Extract each DISTINCT real security incident suffered by THIS SPECIFIC company. "
        "Ignore incidents at other companies, generic security commentary, and routine "
        "business news. For each incident: incident_date = when the breach actually "
        "OCCURRED (YYYY-MM-DD or YYYY-MM; \"\" if the answer never says), disclosure_date "
        "= when it was first publicly reported/disclosed (\"\" if unknown), "
        "records_affected (e.g. \"3.68M\", \"\" if unstated), breach_type, root_cause "
        "(one short phrase, e.g. 'third-party provider compromised via brute force'; \"\" "
        "if unstated), and confidence (high only when the answer cites multiple "
        "independent or authoritative sources such as a regulator). Overall verdict: "
        "'confirmed' when the answer establishes a real incident on solid sourcing, "
        "'reported' when sourcing is thin or single-source, 'possible' when it is "
        "ambiguous, 'none' when the answer establishes no incident for this company."
    )
    schema = {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["confirmed", "reported", "possible", "none"]},
            "incidents": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "incident_date": {"type": "string"},
                        "disclosure_date": {"type": "string"},
                        "records_affected": {"type": "string"},
                        "breach_type": {"type": "string", "enum": [
                            "ransomware", "data_leak", "credential_breach",
                            "insider_error", "third_party", "unknown"]},
                        "root_cause": {"type": "string"},
                        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                    },
                    "required": ["title", "incident_date", "disclosure_date",
                                 "records_affected", "breach_type", "root_cause",
                                 "confidence"],
                },
            },
        },
        "required": ["verdict", "incidents"],
    }
    try:
        r = requests.post(
            f"{_GEMINI_URL}/{GEMINI_EXTRACT_MODEL}:generateContent?key={key}",
            json={"contents": [{"parts": [{"text": prompt}]}],
                  "generationConfig": {"responseMimeType": "application/json",
                                       "responseSchema": schema,
                                       "temperature": 0}},
            timeout=90)
        if r.status_code != 200:
            print(f"[extract] Gemini HTTP {r.status_code}: {r.text[:180]}", file=sys.stderr)
            return None
        txt = r.json()["candidates"][0]["content"]["parts"][0]["text"]
        return json.loads(txt)
    except Exception as e:
        print(f"[extract] {type(e).__name__}: {e}", file=sys.stderr)
        return None


def judge_with_deepsearch(company: str, domain: str):
    """Judgment layer — the vendored Perplexity-parity deep-search engine.

    Rather than judging only the headlines we retrieved, this *researches the
    question*: multi-provider fan-out (incl. Gemini Google-Search grounding),
    fetches and READS the top sources, iterates on the gaps, and synthesizes a
    cited answer — which typically yields the date the breach actually OCCURRED and
    its root cause, neither of which a headline scrape can give. A second cheap
    Gemini call renders that answer into the scanner's incident schema.

    Returns ``None`` (-> deterministic fallback) when GOOGLE_API_KEY is absent or
    anything fails; the scanner must never hard-fail on this layer."""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from websearch import deep_search, is_configured
    except Exception as e:
        print(f"[deepsearch] engine unavailable: {e}", file=sys.stderr)
        return None
    if not is_configured():
        return None  # no Gemini key -> snippets only, not worth a verdict
    who = f"{company} ({domain})" if domain else company
    query = (
        f"Has {who} suffered a data breach, ransomware attack or other cyber security "
        "incident? For each distinct incident state the date it OCCURRED, the date it "
        "was publicly disclosed, how many records or customers were affected, the root "
        "cause, and whether a regulator took action. If there is no evidence this "
        "specific company was breached, say so plainly."
    )
    res = deep_search(query, depth="deep")
    answer, sources = res.get("answer") or "", res.get("sources") or []
    if res.get("error"):
        print(f"[deepsearch] {res['error']}", file=sys.stderr)
    if not answer:
        return None
    parsed = _gemini_extract(answer, sources, company, domain)
    if parsed is None:
        return None
    parsed["_answer"] = answer
    # Surface only the sources the answer actually CITED. The engine's fused pool
    # is ranked, not filtered, so keyless providers contribute plausible-looking
    # noise (a live mip.co.za run returned Wikipedia's "OR-Tools", "Instagram" and
    # "James Graham (actor)" alongside the three real breach statements). On a
    # broker-facing report an irrelevant source is worse than a missing one.
    cited = sorted({int(n) for n in re.findall(r"\[(\d{1,2})\]", answer)})
    picked = [sources[i - 1] for i in cited if 1 <= i <= len(sources)] or sources[:6]
    parsed["_sources"] = [{"title": s.get("title"), "url": s.get("url"),
                           "provider": s.get("provider") or s.get("providers")}
                          for s in picked[:12]]
    parsed["_providers"] = res.get("providers_used") or []
    return parsed


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
    # A leak-site listing FLOORS the verdict at "confirmed", so how it matched
    # decides whether it may do so. An exact victim-domain match is unambiguous; a
    # name match is only trustworthy when the company's tokens are distinctive —
    # a single short token like "mip" identifies nothing on its own.
    distinctive = any(len(t) >= 5 for tl in token_lists for t in tl) or \
        max((len(tl) for tl in token_lists), default=0) >= 2
    rw_hits = []
    for kw in {company, stem} - {""}:
        for v in fetch_ransomware_live(kw):
            exact_domain = bool(stem and _domain_stem(v["victim_domain"]) == stem)
            if exact_domain or about(v["victim"]):
                v["match"] = "domain" if exact_domain else "name"
                v["authoritative"] = exact_domain or distinctive
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
    # reputable-outlet count reported alongside the researched verdict.
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

    # Judgment layer (deep-search answer engine): authoritative when it runs.
    judged = judge_with_deepsearch(company, domain)
    incidents: list = []
    answer, engine_sources, engine_providers = "", [], []
    if judged is not None:
        judgment = "deepsearch"
        verdict = judged.get("verdict") or det_verdict
        incidents = judged.get("incidents") or []
        answer = judged.get("_answer") or ""
        engine_sources = judged.get("_sources") or []
        engine_providers = judged.get("_providers") or []
        dated = _incident_dates(incidents) or det_dated
        confidence = {"confirmed": "high", "reported": "medium",
                      "possible": "low", "none": "none"}.get(verdict, det_conf)
        # A ransomware leak-site listing is direct evidence of compromise, so it
        # never gets graded below "confirmed" — but only an AUTHORITATIVE match
        # (exact victim domain, or a distinctive company name) may force that.
        if any(v.get("authoritative") for v in rw_hits) and \
                verdict in ("reported", "possible", "none"):
            verdict, confidence = "confirmed", "high"
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
        "narrative": answer,
        "engine_sources": engine_sources,
        "news_hits": [{**h, "date": h["date"].date().isoformat() if h["date"] else None} for h in news_hits],
        "ransomware_hits": [{**v, "date": v["date"].isoformat() if v["date"] else None} for v in rw_hits],
        "reputable_source_count": n_rep,
        "sources_checked": (["google_news_rss", "ransomware.live"]
                            + [f"deepsearch:{p}" for p in engine_providers]),
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
        print("\n  Distinct incidents (researched, clustered & dated):")
        for inc in res["incidents"]:
            when = inc.get("incident_date") or "?"
            disc = inc.get("disclosure_date") or ""
            rec = f", {inc['records_affected']} records" if inc.get("records_affected") else ""
            print(f"    • occurred [{when}]"
                  + (f" disclosed [{disc}]" if disc else "")
                  + f"  {inc.get('title', '?')}")
            print(f"        {inc.get('breach_type', '?')}, {inc.get('confidence', '?')} confidence{rec}")
            if inc.get("root_cause"):
                print(f"        root cause: {inc['root_cause']}")
    if res.get("engine_sources"):
        print("\n  Researched sources:")
        for s in res["engine_sources"][:8]:
            print(f"    • {(s.get('title') or '?')[:70]}  {(s.get('url') or '')[:80]}")
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
