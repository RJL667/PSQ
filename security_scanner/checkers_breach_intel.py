"""Breach-history intelligence (SCN-040) — the live-scan checker.

HIBP's breaches-by-domain catalogue only fires when a company is itself a
*catalogued named victim*, so `breaches.breach_count` reads 0 for the great
majority of South African companies even when they have been breached. This
checker corroborates breach history from the open web and — crucially — DATES it,
because a recent confirmed breach materially changes posture while a decade-old
one is largely historical.

It runs the vendored deep-search answer engine (``websearch/``): multi-provider
fan-out, the top source pages are actually fetched and READ, gaps are re-searched,
and a cited answer is synthesized; a second cheap Gemini call renders that into
structured incidents (occurrence date, disclosure date, records, root cause).

SAFETY CONTRACT — why this file is defensive about the key
    The engine degrades *silently* to snippet-only results when the Gemini key is
    missing or rotated (upstream shipped prod that way for weeks). For an
    underwriting tool a silent degradation is worse than an outage: "no breaches
    found" would read as a clean bill of health. So the key is health-probed FIRST
    (free ``/v1beta/models`` call) and, unless it is active, this checker returns a
    NON-CONCLUSIVE status (``no_api_key`` / ``error``) which the dashboard renders
    as "Not assessed" and never as green. A verdict is only ever emitted from a
    scan that actually had working research behind it.

Reporting-only: nothing here feeds the score. Wiring the dated result into
``breaches.breach_count`` / ``most_recent_breach`` (and thus the DBI recency
lever) is a separate, gated decision under the financial-model anchoring rules.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

UA = "Mozilla/5.0 (compatible; PhishieldBreachScan/1.0; +https://veilguard.phishield.com)"

# Breach history barely changes; re-researching every rescan just burns credits.
CACHE_TTL_S = float(os.environ.get("BREACH_INTEL_CACHE_TTL_S", 14 * 24 * 3600))
CACHE_DIR = _HERE / "scans" / "_cache" / "breach_intel"
# "quick" (1 round) is the live-scan default: it still grounds, reads pages and
# synthesizes, but fits comfortably inside the scanner's 180s phase budget.
DEPTH = os.environ.get("BREACH_INTEL_DEPTH", "quick")
TIMEOUT_S = float(os.environ.get("BREACH_INTEL_TIMEOUT_S", "110"))

# Boilerplate that clutters <title> tags; stripped when deriving a company name.
_TITLE_NOISE = re.compile(
    r"\b(online shopping|shop online|official (site|website|store)|home ?page|homepage|"
    r"welcome to|home|buy online|south africa|sa's leading.*|login|sign in)\b", re.I)
_SUFFIX = re.compile(r"\b(pty\.? ?ltd\.?|ltd\.?|limited|inc\.?|incorporated|group|holdings)\b", re.I)


def _domain_stem(domain: str) -> str:
    return re.sub(r"^www\.", "", (domain or "").lower()).split(".")[0]


def resolve_company_name(domain: str, timeout: int = 10) -> tuple[str, str]:
    """Best-effort company name for the search query -> (name, source).

    The scanner only knows a domain, but the web talks about companies by name.
    Prefer ``og:site_name`` (usually already clean), then the ``<title>``'s first
    segment with boilerplate stripped, else the domain stem. Never raises.
    """
    stem = _domain_stem(domain)
    fallback = (stem.replace("-", " ").title(), "domain_stem")
    if not requests or not domain:
        return fallback
    for url in (f"https://{domain}", f"http://{domain}"):
        try:
            r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout,
                             allow_redirects=True)
            if r.status_code >= 400 or not r.text:
                continue
            html = r.text[:200_000]
            m = re.search(
                r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']{2,80})["\']',
                html, re.I) or re.search(
                r'<meta[^>]+content=["\']([^"\']{2,80})["\'][^>]+property=["\']og:site_name["\']',
                html, re.I)
            if m:
                name = _clean_name(m.group(1))
                if name:
                    return name, "og:site_name"
            m = re.search(r"<title[^>]*>(.{2,160}?)</title>", html, re.I | re.S)
            if m:
                # "Takealot.com: Online Shopping | SA's leading online store"
                #  -> first segment, boilerplate stripped -> "Takealot"
                first = re.split(r"\s*[|–—:·-]\s*", m.group(1).strip())[0]
                name = _clean_name(first) or _clean_name(m.group(1))
                if name:
                    return name, "title"
        except Exception:
            continue
    return fallback


def _clean_name(raw: str) -> str:
    s = re.sub(r"\s+", " ", (raw or "")).strip()
    s = _TITLE_NOISE.sub("", s)
    s = _SUFFIX.sub("", s)
    s = re.sub(r"\.(com|co\.za|net|org)\b", "", s, flags=re.I)
    s = s.strip(" .,-|:–—")
    # A stray tagline fragment is worse than the domain stem.
    return s if 2 <= len(s) <= 60 else ""


def _cache_path(domain: str) -> Path:
    safe = re.sub(r"[^a-z0-9.\-]", "_", (domain or "").lower())
    return CACHE_DIR / f"{safe}.json"


def _cache_read(domain: str):
    try:
        p = _cache_path(domain)
        if p.exists() and (time.time() - p.stat().st_mtime) < CACHE_TTL_S:
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def _cache_write(domain: str, payload: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(domain).write_text(json.dumps(payload), encoding="utf-8")
    except Exception:
        pass


class BreachIntelChecker:
    """Open-web breach-history corroboration. Reporting-only."""

    def check(self, domain: str, company_name: str | None = None) -> dict:
        result = {
            "status": "completed",
            "key_status": "unknown",
            "company_name": "",
            "name_source": "",
            "verdict": "none",
            "confidence": "none",
            "incident_count": 0,
            "most_recent_breach": None,
            "months_since_most_recent": None,
            "recent_material_breach": False,
            "incidents": [],
            "narrative": "",
            "sources": [],
            "cached": False,
            "issues": [],
        }
        if not domain:
            result["status"] = "error"
            result["error"] = "no domain"
            return result

        # --- key health FIRST: never emit a verdict from an unresearched scan ---
        try:
            from websearch import check_key
            ks = check_key()
        except Exception as e:
            ks = {"status": "error", "error": f"{type(e).__name__}: {e}"}
        result["key_status"] = ks.get("status", "error")
        if ks.get("key_fingerprint"):
            result["key_fingerprint"] = ks["key_fingerprint"]
        if ks.get("status") != "active":
            # Non-conclusive on purpose -> dashboard shows "Not assessed", not green.
            result["status"] = ("no_api_key" if ks.get("status") == "no_api_key"
                                else "error")
            result["verdict"] = "unknown"
            result["confidence"] = "none"
            detail = ks.get("error") or f"HTTP {ks.get('http')}"
            result["error"] = detail
            cause = {
                "no_api_key": "is not configured",
                "quota_exhausted": "has no credit left — top up the Google AI "
                                   "Studio billing account",
                "inactive": f"was rejected ({detail}) — it has likely been rotated "
                            "or revoked; update GOOGLE_API_KEY",
            }.get(ks.get("status"), f"could not be verified ({detail})")
            result["issues"].append(
                f"Breach-history research did not run: the web-search API key {cause}. "
                "This scan can neither confirm nor rule out a prior breach — treat "
                "the breach history as UNASSESSED, not clean."
            )
            return result

        cached = _cache_read(domain)
        if cached:
            cached["cached"] = True
            cached.setdefault("issues", [])
            return cached

        name, source = (company_name, "provided") if company_name else resolve_company_name(domain)
        result["company_name"], result["name_source"] = name, source

        try:
            sys.path.insert(0, str(_HERE / "tooling"))
            from breach_web_discovery import discover
            found = discover(name, domain)
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"{type(e).__name__}: {e}"
            result["verdict"] = "unknown"
            result["issues"].append(
                "Breach-history research failed to complete; this scan cannot "
                "confirm or rule out a prior breach.")
            return result

        # The discovery layer degrades to a deterministic verdict if the engine
        # fell over mid-flight; that is weaker evidence, so say so rather than
        # presenting it as researched.
        judged_by = found.get("judgment", "deterministic")
        if judged_by != "deepsearch":
            result["issues"].append(
                "Breach research degraded to headline-matching only; treat a "
                "'none' verdict as unconfirmed rather than clean.")

        incidents = found.get("incidents") or []
        result.update({
            "judgment": judged_by,
            "verdict": found.get("verdict", "none"),
            "confidence": found.get("confidence", "none"),
            "incident_count": len(incidents),
            "most_recent_breach": found.get("most_recent_breach"),
            "months_since_most_recent": found.get("months_since_most_recent"),
            "recent_material_breach": bool(found.get("recent_material_breach")),
            "incidents": incidents,
            "narrative": (found.get("narrative") or "")[:4000],
            "sources": (found.get("engine_sources") or [])[:10],
            "leak_site_hits": len(found.get("ransomware_hits") or []),
            "sources_checked": found.get("sources_checked") or [],
        })

        for inc in incidents:
            when = inc.get("incident_date") or inc.get("disclosure_date") or "date unknown"
            rec = f", {inc['records_affected']} records" if inc.get("records_affected") else ""
            cause = f" — {inc['root_cause']}" if inc.get("root_cause") else ""
            result["issues"].append(
                f"Breach ({inc.get('confidence', '?')} confidence) [{when}]: "
                f"{inc.get('title', 'incident')}{rec}{cause}")
        if result["recent_material_breach"]:
            result["issues"].append(
                f"RECENT breach — most recent incident {result['months_since_most_recent']} "
                "months ago; recent incidents materially affect cyber posture.")

        # Only cache a properly RESEARCHED result. Caching a degraded run would
        # pin a weak answer for the whole TTL — exactly what happened when the
        # Gemini credits lapsed mid-scan: the headline-only fallback would have
        # been served for 14 days after billing was restored.
        if judged_by == "deepsearch":
            _cache_write(domain, dict(result, cached=False))
        return result
