"""Pluggable web-search providers + weighted Reciprocal Rank Fusion (shared).

Each provider is ``async def p(client, query, limit, recency, *, cfg=None) ->
list[SearchResult]`` and is **fail-soft** (any error → ``[]`` so one dead
provider never sinks a search). The engine fans a query (and its sub-queries)
across every *enabled* provider in parallel and fuses the ranked lists with RRF
— provider-diverse retrieval, like a metasearch engine, with **no LLM reranker**
in the hot path.

Always-on (no key, no container): DuckDuckGo (Bing-based), Wikipedia
(encyclopedic), Mojeek (independent crawler — best-effort; it 403s datacenter
IPs, so in cloud deployments it contributes nothing and simply fails soft).

Keyed, configured in **Settings › Search** (``cc_search_settings``, resolved by
``search_config.py``) and falling back to env: Brave, Tavily, Exa, Serper,
SearXNG. Gemini ``google_search`` grounding is handled in ``web_answer`` (it
also yields the grounded summary + query expansion) and feeds its chunks into
the same RRF pool.

[SEARCH_KEYS_2026-07-25] Providers used to read their key straight from
``os.environ``. They now take the resolved :class:`SearchConfig`; ``cfg=None``
keeps the old env behaviour so the module still works standalone (and in the
mocked tests).

Hard deps: stdlib + httpx. ``bs4`` is used for DuckDuckGo parsing when
importable, else a tolerant regex fallback (sub-agents image ships httpx only).
"""

from __future__ import annotations

import html as _html
import os
import re
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional
from urllib.parse import parse_qs, unquote, urlparse

import httpx

try:  # pragma: no cover - environment-specific
    from bs4 import BeautifulSoup as _BS
except Exception:  # pragma: no cover
    _BS = None

# General fetches/searches present as a normal browser — most content sites
# (and DuckDuckGo) serve full pages to it.
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
# Fuller browser-like headers — DuckDuckGo/Mojeek serve results more reliably and
# bot-block less when Accept/Accept-Language are present (UA alone trips heuristics).
_BROWSER_HEADERS = {
    "User-Agent": _USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
# Wikimedia's robot policy 403s generic browser UAs from datacenter IPs and
# requires a self-identifying bot UA with a contact URL. Use this for any
# wikipedia/wikimedia request (API and page fetch).
_BOT_UA = "Mozilla/5.0 (compatible; VeilguardBot/1.0; +https://veilguard.app/bot)"
_BOT_UA_HOSTS = ("wikipedia.org", "wikimedia.org", "wiktionary.org", "wikidata.org")


def user_agent_for(url: str) -> str:
    """Pick a polite UA per host: a compliant bot UA for Wikimedia (which 403s
    browser UAs), a normal browser UA everywhere else."""
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        host = ""
    return _BOT_UA if any(host.endswith(h) or host == h for h in _BOT_UA_HOSTS) else _USER_AGENT


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str = ""
    provider: str = ""
    #: Extracted page text, when the provider returned it (Tavily/Exa do). Lets
    #: the engine skip a fetch for that URL — the answer is built on real page
    #: content either way.
    content: str = ""


def _strip_tags(s: str) -> str:
    s = re.sub(r"<[^>]+>", "", s or "")
    return _html.unescape(s).strip()


def _cfg_key(cfg, field: str, *env_names: str) -> str:
    """A keyed provider's secret: the resolved config first, env as the floor."""
    if cfg is not None:
        try:
            v = cfg.key_for(field)
            if v:
                return v
        except Exception:
            pass
    for e in env_names:
        v = (os.environ.get(e) or "").strip()
        if v:
            return v
    return ""


def normalize_url(url: str) -> str:
    """Dedup key: drop scheme, leading www, trailing slash, fragment, tracking qs."""
    try:
        p = urlparse(url.strip())
    except Exception:
        return (url or "").strip().lower()
    netloc = p.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    path = p.path.rstrip("/")
    # Drop common tracking params so the same page from two providers dedupes.
    keep = []
    for kv in (p.query or "").split("&"):
        k = kv.split("=", 1)[0].lower()
        if k and not (k.startswith("utm_") or k in {"ref", "fbclid", "gclid", "spm"}):
            keep.append(kv)
    q = "&".join(keep)
    return f"{netloc}{path}" + (f"?{q}" if q else "")


def registrable_domain(url: str) -> str:
    """Coarse eTLD+1 for diversity capping. Handles the common two-label public
    suffixes (co.za, co.uk, com.au …) without pulling in a PSL dependency."""
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""
    if host.startswith("www."):
        host = host[4:]
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    second = parts[-2]
    if second in {"co", "com", "org", "net", "gov", "edu", "ac"} and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ── Providers ────────────────────────────────────────────────────────────


# recency → DuckDuckGo ``df`` date-filter codes.
_DDG_DF = {"day": "d", "week": "w", "month": "m", "year": "y"}

#: Whole-provider budget for the DuckDuckGo retry ladder, and the per-attempt
#: timeout inside it (see ddg_search). The shared client's 30s default is far
#: too generous for a results page.
_DDG_TOTAL_BUDGET_S = 6.0
_DDG_ATTEMPT_TIMEOUT_S = 4.0


async def ddg_search(client: httpx.AsyncClient, query: str, limit: int = 10,
                     recency: str | None = None, *, cfg=None) -> list[SearchResult]:
    """DuckDuckGo — no API key. HTML endpoint (decodes ``uddg=`` redirects) with a
    ``lite`` endpoint fallback for resilience against markup/rate-limit hiccups."""
    data = {"q": query}
    df = _DDG_DF.get((recency or "").lower())
    if df:
        data["df"] = df
    # [DDG_202_2026-07-25] From a datacenter IP DuckDuckGo intermittently answers
    # 202 (an anti-bot challenge) instead of 200, and a run where that happens on
    # both endpoints loses the ONLY keyless general-web engine — measured live:
    # a search that had returned 8 DDG sources came back Wikipedia-only minutes
    # later. So try four shapes across two hosts and two verbs before giving up;
    # they sit in different rate-limit buckets. The durable fix is a keyed engine
    # (Settings › Search), which is why an all-empty round is now reported.
    attempts = (
        ("POST", "https://html.duckduckgo.com/html/", _parse_ddg),
        ("POST", "https://lite.duckduckgo.com/lite/", _parse_ddg_lite),
        ("GET", "https://html.duckduckgo.com/html/", _parse_ddg),
        ("GET", "https://lite.duckduckgo.com/lite/", _parse_ddg_lite),
    )
    # The ladder distinguishes the two failure shapes, because they deserve
    # opposite responses:
    #   • a FAST reject (202 challenge, 403, odd markup) — another shape/host
    #     may well work, and retrying costs milliseconds. Keep going.
    #   • a TIMEOUT — the host is hanging, not rejecting. Every further attempt
    #     costs the full per-attempt timeout and none of them will land. Stop.
    # Measured 2026-07-25: without this the hang case made `search` the slowest
    # stage of every query (33.7s raw, then pinned to whatever leash was set),
    # while the four attempts bought exactly nothing.
    import time as _time
    _budget_until = _time.monotonic() + _DDG_TOTAL_BUDGET_S
    for i, (verb, url, parse) in enumerate(attempts):
        if _time.monotonic() >= _budget_until:
            break
        try:
            if verb == "POST":
                resp = await client.post(url, data=data, headers=_BROWSER_HEADERS,
                                         timeout=_DDG_ATTEMPT_TIMEOUT_S)
            else:
                resp = await client.get(url, params=data, headers=_BROWSER_HEADERS,
                                        timeout=_DDG_ATTEMPT_TIMEOUT_S)
            if resp.status_code == 200:
                res = parse(resp.text, limit)
                if res:
                    return res
        except httpx.TimeoutException:
            break  # hanging host — further shapes cost time and win nothing
        except Exception:
            pass
        if i == 1:  # brief pause before switching verb — the challenge is per-burst
            try:
                import asyncio as _a
                await _a.sleep(0.4)
            except Exception:
                pass
    return []


def _decode_ddg_href(href) -> str:
    href = str(href or "")
    if href.startswith("//"):
        href = "https:" + href
    if "duckduckgo.com/l/" in href or "uddg=" in href:
        try:
            qs = parse_qs(urlparse(href).query)
            if "uddg" in qs:
                return unquote(qs["uddg"][0])
        except Exception:
            pass
    return href


def _parse_ddg(html: str, limit: int) -> list[SearchResult]:
    out: list[SearchResult] = []
    if _BS is not None:
        try:
            soup = _BS(html, "html.parser")
            for res in soup.select("div.result, div.web-result"):
                a = res.select_one("a.result__a")
                if not a:
                    continue
                href = _decode_ddg_href(str(a.get("href") or ""))
                if not href:
                    continue
                sn = res.select_one(".result__snippet")
                out.append(SearchResult(
                    title=a.get_text(" ", strip=True),
                    url=href,
                    snippet=sn.get_text(" ", strip=True) if sn else "",
                    provider="duckduckgo",
                ))
                if len(out) >= limit:
                    break
            if out:
                return out
        except Exception:
            pass
    # Regex fallback — zip result__a (url+title) with result__snippet in order.
    links = re.findall(
        r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', html, flags=re.DOTALL
    )
    snips = re.findall(
        r'class="result__snippet"[^>]*>(.*?)</a>', html, flags=re.DOTALL
    )
    for i, (href, title) in enumerate(links[:limit]):
        url = _decode_ddg_href(_html.unescape(href))
        if not url:
            continue
        out.append(SearchResult(
            title=_strip_tags(title),
            url=url,
            snippet=_strip_tags(snips[i]) if i < len(snips) else "",
            provider="duckduckgo",
        ))
    return out


def _parse_ddg_lite(html: str, limit: int) -> list[SearchResult]:
    """Parse the lite.duckduckgo.com results table (plain <a href>, no uddg)."""
    out: list[SearchResult] = []
    for href, title in re.findall(
        r'<a[^>]+class="result-link"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        html, flags=re.DOTALL,
    ):
        url = _decode_ddg_href(_html.unescape(href))
        if not url.startswith("http"):
            continue
        out.append(SearchResult(title=_strip_tags(title), url=url,
                                snippet="", provider="duckduckgo"))
        if len(out) >= limit:
            break
    return out


#: Wikipedia is background, not coverage. Asking it for 8 hits on "2026 FIFA
#: World Cup" returns eight near-identical group-stage stubs that then crowd out
#: the primary sources in the fused list, so cap what it can contribute
#: regardless of the caller's per-provider budget.
_WIKI_MAX = 4


async def wikipedia_search(client: httpx.AsyncClient, query: str, limit: int = 5,
                           recency: str | None = None, *, cfg=None) -> list[SearchResult]:
    """Wikipedia full-text search — no API key. Good for encyclopedic grounding."""
    limit = min(limit, _WIKI_MAX)
    try:
        resp = await client.get(
            "https://en.wikipedia.org/w/api.php",
            params={
                "action": "query", "list": "search", "srsearch": query,
                "format": "json", "srlimit": limit,
            },
            headers={"User-Agent": _BOT_UA},
        )
        if resp.status_code != 200:
            return []
        items = (resp.json().get("query", {}) or {}).get("search", []) or []
    except Exception:
        return []
    out: list[SearchResult] = []
    for it in items[:limit]:
        title = it.get("title", "")
        if not title:
            continue
        out.append(SearchResult(
            title=title,
            url="https://en.wikipedia.org/wiki/" + title.replace(" ", "_"),
            snippet=_strip_tags(it.get("snippet", "")),
            provider="wikipedia",
        ))
    return out


_SEARX_TIME = {"day": "day", "week": "week", "month": "month", "year": "year"}


async def searxng_search(client: httpx.AsyncClient, query: str, limit: int = 10,
                         recency: str | None = None, *, cfg=None) -> list[SearchResult]:
    """Self-hosted SearXNG metasearch (aggregates many engines). Needs a base URL."""
    base = _cfg_key(cfg, "searxng_url", "SEARXNG_URL", "VEILGUARD_SEARXNG_URL")
    if not base:
        return []
    params = {"q": query, "format": "json"}
    tr = _SEARX_TIME.get((recency or "").lower())
    if tr:
        params["time_range"] = tr
    try:
        resp = await client.get(
            base.rstrip("/") + "/search",
            params=params,
            headers={"User-Agent": _USER_AGENT},
        )
        if resp.status_code != 200:
            return []
        results = resp.json().get("results", []) or []
    except Exception:
        return []
    out: list[SearchResult] = []
    for r in results[:limit]:
        url = r.get("url", "")
        if not url:
            continue
        out.append(SearchResult(
            title=r.get("title", "") or url,
            url=url,
            snippet=r.get("content", "") or "",
            provider="searxng",
        ))
    return out


_BRAVE_FRESH = {"day": "pd", "week": "pw", "month": "pm", "year": "py"}


async def brave_search(client: httpx.AsyncClient, query: str, limit: int = 10,
                       recency: str | None = None, *, cfg=None) -> list[SearchResult]:
    """Brave Search API — independent index, free tier ~2k/mo."""
    key = _cfg_key(cfg, "brave_api_key", "BRAVE_API_KEY", "BRAVE_SEARCH_API_KEY")
    if not key:
        return []
    params = {"q": query, "count": min(limit, 20)}
    fr = _BRAVE_FRESH.get((recency or "").lower())
    if fr:
        params["freshness"] = fr
    try:
        resp = await client.get(
            "https://api.search.brave.com/res/v1/web/search",
            params=params,
            headers={"X-Subscription-Token": key, "Accept": "application/json"},
        )
        if resp.status_code != 200:
            return []
        results = ((resp.json().get("web", {}) or {}).get("results", [])) or []
    except Exception:
        return []
    out: list[SearchResult] = []
    for r in results[:limit]:
        url = r.get("url", "")
        if not url:
            continue
        out.append(SearchResult(
            title=r.get("title", "") or url,
            url=url,
            snippet=_strip_tags(r.get("description", "") or ""),
            provider="brave",
        ))
    return out


_TAVILY_TIME = {"day": "day", "week": "week", "month": "month", "year": "year"}


async def tavily_search(client: httpx.AsyncClient, query: str, limit: int = 10,
                        recency: str | None = None, *, cfg=None) -> list[SearchResult]:
    """Tavily — a search API built for LLMs. Unusually valuable here because it
    returns **extracted page content**, not just a snippet: those results seed
    ``SearchResult.content`` so the engine can skip fetching them."""
    key = _cfg_key(cfg, "tavily_api_key", "TAVILY_API_KEY")
    if not key:
        return []
    payload = {
        "query": query,
        "max_results": min(limit, 20),
        "search_depth": "advanced",
        "include_answer": False,
        "include_raw_content": False,
    }
    tr = _TAVILY_TIME.get((recency or "").lower())
    if tr:
        payload["time_range"] = tr
    try:
        resp = await client.post(
            "https://api.tavily.com/search",
            json=payload,
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json"},
        )
        if resp.status_code != 200:
            return []
        results = resp.json().get("results", []) or []
    except Exception:
        return []
    out: list[SearchResult] = []
    for r in results[:limit]:
        url = r.get("url", "")
        if not url:
            continue
        body = str(r.get("raw_content") or r.get("content") or "")
        out.append(SearchResult(
            title=r.get("title", "") or url,
            url=url,
            snippet=body[:400],
            provider="tavily",
            content=body,
        ))
    return out


async def exa_search(client: httpx.AsyncClient, query: str, limit: int = 10,
                     recency: str | None = None, *, cfg=None) -> list[SearchResult]:
    """Exa — neural/semantic retrieval. Finds pages by MEANING, so it surfaces
    sources keyword engines miss on awkwardly-phrased questions. Also returns
    page text, which seeds ``content``."""
    key = _cfg_key(cfg, "exa_api_key", "EXA_API_KEY")
    if not key:
        return []
    payload: dict = {
        "query": query,
        "numResults": min(limit, 20),
        "type": "auto",
        "contents": {"text": {"maxCharacters": 4000}},
    }
    # Exa filters by crawl date; translate the coarse recency buckets.
    days = {"day": 1, "week": 7, "month": 31, "year": 366}.get((recency or "").lower())
    if days:
        import datetime as _dt
        start = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=days)
        payload["startPublishedDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    try:
        resp = await client.post(
            "https://api.exa.ai/search",
            json=payload,
            headers={"x-api-key": key, "Content-Type": "application/json"},
        )
        if resp.status_code != 200:
            return []
        results = resp.json().get("results", []) or []
    except Exception:
        return []
    out: list[SearchResult] = []
    for r in results[:limit]:
        url = r.get("url", "")
        if not url:
            continue
        body = str(r.get("text") or "")
        out.append(SearchResult(
            title=r.get("title", "") or url,
            url=url,
            snippet=body[:400],
            provider="exa",
            content=body,
        ))
    return out


_SERPER_TBS = {"day": "qdr:d", "week": "qdr:w", "month": "qdr:m", "year": "qdr:y"}


async def serper_search(client: httpx.AsyncClient, query: str, limit: int = 10,
                        recency: str | None = None, *, cfg=None) -> list[SearchResult]:
    """Serper — real Google SERP results over an API. The closest thing to
    "what Google actually returns", which is a genuinely different ranking from
    DuckDuckGo's Bing-derived one. Free tier ~2.5k queries."""
    key = _cfg_key(cfg, "serper_api_key", "SERPER_API_KEY", "SERPER_DEV_API_KEY")
    if not key:
        return []
    payload = {"q": query, "num": min(limit, 20)}
    tbs = _SERPER_TBS.get((recency or "").lower())
    if tbs:
        payload["tbs"] = tbs
    try:
        resp = await client.post(
            "https://google.serper.dev/search",
            json=payload,
            headers={"X-API-KEY": key, "Content-Type": "application/json"},
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
    except Exception:
        return []
    out: list[SearchResult] = []
    # answerBox / knowledgeGraph carry a direct answer with a source — worth
    # ranking first when present.
    for special in ("answerBox", "knowledgeGraph"):
        node = data.get(special)
        if isinstance(node, dict):
            link = node.get("link") or node.get("website") or ""
            body = str(node.get("answer") or node.get("snippet")
                       or node.get("description") or "")
            if link and body:
                out.append(SearchResult(
                    title=str(node.get("title") or special), url=link,
                    snippet=body, provider="serper"))
    for r in (data.get("organic") or [])[:limit]:
        url = r.get("link", "")
        if not url:
            continue
        out.append(SearchResult(
            title=r.get("title", "") or url,
            url=url,
            snippet=r.get("snippet", "") or "",
            provider="serper",
        ))
    return out[:limit]


async def mojeek_search(client: httpx.AsyncClient, query: str, limit: int = 10,
                        recency: str | None = None, *, cfg=None) -> list[SearchResult]:
    """Mojeek — no API key, no container. An **independent crawler** (its own
    index, not Google/Bing-derived), so it adds genuine ranking diversity.

    Caveat measured 2026-07-25: Mojeek 403s requests from datacenter IPs
    ("your network appears to be sending automated queries"), so on the GCP VM
    it returns nothing. Kept because it costs one parallel request and works
    from residential/dev machines; it fails soft everywhere else."""
    try:
        resp = await client.get(
            "https://www.mojeek.com/search", params={"q": query},
            headers={**_BROWSER_HEADERS, "Referer": "https://www.mojeek.com/"},
            follow_redirects=True,
        )
        if resp.status_code != 200:
            return []
    except Exception:
        return []
    out: list[SearchResult] = []
    # <h2><a class="title" href="URL">Title</a></h2><p class="s">snippet</p>
    for href, title, snip in re.findall(
        r'<a class="title"[^>]*href="([^"]+)"[^>]*>(.*?)</a></h2>\s*<p class="s">(.*?)</p>',
        resp.text, flags=re.DOTALL,
    ):
        if not href.startswith("http"):
            continue
        out.append(SearchResult(_strip_tags(title), _html.unescape(href),
                                _strip_tags(snip), "mojeek"))
        if len(out) >= limit:
            break
    if out:
        return out
    # Fallback: title anchors without the adjacent snippet.
    for href, title in re.findall(
        r'<a class="title"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', resp.text, flags=re.DOTALL,
    ):
        if href.startswith("http"):
            out.append(SearchResult(_strip_tags(title), _html.unescape(href), "", "mojeek"))
        if len(out) >= limit:
            break
    return out


ProviderFn = Callable[..., Awaitable[list[SearchResult]]]

# name → coroutine. Gemini grounding is NOT here (handled in web_answer, as it
# also produces the grounded summary + sub-query expansion).
_ALL_PROVIDERS: dict[str, ProviderFn] = {
    "duckduckgo": ddg_search,    # always on, no key (Bing-based index)
    "wikipedia": wikipedia_search,  # always on, no key (encyclopedic)
    "mojeek": mojeek_search,     # always on, no key (independent crawler)
    "searxng": searxng_search,   # keyed: base URL of your SearXNG instance
    "brave": brave_search,       # keyed: independent index
    "tavily": tavily_search,     # keyed: LLM-oriented, returns page content
    "exa": exa_search,           # keyed: neural/semantic retrieval
    "serper": serper_search,     # keyed: real Google SERP
}

#: Keyed providers → the engine-key field that switches them on, and the env
#: names that still work as a floor. MIRRORS ``SEARCH_ENGINES`` in
#: command-centre/src/lib/searchSettings.ts.
PROVIDER_KEY_FIELD: dict[str, tuple[str, tuple[str, ...]]] = {
    "searxng": ("searxng_url", ("SEARXNG_URL", "VEILGUARD_SEARXNG_URL")),
    "brave": ("brave_api_key", ("BRAVE_API_KEY", "BRAVE_SEARCH_API_KEY")),
    "tavily": ("tavily_api_key", ("TAVILY_API_KEY",)),
    "exa": ("exa_api_key", ("EXA_API_KEY",)),
    "serper": ("serper_api_key", ("SERPER_API_KEY", "SERPER_DEV_API_KEY")),
}

#: RRF weights. Not all rankings are equal: a Google SERP or an LLM-tuned index
#: earns more than an encyclopedia hit that matched on one word. Weighting is
#: still reranker-FREE — it scales each list's contribution, it does not look at
#: the query or the documents. `google` is Gemini's grounding chunk list.
PROVIDER_WEIGHT: dict[str, float] = {
    "google": 1.30,
    "serper": 1.25,
    "tavily": 1.20,
    "brave": 1.10,
    "exa": 1.05,
    "duckduckgo": 1.00,
    "searxng": 1.00,
    "mojeek": 0.85,
    "wikipedia": 0.80,
}


def enabled_providers(cfg=None) -> list[tuple[str, ProviderFn]]:
    """Providers usable right now.

    DuckDuckGo + Wikipedia + Mojeek are always on (no key, no container). A
    keyed provider switches on when its key is present — from Settings › Search
    (``cfg``) or, as a floor, its env var. An explicit ``cfg.providers[name]``
    entry overrides either way: ``False`` disables a working provider, ``True``
    keeps a keyed one in the list only if it actually has a key (an on-toggle
    can't conjure a credential).
    """
    overrides = {}
    if cfg is not None:
        try:
            overrides = dict(cfg.providers or {})
        except Exception:
            overrides = {}
    provs: list[tuple[str, ProviderFn]] = []
    for name, fn in _ALL_PROVIDERS.items():
        keyed = PROVIDER_KEY_FIELD.get(name)
        has_key = True
        if keyed:
            field, envs = keyed
            has_key = bool(_cfg_key(cfg, field, *envs))
        want = overrides.get(name)
        if want is False:
            continue
        if not has_key:
            continue
        provs.append((name, fn))
    return provs


# ── Reciprocal Rank Fusion ───────────────────────────────────────────────


def rrf_merge(ranked_lists: list[list[SearchResult]], k: int = 60,
              *, weights: Optional[dict[str, float]] = None,
              per_domain: int = 0) -> list[SearchResult]:
    """Fuse ranked provider lists into one ranking.

    RRF: ``score(url) = Σ_lists w_provider/(k + rank)``. Cheap, reranker-free,
    and naturally rewards URLs surfaced by multiple providers. Dedupe by
    normalized URL; keep the longest snippet (and any provider-supplied page
    content) and record which providers contributed (stored on ``.provider`` as
    a comma-joined string).

    ``per_domain`` > 0 applies a **soft** diversity cap: once a registrable
    domain has that many entries, further pages from it are demoted below the
    diverse set instead of being dropped. Without it a single site that ranks
    well on five engines can occupy most of the citation slots.
    """
    weights = PROVIDER_WEIGHT if weights is None else weights
    agg: dict[str, dict] = {}
    for lst in ranked_lists:
        for rank, r in enumerate(lst):
            if not r or not r.url:
                continue
            key = normalize_url(r.url)
            if not key:
                continue
            slot = agg.get(key)
            if slot is None:
                slot = {"score": 0.0,
                        "res": SearchResult(r.title, r.url, r.snippet, r.provider,
                                            getattr(r, "content", "") or ""),
                        "provs": set()}
                agg[key] = slot
            w = weights.get(r.provider, 1.0) if r.provider else 1.0
            slot["score"] += w / (k + rank + 1)
            if r.provider:
                slot["provs"].add(r.provider)
            if len(r.snippet or "") > len(slot["res"].snippet or ""):
                slot["res"].snippet = r.snippet
            rc = getattr(r, "content", "") or ""
            if len(rc) > len(slot["res"].content or ""):
                slot["res"].content = rc
            if not slot["res"].title and r.title:
                slot["res"].title = r.title
    ordered = sorted(agg.values(), key=lambda s: s["score"], reverse=True)

    primary: list[SearchResult] = []
    overflow: list[SearchResult] = []
    seen_domain: dict[str, int] = {}
    for slot in ordered:
        res = slot["res"]
        res.provider = ",".join(sorted(slot["provs"]))
        if per_domain > 0:
            d = registrable_domain(res.url)
            n = seen_domain.get(d, 0)
            seen_domain[d] = n + 1
            if d and n >= per_domain:
                overflow.append(res)
                continue
        primary.append(res)
    return primary + overflow
