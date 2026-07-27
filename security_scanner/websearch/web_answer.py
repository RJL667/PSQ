"""Perplexity-parity web answer engine — deep, multi-provider (shared).

One `web_answer(query)` call → a deep, grounded, **cited** answer:

  1. Plan    — Gemini ``google_search`` grounding returns the grounded summary +
               Gemini's own query expansion (``webSearchQueries``) + a
               grounding-chunk source list. Sub-queries = {query} ∪ expansion.
  2. Search  — every enabled provider (DuckDuckGo, Wikipedia, Brave, Tavily,
               Exa, Serper, SearXNG, + the grounding chunks) is queried across
               all sub-queries in parallel.
  3. Fuse    — weighted Reciprocal Rank Fusion merges the ranked lists (no LLM
               reranker); dedupe by normalized URL; URLs found by multiple
               providers rise; a soft per-domain cap keeps one site from
               occupying every citation slot.
  4. Read    — the top sources are actually fetched & read (redirects resolved
               to real URLs), so the answer is built on page content, not
               snippets. Providers that already returned page text (Tavily, Exa)
               skip the fetch.
  5. Reason  — gap analysis proposes what is still missing, and the loop runs
               again (grounding included) on those queries.
  6. Synth   — a strict, source-only prompt writes a comprehensive answer with
               inline ``[n]`` citations + follow-up questions.

Design (see veilguard/docs/WEB_SEARCH_PERPLEXITY_PARITY_SPEC.md):

* Hard deps: stdlib + httpx. ``html2text``/``bs4`` used when importable (the
  ``web`` service) and fall back to regex (the ``sub-agents`` image).
* **Fail-soft everywhere** — provider/fetch/synth failures degrade, never raise.
* **No LLM reranker** in the hot path — weighted RRF ranks; BM25 picks the
  passages; synth attends to fetched content.
* **Configuration comes from the DB**, not the container env — see
  ``search_config.py``. [SEARCH_CONFIG_2026-07-25] The old env-only path meant
  an empty ``GOOGLE_API_KEY`` silently disabled grounding AND synthesis, and the
  tool still answered (from snippets) as if nothing were wrong. Every degraded
  run now records WHY in ``WebAnswer.diagnostics``.
* Stateless — caching is left to the caller's ``@cached`` layer.
"""

from __future__ import annotations

import asyncio
import random
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Optional

import httpx

# search_providers lives beside this module; ensure it's importable whether the
# caller put _shared on sys.path via the shim or imported us as a package.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from search_config import SearchConfig, resolve_search_config  # noqa: E402
from search_providers import (  # noqa: E402
    SearchResult,
    enabled_providers,
    normalize_url,
    registrable_domain,
    rrf_merge,
    user_agent_for,
)

# Optional richer HTML→markdown (present in the `web` service image). The
# sub-agents image ships httpx only → regex fallback.
try:  # pragma: no cover - import availability is environment-specific
    import html2text as _html2text

    _H2T = _html2text.HTML2Text()
    _H2T.ignore_links = True
    _H2T.ignore_images = True
    _H2T.body_width = 0
except Exception:  # pragma: no cover
    _H2T = None

_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models"
# Compiled defaults. Settings › Search overrides these per user/fleet; the env
# vars remain as an emergency floor (see search_config.py).
_DEFAULT_SEARCH_MODEL = "gemini-3.1-flash-lite"
# Synthesis is a single (non-grounded) generation, NOT billed per-query like
# grounding — so it pays to use a stronger model here than the cheap grounding
# tier. gemini-2.5-flash gives clearly better, better-cited prose than
# flash-lite at reasonable latency. Override in Settings › Search.
_DEFAULT_SYNTH_MODEL = "gemini-2.5-flash"

# Raw extracted text kept per page. Larger than before because passage
# reranking (_select_passages) compresses it down to the relevant windows;
# the model never sees the whole blob.
_PER_SOURCE_CHARS = 12000
# Hard byte ceiling on a single fetched page — a 40MB HTML dump would otherwise
# stall one slow source and blow the container's memory for no gain.
_MAX_FETCH_BYTES = 3_000_000
# Parallel page fetches. Enough to keep latency down, low enough to stay a
# polite citizen (and not to starve the event loop on a small container).
_FETCH_CONCURRENCY = 8
#: Per (provider, query) wall clock. The round is only as fast as its slowest
#: engine; anything past this is a hung engine, not a slow one.
_PROVIDER_TIMEOUT_S = 10.0
_RETRYABLE = {429, 500, 502, 503, 504}


@dataclass
class Source:
    """One numbered citation source."""

    n: int
    title: str
    url: str  # resolved real URL when the fetch succeeded, else the original
    snippet: str = ""
    providers: str = ""  # comma-joined providers that surfaced it
    fetched: bool = False
    content: str = ""  # extracted page text (synth input; not rendered)


@dataclass
class WebAnswer:
    """Structured result of :func:`web_answer`."""

    query: str
    answer: str = ""
    sources: list[Source] = field(default_factory=list)
    follow_ups: list[str] = field(default_factory=list)
    search_queries: list[str] = field(default_factory=list)
    providers_used: list[str] = field(default_factory=list)
    error: str = ""
    #: Human-readable notes about anything that DEGRADED this run (no Gemini
    #: key, grounding 429, synthesis failed, every provider empty). Rendered as
    #: a "Search notes" block so a silently-worse answer is never mistaken for
    #: a confident one.
    diagnostics: list[str] = field(default_factory=list)
    #: Counters for the tool's footer: how much work actually happened.
    stats: dict = field(default_factory=dict)

    def to_markdown(self, *, show_notes: bool = True) -> str:
        if self.error and not self.answer and not self.sources:
            parts = [self.error]
            if show_notes and self.diagnostics:
                parts.append("_" + "; ".join(self.diagnostics) + "_")
            return "\n\n".join(parts)
        parts: list[str] = []
        if self.answer:
            parts.append(self.answer.strip())
        if self.sources:
            lines = ["## Sources"]
            for s in self.sources:
                tag = f" _( {s.providers} )_" if s.providers else ""
                line = f"{s.n}. **{s.title or 'Untitled'}**{tag}\n   {s.url}"
                if s.snippet:
                    snip = re.sub(r"\s+", " ", s.snippet).strip()
                    if len(snip) > 280:
                        snip = snip[:280].rstrip() + "…"
                    line += f"\n   {snip}"
                lines.append(line)
            parts.append("\n".join(lines))
        if self.follow_ups:
            parts.append("## Related\n" + "\n".join(f"- {q}" for q in self.follow_ups))
        if show_notes and self.diagnostics:
            parts.append("## Search notes\n"
                         + "\n".join(f"- {d}" for d in self.diagnostics))
        out = "\n\n".join(parts).strip()
        return out or f"No results for: {self.query}"

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "answer": self.answer,
            "sources": [
                {
                    "n": s.n, "title": s.title, "url": s.url, "snippet": s.snippet,
                    "providers": s.providers, "fetched": s.fetched,
                }
                for s in self.sources
            ],
            "follow_ups": self.follow_ups,
            "search_queries": self.search_queries,
            "providers_used": self.providers_used,
            "error": self.error,
            "diagnostics": self.diagnostics,
            "stats": self.stats,
        }


# ── HTML → text ──────────────────────────────────────────────────────────


def _html_to_text(html: str) -> str:
    if _H2T is not None:
        try:
            text = _H2T.handle(html)
        except Exception:
            text = html
    else:
        text = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL | re.I)
        text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.I)
        # Drop chrome that adds tokens and no information.
        text = re.sub(r"<(nav|header|footer|aside|form|noscript)[^>]*>.*?</\1>", " ",
                      text, flags=re.DOTALL | re.I)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"&nbsp;?", " ", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    # [WEB_FETCH_WHITESPACE_2026-07-25] Tag-stripping turns every element into a
    # space, so a JS-heavy page (resbank.co.za was the example) came back as
    # hundreds of lines containing one space — pages of nothing, burning tokens
    # and pushing the real content past the caller's char cap. Drop
    # whitespace-only lines before collapsing runs.
    lines = [ln.rstrip() for ln in text.splitlines()]
    kept: list[str] = []
    for ln in lines:
        if ln.strip():
            kept.append(ln.strip() if not ln.startswith(("  ", "\t")) else ln)
        elif kept and kept[-1] != "":
            kept.append("")
    text = "\n".join(kept)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


# ── Gemini grounding (the "google" provider + summary + query expansion) ──


async def _ground(client: httpx.AsyncClient, query: str, api_key: str,
                  search_model: str, num_results: int) -> dict:
    url = f"{_ENDPOINT}/{search_model}:generateContent"
    payload = {
        "contents": [{"role": "user", "parts": [{"text": (
            f"Search Google and answer: {query}\n\n"
            f"Give a concise, factual summary grounded in the search results, "
            f"then list the {num_results} most relevant sources."
        )}]}],
        "tools": [{"google_search": {}}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024},
    }
    backoff = 0.5
    resp = None
    for attempt in range(4):
        try:
            resp = await client.post(url, headers={"x-goog-api-key": api_key}, json=payload)
        except Exception as e:
            if attempt == 3:
                return {"error": f"grounding request failed: {type(e).__name__}: {e}"}
            await asyncio.sleep(backoff + random.uniform(0, 0.25))
            backoff *= 2
            continue
        if resp.status_code not in _RETRYABLE:
            break
        if attempt == 3:
            break
        retry_after = resp.headers.get("retry-after")
        try:
            wait_s = float(retry_after) if retry_after else backoff
        except ValueError:
            wait_s = backoff
        await asyncio.sleep(min(wait_s, 4.0) + random.uniform(0, 0.25))
        backoff *= 2

    if resp is None:
        return {"error": "grounding: no response"}
    if resp.status_code == 429:
        return {"error": ("grounding hit 429 — the Gemini key is rate-limited or the "
                          "AI Studio project is out of prepayment credits "
                          "(google_search grounding needs the paid tier).")}
    if resp.status_code in (400, 401, 403):
        return {"error": (f"grounding HTTP {resp.status_code} — the Gemini key was "
                          f"rejected. Check Settings › Search. "
                          f"{resp.text[:160]}")}
    if resp.status_code != 200:
        return {"error": f"grounding HTTP {resp.status_code}: {resp.text[:200]}"}
    return _parse_grounding(resp.json())


def _parse_grounding(data: dict) -> dict:
    cands = data.get("candidates") or []
    if not cands:
        return {"summary": "", "chunks": [], "supports": [], "queries": []}
    cand = cands[0]
    summary_parts = [
        p["text"] for p in (cand.get("content", {}).get("parts") or [])
        if isinstance(p, dict) and "text" in p
    ]
    gm = cand.get("groundingMetadata", {}) or {}
    chunks = []
    for ch in gm.get("groundingChunks", []) or []:
        web = (ch.get("web") or {}) if isinstance(ch, dict) else {}
        if web.get("uri"):
            chunks.append({"uri": web.get("uri", ""), "title": web.get("title", "")})
    return {
        "summary": "".join(summary_parts).strip(),
        "chunks": chunks,
        "supports": gm.get("groundingSupports", []) or [],
        "queries": gm.get("webSearchQueries", []) or [],
    }


def _cite_grounded_summary(summary: str, supports: list, n_sources: int) -> str:
    """Rebuild inline ``[n]`` on Gemini's summary from groundingSupports (byte
    offsets). Used as the synth fallback so even the non-fetched path carries
    claim→source citations."""
    if not summary or not supports:
        return summary
    inserts: list[tuple[int, str]] = []
    for sup in supports:
        if not isinstance(sup, dict):
            continue
        seg = sup.get("segment") or {}
        end = seg.get("endIndex")
        idxs = sup.get("groundingChunkIndices") or []
        cites = [i + 1 for i in idxs if isinstance(i, int) and 0 <= i < n_sources]
        if end is None or not cites:
            continue
        marker = "".join(f"[{c}]" for c in sorted(set(cites)))
        inserts.append((int(end), marker))
    if not inserts:
        return summary
    raw = summary.encode("utf-8")
    for end, marker in sorted(inserts, key=lambda t: t[0], reverse=True):
        end = max(0, min(end, len(raw)))
        raw = raw[:end] + marker.encode("utf-8") + raw[end:]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return summary


# ── Page fetch ───────────────────────────────────────────────────────────


_GROUNDING_HOST = "vertexaisearch"


async def _real_url(client: httpx.AsyncClient, url: str) -> str:
    """One hop: ask for the redirect target WITHOUT following it.

    Gemini hands back ``vertexaisearch.cloud.google.com/grounding-api-redirect/…``
    URLs. Following them with ``HEAD`` + ``follow_redirects`` was slow (11s
    observed in prod) and often ended on another 302, so the citation displayed
    an opaque Google URL. A no-follow GET returns the ``Location`` header
    immediately. Fail-soft: returns the input unchanged.
    """
    try:
        resp = await asyncio.wait_for(
            client.get(url, headers={"User-Agent": user_agent_for(url)},
                       follow_redirects=False),
            timeout=5.0,
        )
        loc = resp.headers.get("location") or ""
        if loc.startswith("http") and _GROUNDING_HOST not in loc:
            return loc
    except Exception:
        pass
    return url


async def _resolve_grounding_chunks(client: httpx.AsyncClient,
                                    chunks: list[dict]) -> list[dict]:
    """Turn grounding redirect URIs into their real destinations BEFORE fusion.

    [GROUNDING_URLS_2026-07-25] Resolving them at render time (the old
    behaviour) meant the fusion stage saw every Google chunk as the same
    ``google.com`` domain: URL dedup could not match a page DuckDuckGo had
    already found, and the per-domain diversity cap counted them all as one
    site. Resolving up front makes dedup, the domain cap and the display all
    work on the same real URLs. One parallel batch per grounding call.
    """
    targets = [c for c in chunks if _GROUNDING_HOST in (c.get("uri") or "")]
    if not targets:
        return chunks
    try:
        resolved = await asyncio.wait_for(
            asyncio.gather(*[_real_url(client, c["uri"]) for c in targets]),
            timeout=10.0,
        )
    except (asyncio.TimeoutError, Exception):
        return chunks
    for c, url in zip(targets, resolved):
        c["uri"] = url
    return chunks


async def _resolve_redirect(client: httpx.AsyncClient, src: "Source") -> None:
    """Resolve a Gemini grounding redirect URL to its real destination for display
    (only for sources we didn't already fetch). Fail-soft — keeps the redirect."""
    if src.fetched or "vertexaisearch" not in src.url:
        return
    try:
        resp = await asyncio.wait_for(
            client.head(src.url, headers={"User-Agent": user_agent_for(src.url)},
                        follow_redirects=True),
            timeout=6.0,
        )
        final = str(resp.url)
        if final and "vertexaisearch" not in final:
            src.url = final
    except Exception:
        return


#: Extensions we cannot turn into text here (no PDF/office extractor in the
#: dependency-light shared core). The source is still cited — we just don't
#: pretend to have read it.
_UNREADABLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|zip|csv|epub)(\?|#|$)", re.I)

#: Hosts that serve a JavaScript shell with no article text. Fetching one burns
#: a slot and yields nothing.
#:
#: [FETCH_BUDGET_2026-07-25] Measured: "What are the main new features in Python
#: 3.14?" ranked docs.python.org/3/whatsnew/3.14.html 4th, but quick mode reads
#: only the top 3 — and two of those were YouTube watch pages. The engine had
#: the authoritative source in hand and answered "the sources do not detail the
#: main new features". These hosts are DEMOTED for the READ stage only: they
#: stay in the fused list and stay citable, they just go last in the queue for
#: the fetch budget.
_LOW_YIELD_HOSTS = (
    "youtube.com", "youtu.be", "vimeo.com", "tiktok.com", "twitter.com", "x.com",
    "facebook.com", "instagram.com", "linkedin.com", "pinterest.com",
    "spotify.com", "soundcloud.com",
)


def _low_yield(url: str) -> bool:
    d = registrable_domain(url)
    return any(d == h or d.endswith("." + h) for h in _LOW_YIELD_HOSTS)


async def _fetch_one(client: httpx.AsyncClient, url: str,
                     sem: asyncio.Semaphore) -> Optional[dict]:
    """Fetch + extract one URL. Returns {final_url, content, snippet} or None.

    Bounded three ways so one pathological page can't hold the round open or
    balloon memory: a shared concurrency semaphore, a 12s wall clock, and a byte
    ceiling on the body we decode and run the HTML→text pass over.
    """
    if _UNREADABLE_EXT.search(url or ""):
        return None
    try:
        async with sem:
            resp = await asyncio.wait_for(
                client.get(url, headers={"User-Agent": user_agent_for(url)},
                           follow_redirects=True),
                timeout=12.0,
            )
        if resp.status_code != 200:
            return None
        ctype = resp.headers.get("content-type", "")
        if ctype and "html" not in ctype and "text/plain" not in ctype:
            return None
        raw = resp.content[:_MAX_FETCH_BYTES]
        try:
            body = raw.decode(resp.encoding or "utf-8", errors="replace")
        except Exception:
            body = resp.text[: _MAX_FETCH_BYTES // 2]
        text = _html_to_text(body)
        if not text or len(text) < 80:
            return None
        return {"final_url": str(resp.url) or url,
                "content": text[:_PER_SOURCE_CHARS],
                "snippet": text[:300]}
    except Exception:
        return None


# ── Passage reranking (lexical — no model in the hot path) ────────────────

_STOP = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "is", "are",
    "was", "were", "be", "by", "with", "as", "at", "it", "its", "this", "that",
    "what", "which", "who", "whom", "how", "why", "when", "where", "do", "does",
    "did", "has", "have", "had", "i", "you", "we", "they", "he", "she", "from",
    "about", "into", "over", "than", "then", "so", "if", "but", "not", "can",
}


def _tokenize(s: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", (s or "").lower())


def _select_passages(query_text: str, sources: list["Source"], *,
                     max_passages: int = 14, win: int = 700, stride: int = 550,
                     per_source: int = 3, k1: float = 1.5, b: float = 0.75
                     ) -> list[tuple[int, str]]:
    """Rank ~paragraph windows of the fetched pages by **BM25** relevance to the
    query and return [(source_n, passage)] so the synth model reads the *relevant*
    sections, not each page's first N chars.

    BM25 over the windowed passages as the corpus (IDF rewards rare query terms,
    length-normalised) — a real ranking function, still pure-Python with no model
    in the hot path (honours the no-LLM-reranker rule)."""
    import math

    qterms = {t for t in _tokenize(query_text) if len(t) > 2 and t not in _STOP}
    if not qterms:
        return []
    # 1. Build the passage corpus (windows of each fetched page).
    passages: list[tuple[int, str, list[str]]] = []  # (source_n, text, tokens)
    for s in sources:
        content = s.content
        if not content:
            continue
        for start in range(0, len(content), stride):
            chunk = content[start:start + win]
            if len(chunk) < 80:
                continue
            toks = _tokenize(chunk)
            if toks:
                passages.append((s.n, chunk.strip(), toks))
    if not passages:
        return []
    # 2. IDF over the corpus + average length.
    N = len(passages)
    df: dict[str, int] = {}
    for _n, _t, toks in passages:
        for term in set(toks):
            if term in qterms:
                df[term] = df.get(term, 0) + 1
    idf = {t: math.log(1 + (N - df.get(t, 0) + 0.5) / (df.get(t, 0) + 0.5)) for t in qterms}
    avgdl = sum(len(toks) for _n, _t, toks in passages) / N
    # 3. Score each passage with BM25.
    scored: list[tuple[float, int, str]] = []
    for n, text, toks in passages:
        dl = len(toks)
        tf: dict[str, int] = {}
        for term in toks:
            if term in qterms:
                tf[term] = tf.get(term, 0) + 1
        if not tf:
            continue
        score = 0.0
        for term, f in tf.items():
            denom = f + k1 * (1 - b + b * dl / (avgdl or 1))
            score += idf.get(term, 0.0) * (f * (k1 + 1)) / (denom or 1)
        if score > 0:
            scored.append((score, n, text))
    scored.sort(key=lambda x: x[0], reverse=True)
    # 4. Take the top, capping passages per source for diversity.
    out: list[tuple[int, str]] = []
    per: dict[int, int] = {}
    for _score, n, chunk in scored:
        if per.get(n, 0) >= per_source:
            continue
        per[n] = per.get(n, 0) + 1
        out.append((n, chunk))
        if len(out) >= max_passages:
            break
    return out


# ── Recency + citation hygiene ───────────────────────────────────────────


def _detect_recency(query: str) -> Optional[str]:
    ql = (query or "").lower()
    if re.search(r"\b(today|breaking|right now|past day|last 24)\b", ql):
        return "week"
    if re.search(r"\b(latest|current|recent|currently|now|this (week|month|year)|"
                 r"20(2[6-9]|3\d)|up[- ]?to[- ]?date|newest|just announced)\b", ql):
        return "month"
    return None


def _validate_citations(answer: str, n_sources: int) -> str:
    """Drop any ``[n]`` whose n is out of range (synth can hallucinate numbers),
    then tidy the whitespace the removal leaves behind."""
    out = re.sub(
        r"\[(\d+)\]",
        lambda m: m.group(0) if 1 <= int(m.group(1)) <= n_sources else "",
        answer,
    )
    out = re.sub(r" +([.,;:])", r"\1", out)
    return re.sub(r"[ \t]{2,}", " ", out)


# ── Gap analysis (the agentic "search again" step) ───────────────────────


async def _gemini_text(client: httpx.AsyncClient, prompt: str, api_key: str,
                       model: str, max_tokens: int = 2048, temp: float = 0.3
                       ) -> tuple[str, str]:
    """Return (text, error). Retries the transient statuses; an error string is
    returned rather than raised so callers can record WHY synthesis was empty."""
    url = f"{_ENDPOINT}/{model}:generateContent"
    payload = {"contents": [{"role": "user", "parts": [{"text": prompt}]}],
               "generationConfig": {"temperature": temp, "maxOutputTokens": max_tokens}}
    backoff = 0.6
    last = "no attempt"
    for attempt in range(3):
        try:
            resp = await client.post(url, headers={"x-goog-api-key": api_key},
                                     json=payload)
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
            await asyncio.sleep(backoff)
            backoff *= 2
            continue
        if resp.status_code in _RETRYABLE and attempt < 2:
            last = f"HTTP {resp.status_code}"
            await asyncio.sleep(backoff)
            backoff *= 2
            continue
        if resp.status_code != 200:
            return "", f"{model} HTTP {resp.status_code}: {resp.text[:160]}"
        try:
            cands = resp.json().get("candidates") or []
        except Exception as e:
            return "", f"{model} bad JSON: {e}"
        if not cands:
            return "", f"{model} returned no candidates"
        text = "".join(
            p["text"] for p in (cands[0].get("content", {}).get("parts") or [])
            if isinstance(p, dict) and "text" in p
        ).strip()
        if not text:
            return "", f"{model} returned empty text " \
                       f"(finishReason={cands[0].get('finishReason')})"
        return text, ""
    return "", f"{model} failed after retries ({last})"


async def _gap_analysis(client: httpx.AsyncClient, query: str, evidence: str,
                        api_key: str, model: str, max_gaps: int = 3) -> list[str]:
    """Read the evidence so far and propose NEW search queries that fill the most
    important remaining gaps — the iterative "search → reason → search again" step.
    Returns [] when the question already looks well covered."""
    prompt = (
        f"Research question: {query}\n\n"
        "Notes gathered so far from web sources:\n"
        f"{evidence[:6000]}\n\n"
        f"List up to {max_gaps} SPECIFIC web-search queries that would fill the most "
        "important REMAINING gaps needed to fully and accurately answer the question "
        "(e.g. missing facts, other viewpoints, more recent data, verification of a "
        "claim). Make each query self-contained and distinct from the notes above. "
        "If the question is already well covered, output exactly: NONE\n"
        "Output one query per line, no numbering, no commentary."
    )
    text, _err = await _gemini_text(client, prompt, api_key, model,
                                    max_tokens=256, temp=0.4)
    if not text or "NONE" in text.upper().split():
        return []
    gaps: list[str] = []
    for line in text.splitlines():
        line = re.sub(r"^[-*\d.)\s]+", "", line.strip()).strip().strip('"')
        if line and line.upper() != "NONE" and len(line) > 3:
            gaps.append(line)
    return gaps[:max_gaps]


# ── Synthesis ────────────────────────────────────────────────────────────


async def _synthesize(client: httpx.AsyncClient, query: str, sources: list[Source],
                      passages: list[tuple[int, str]], api_key: str,
                      synth_model: str, *, recency: Optional[str] = None
                      ) -> tuple[str, list[str], str]:
    by_src: dict[int, list[str]] = {}
    for n, chunk in passages:
        by_src.setdefault(n, []).append(chunk)
    blocks = []
    for s in sources:
        if s.n in by_src:
            body = "\n…\n".join(by_src[s.n])
        elif s.content:
            body = s.content[:1800]
        elif s.snippet:
            body = s.snippet
        else:
            continue
        blocks.append(f"[{s.n}] {s.title or s.url}\nURL: {s.url}\n{body[:2200]}")
    if not blocks:
        return "", [], "no readable source content to synthesize from"
    today = date.today().isoformat()
    freshness = (
        "- This question is time-sensitive. Lead with the most recent figure or "
        "event and give its date; say explicitly if the newest source is stale.\n"
        if recency else ""
    )
    prompt = (
        f"Today's date is {today}.\n"
        f"Question: {query}\n\n"
        "You are a research answer engine. Using ONLY the numbered sources below, "
        "write a comprehensive, well-structured answer to the question. "
        "Requirements:\n"
        "- Answer the question directly in the FIRST sentence. No preamble, no "
        "restating the question, no 'based on the sources'.\n"
        "- Cite sources inline with [n] immediately after each claim they support "
        "(e.g. \"X happened in 2024 [2][5].\"). Use only the numbers given below; "
        "never invent a source. Every factual sentence needs at least one citation.\n"
        "- Be specific and factual; prefer concrete numbers, names, dates. Never "
        "round away a figure the source states precisely.\n"
        f"{freshness}"
        "- Use short paragraphs and markdown headers/bullets where it helps. Do "
        "not pad: if the answer is two sentences, write two sentences.\n"
        "- If the sources disagree, say so and give both figures with their "
        "citations. If they do not answer the question, say exactly what is "
        "missing rather than guessing.\n"
        "- After the answer, output a line exactly '### Related' followed by 3-5 "
        "follow-up questions as '- ' bullets.\n\n"
        "Sources:\n" + "\n\n".join(blocks)
    )
    text, err = await _gemini_text(client, prompt, api_key, synth_model,
                                   max_tokens=2048, temp=0.3)
    if not text:
        return "", [], err
    ans, fus = _split_answer_followups(text)
    return ans, fus, ""


_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'“(])")


def _extractive_answer(query: str, sources: list[Source],
                       passages: list[tuple[int, str]], *, max_points: int = 6) -> str:
    """A cited digest built with NO model, from the passages already ranked.

    [SEARCH_DEGRADED_2026-07-25] Observed in prod: the one Gemini key in the
    stack ran out of prepaid credits, so grounding AND synthesis 429'd and
    ``web_search`` returned an EMPTY answer above a list of links — the worst
    possible output, because it looks like search found nothing. The pages had
    in fact been fetched and ranked; only the writer was missing.

    So when the LLM cannot write, quote instead: score sentences inside the
    top BM25 passages by query-term overlap, keep the best one per source, and
    emit them as cited bullets. Deterministic, free, honest — every line is a
    verbatim sentence from a numbered source.
    """
    qterms = {t for t in _tokenize(query) if len(t) > 2 and t not in _STOP}
    if not qterms or not passages:
        return ""
    titles = {s.n: (s.title or s.url) for s in sources}
    best: dict[int, tuple[float, str]] = {}
    # Source rank is information the sentence scorer must not throw away: on
    # "who won the 2026 World Cup" the 1986/1990/1994 final pages match just as
    # many query terms as the 2026 one, and without this the digest led with a
    # 1986 match report. Decay by rank so the fused list's own ordering wins ties.
    def _rank_weight(n: int) -> float:
        return 1.0 / (1.0 + 0.35 * max(0, n - 1))

    # Weight each query term by how RARE it is across the fetched pages. Raw hit
    # count treats "2026" and "final" as equally informative, which is how the
    # 2026 World Cup digest ended up quoting a 2018 friendly: that sentence had
    # four common terms and none of the discriminating one.
    import math
    corpus = [(s.content or "").lower() for s in sources if s.content]
    ndoc = max(1, len(corpus))
    tw = {
        t: math.log(1 + ndoc / (1 + sum(1 for c in corpus if t in c)))
        for t in qterms
    }
    tw_total = sum(tw.values()) or 1.0
    for n, chunk in passages:
        for sent in _SENT_SPLIT.split(chunk):
            sent = re.sub(r"\s+", " ", sent).strip(" -•\t")
            # Floor at 40 chars: the sentence that answers a question is often
            # short ("The repo rate is unchanged at 7.00%."), but anything
            # shorter is a nav crumb or a heading fragment.
            if not (40 <= len(sent) <= 400):
                continue
            toks = set(_tokenize(sent))
            hit_terms = qterms & toks
            if not hit_terms:
                continue
            # Rarity-weighted coverage of the question, with a nudge for
            # sentences carrying a concrete figure or date — those are what the
            # question usually wants.
            score = sum(tw[t] for t in hit_terms) / tw_total
            if re.search(r"\d", sent):
                score += 0.15
            score *= _rank_weight(n)
            if score > best.get(n, (0.0, ""))[0]:
                best[n] = (score, sent)
    if not best:
        return ""
    ranked = sorted(best.items(), key=lambda kv: kv[1][0], reverse=True)[:max_points]
    # Present in source order once selected — the reader follows [1],[2],[3].
    ranked.sort(key=lambda kv: kv[0])
    lines = [
        "_No answer model was available for this search, so the most relevant "
        "sentence from each source is quoted verbatim below._",
        "",
    ]
    seen: set[str] = set()
    for n, (_score, sent) in ranked:
        fingerprint = " ".join(_tokenize(sent)[:12])
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        lines.append(f"- **{titles.get(n, f'Source {n}')}** — {sent} [{n}]")
    return "\n".join(lines) if len(lines) > 2 else ""


#: Leading interrogative scaffolding that helps a model and hurts a keyword
#: engine. Stripped REPEATEDLY ("what is the current X" → "current X").
_QUESTION_LEAD = re.compile(
    r"^(tell me|give me|show me|please|what|which|who|whom|whose|when|where|why|"
    r"how|is|are|was|were|do|does|did|can|could|should|would|will|find|the|a|an)"
    r"\b[\s,]*", re.I,
)


def _fallback_subqueries(query: str) -> list[str]:
    """Sub-queries to fan out with when Gemini can't expand the question.

    Deep mode used to collapse to a SINGLE query whenever grounding was
    unavailable, because expansion was the model's job. Keyword engines
    (DuckDuckGo, Serper, Brave) rank a noun-phrase form better than a full
    sentence, so strip the interrogative scaffolding and the trailing '?'.
    Returns [] when that leaves nothing meaningfully different — a fan-out slot
    spent on the same query is a wasted request.
    """
    q = (query or "").strip().rstrip("?.! ")
    stripped = q
    while True:
        nxt = _QUESTION_LEAD.sub("", stripped, count=1).strip()
        if nxt == stripped or not nxt:
            break
        stripped = nxt
    if len(stripped) < 8 or len(stripped.split()) < 2:
        return []
    if stripped.lower() == q.lower():
        return []
    return [stripped]


def _split_answer_followups(text: str) -> tuple[str, list[str]]:
    if not text:
        return "", []
    m = re.split(r"\n#{1,6}\s*Related\s*\n", text, maxsplit=1, flags=re.I)
    answer = m[0].strip()
    follow_ups: list[str] = []
    if len(m) > 1:
        for line in m[1].splitlines():
            line = re.sub(r"^[-*\d.)\s]+", "", line.strip()).strip()
            if line:
                follow_ups.append(line)
    return answer, follow_ups[:5]


# ── Public entry point ───────────────────────────────────────────────────


async def web_answer(
    query: str,
    *,
    depth: str = "deep",
    rounds: Optional[int] = None,
    num_results: int = 8,
    fetch_sources: Optional[int] = None,
    synth: bool = True,
    recency: Optional[str] = None,
    max_subqueries: int = 3,
    per_provider: int = 8,
    deadline_s: Optional[float] = None,
    api_key: Optional[str] = None,
    search_model: Optional[str] = None,
    synth_model: Optional[str] = None,
    user_id: str = "",
    config: Optional[SearchConfig] = None,
) -> WebAnswer:
    """Deep, multi-provider, **iterative** web answer (Perplexity-style). Never raises.

    Runs ``rounds`` of: multi-provider search (Gemini grounding included) → fetch
    & read top pages → reason about what's still missing → search again. Then
    ranks the *relevant passages* of the read pages (lexical, no model) and
    synthesizes a cited answer.

    Args:
        query: the user's question.
        depth: ``"deep"`` (iterative, fan-out, more sources) / ``"quick"``
            (1 round, single query, fewer fetches).
        rounds: override the search→reason→search iteration count
            (default 2 deep / 1 quick). Needs a Gemini key for the gap step.
        num_results: how many fused sources to keep/cite (1-20).
        fetch_sources: top sources to fetch & read per round (default 6 deep/3 quick).
        synth: synthesize a cited answer (else grounded summary / snippets).
        recency: ``day``/``week``/``month``/``year`` time-filter for providers;
            auto-detected from the query ("latest", "2026", …) when None.
        max_subqueries: cap on Gemini-expanded sub-queries seeded in round 1.
        per_provider: results requested per provider per sub-query.
        deadline_s: overall wall-clock budget (default 60 deep / 30 quick). The
            loop stops starting new work past it and synthesis gets whatever is
            left (floor 12s), so a slow round can no longer run away — a "quick"
            search was measured at 135s before this existed. Never a hard abort:
            the answer is produced from what has been gathered.
        user_id: the caller (email or uuid) whose Settings › Search and vault
            Gemini key this run should use.
        config: a pre-resolved :class:`SearchConfig` (skips the lookup).
    """
    query = (query or "").strip()
    result = WebAnswer(query=query)
    if not query:
        result.error = "Error: empty query"
        return result
    t_start = time.monotonic()
    timings: dict[str, float] = {"ground": 0.0, "search": 0.0, "fetch": 0.0,
                                 "gap": 0.0, "synth": 0.0}

    def _elapsed() -> float:
        return time.monotonic() - t_start

    # Configuration: DB (Settings › Search) → env floor → compiled defaults.
    cfg = config if config is not None else await resolve_search_config(user_id)
    if cfg.error:
        result.diagnostics.append(cfg.error)

    deep = (depth or cfg.depth or "deep") != "quick"
    if rounds is None:
        rounds = cfg.rounds if cfg.rounds is not None else (2 if deep else 1)
    rounds = max(1, min(int(rounds), 4))
    if cfg.num_results is not None and num_results == 8:
        num_results = cfg.num_results
    num_results = max(1, min(int(num_results), 20))
    if fetch_sources is None:
        fetch_sources = (cfg.fetch_sources if cfg.fetch_sources is not None
                         else (6 if deep else 3))
    fetch_sources = max(0, min(int(fetch_sources), num_results))
    if deadline_s is None:
        deadline_s = 60.0 if deep else 30.0
    deadline_s = max(15.0, float(deadline_s))

    def _left() -> float:
        return deadline_s - _elapsed()

    if recency is None:
        recency = _detect_recency(query)

    key = (api_key or cfg.gemini_api_key or "").strip()
    search_model = search_model or cfg.search_model or _DEFAULT_SEARCH_MODEL
    synth_model = synth_model or cfg.synth_model or _DEFAULT_SYNTH_MODEL

    providers = enabled_providers(cfg)
    if not key:
        result.diagnostics.append(
            "No Gemini key resolved — running WITHOUT Google grounding, query "
            "expansion or answer synthesis (fused snippets only). Link a Gemini "
            "key under Settings › Models, or pin a credential owner in "
            "Settings › Search."
        )
    if not key and not providers:
        result.error = (
            "Error: web search is not configured — no Gemini key and no search "
            "engine enabled. Set them in Settings › Search."
        )
        return result

    async def _run(pfn, q):
        # Hard leash per (provider, query). The fan-out is only as fast as its
        # slowest member, and one hanging engine used to hold the whole round
        # open for the client's 30s default. Fail-soft: a timeout is just [].
        try:
            return await asyncio.wait_for(
                pfn(client, q, per_provider, recency, cfg=cfg),
                timeout=_PROVIDER_TIMEOUT_S,
            )
        except Exception:
            return []

    all_ranked: list[list[SearchResult]] = []      # every provider list, all rounds
    fetched: dict[str, dict] = {}                    # norm_url -> {final_url,content,snippet}
    prefetched: dict[str, str] = {}                  # norm_url -> provider-supplied text
    seen_fetch: set[str] = set()                     # norm_urls already attempted
    executed: set[str] = set()                       # queries already run (lowercased)
    engines_with_hits: set[str] = set()              # engines that returned >0 rows
    grounded_summary = ""
    grounded_supports: list = []
    grounding_err = ""
    ground_calls = 0
    sem = asyncio.Semaphore(_FETCH_CONCURRENCY)

    async def _ground_into(q: str) -> None:
        """Run one grounding call for `q` and fold its chunks into the pool."""
        nonlocal grounded_summary, grounded_supports, grounding_err, ground_calls
        ground_calls += 1
        _t = time.monotonic()
        grounded = await _ground(client, q, key, search_model, num_results)
        timings["ground"] += time.monotonic() - _t
        err = grounded.get("error") or ""
        if err:
            grounding_err = err
            return
        if not grounded_summary:
            grounded_summary = grounded.get("summary") or ""
            grounded_supports = grounded.get("supports") or []
        g_chunks = await _resolve_grounding_chunks(client, grounded.get("chunks") or [])
        if g_chunks:
            all_ranked.append([
                SearchResult(title=c.get("title", "") or "Untitled",
                             url=c.get("uri", ""), provider="google")
                for c in g_chunks if c.get("uri")
            ])
        if deep:
            for eq in (grounded.get("queries") or [])[:max_subqueries]:
                eq = (eq or "").strip()
                if eq and eq.lower() not in executed and eq not in pending:
                    pending.append(eq)

    async with httpx.AsyncClient(timeout=30) as client:
        # Round 1 seed: Gemini grounding (summary + query expansion + chunks).
        pending: list[str] = [query]
        if key:
            await _ground_into(query)
            if grounding_err:
                result.diagnostics.append(grounding_err)
        # No LLM expansion available (no key, or grounding failed) — fan out on
        # a keyword form of the question rather than collapsing deep mode to a
        # single query, which is what used to happen.
        if deep and len(pending) == 1:
            pending.extend(_fallback_subqueries(query))

        # Iterative loop: search → fetch → reason about gaps → search again.
        for rnd in range(rounds):
            pending = [q for q in pending if q.lower() not in executed][: 1 + max_subqueries]
            if not pending:
                break
            # Never START a round we haven't the budget to finish and still
            # synthesize. Round 1 always runs — an answer needs some evidence.
            if rnd > 0 and _left() < 20:
                result.diagnostics.append(
                    f"Stopped after {rnd} round(s): the {deadline_s:.0f}s search "
                    "budget was nearly spent. The answer uses what was gathered."
                )
                break
            for q in pending:
                executed.add(q.lower())
            result.search_queries.extend(pending)

            _t = time.monotonic()
            round_lists = await asyncio.gather(
                *[_run(pfn, q) for (name, pfn) in providers for q in pending]
            )
            timings["search"] += time.monotonic() - _t
            # Which engines actually produced anything. A keyless engine that
            # gets bot-challenged (DuckDuckGo 202, Mojeek 403 from a datacenter
            # IP) otherwise fails silently and the whole search quietly narrows
            # to Wikipedia. The gather above is provider-major, so the names
            # flatten in the same order.
            flat_names = [name for (name, _p) in providers for _q in pending]
            for pname, lst in zip(flat_names, round_lists):
                if lst:
                    engines_with_hits.add(pname)
            for lst in round_lists:
                if lst:
                    all_ranked.append(lst)
                    # Providers that return page text (Tavily/Exa) save us a fetch.
                    for r in lst:
                        body = getattr(r, "content", "") or ""
                        nk = normalize_url(r.url)
                        if nk and len(body) > 400 and len(body) > len(prefetched.get(nk, "")):
                            prefetched[nk] = body[:_PER_SOURCE_CHARS]

            # Fuse everything so far; fetch the best not-yet-read sources.
            fused_now = rrf_merge(all_ranked, per_domain=2)
            # Two passes so the fetch budget goes to pages that can actually
            # yield text: JS-shell hosts (YouTube et al.) queue behind everything
            # else rather than consuming the top slots by rank alone.
            to_read: list[tuple[str, str]] = []
            deferred: list[tuple[str, str]] = []
            for r in fused_now:
                nk = normalize_url(r.url)
                if not nk or nk in seen_fetch:
                    continue
                seen_fetch.add(nk)
                if nk in prefetched:      # already have the text — don't refetch
                    fetched[nk] = {"final_url": r.url,
                                   "content": prefetched[nk],
                                   "snippet": prefetched[nk][:300]}
                    continue
                (deferred if _low_yield(r.url) else to_read).append((nk, r.url))
                if len(to_read) >= fetch_sources:
                    break
            if len(to_read) < fetch_sources:
                to_read.extend(deferred[: fetch_sources - len(to_read)])
            if to_read:
                _t = time.monotonic()
                # Cap the whole batch, not just each fetch: _fetch_one's 12s
                # timeout is per URL, so a slow set could still stack up.
                try:
                    datas = await asyncio.wait_for(
                        asyncio.gather(
                            *[_fetch_one(client, u, sem) for _, u in to_read]
                        ),
                        timeout=max(8.0, min(20.0, _left() - 10)),
                    )
                except asyncio.TimeoutError:
                    datas = [None] * len(to_read)
                timings["fetch"] += time.monotonic() - _t
                for (nk, _u), data in zip(to_read, datas):
                    if data:
                        fetched[nk] = data

            # Decide next round's queries (the agentic "search again" step).
            if rnd < rounds - 1 and key and synth and _left() > 25:
                evidence = "\n\n".join(
                    (d.get("content") or "")[:800] for d in fetched.values()
                )[:6000] or grounded_summary
                # Gap-analysis is planning, not prose — keep it on the cheap model.
                _t = time.monotonic()
                gaps = await _gap_analysis(client, query, evidence, key, search_model)
                timings["gap"] += time.monotonic() - _t
                pending = [g for g in gaps if g.lower() not in executed]
                # Give the next round Google's index too, not just the other
                # engines: grounding is the strongest single provider and used
                # to run only once, on the original query.
                if pending and not grounding_err:
                    await _ground_into(pending[0])
            else:
                pending = []

        if not all_ranked:
            result.error = (f"Web search error: {grounding_err}" if grounding_err
                            else f"No results for: {query}")
            if providers:
                result.diagnostics.append(
                    "Every enabled engine returned 0 results "
                    f"({', '.join(n for n, _ in providers)}) — outbound network "
                    "blocked, or all engines rate-limited this IP."
                )
            return result

        # Final fuse → numbered sources, merging in fetched page content.
        fused = rrf_merge(all_ranked, per_domain=2)
        provs_seen: set[str] = set()
        for r in fused[:num_results]:
            nk = normalize_url(r.url)
            src = Source(n=len(result.sources) + 1, title=r.title, url=r.url,
                         snippet=r.snippet, providers=r.provider)
            data = fetched.get(nk)
            if data:
                src.url = data.get("final_url") or src.url
                src.content = data.get("content") or ""
                if not src.snippet:
                    src.snippet = data.get("snippet") or ""
                src.fetched = True
            elif getattr(r, "content", ""):
                src.content = r.content[:_PER_SOURCE_CHARS]
                src.fetched = True
            result.sources.append(src)
            for p in (r.provider or "").split(","):
                if p:
                    provs_seen.add(p)
        result.providers_used = sorted(provs_seen)
        result.search_queries = list(dict.fromkeys(result.search_queries))

        # Clean up display URLs: resolve any leftover Gemini grounding redirects
        # on sources we didn't fetch (so every source shows a real URL).
        unresolved = [s for s in result.sources
                      if not s.fetched and "vertexaisearch" in s.url]
        if unresolved:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*[_resolve_redirect(client, s) for s in unresolved]),
                    timeout=8.0,
                )
            except asyncio.TimeoutError:
                pass

        read_n = sum(1 for s in result.sources if s.fetched)
        result.stats = {
            "queries": len(result.search_queries),
            "engines": len(result.providers_used),
            "candidates": len({normalize_url(r.url) for lst in all_ranked for r in lst}),
            "sources": len(result.sources),
            "read": read_n,
            "domains": len({registrable_domain(s.url) for s in result.sources}),
            "grounding_calls": ground_calls,
            "rounds": rounds,
            "config": cfg.source,
            "gemini_key_source": cfg.gemini_key_source,
        }

        # Rank passages against the ORIGINAL question plus the first couple of
        # expansions — all of them would dilute the term set with gap-query
        # vocabulary that is, by definition, off the main topic.
        focus = " ".join([query] + result.search_queries[1:3])
        passages = _select_passages(focus, result.sources)

        # Synthesize over the *relevant passages* of the read pages.
        if synth and key:
            _t = time.monotonic()
            try:
                answer, follow_ups, synth_err = await asyncio.wait_for(
                    _synthesize(client, query, result.sources, passages, key,
                                synth_model, recency=recency),
                    timeout=max(12.0, _left()),
                )
            except asyncio.TimeoutError:
                answer, follow_ups = "", []
                synth_err = (f"{synth_model} did not answer within the remaining "
                             f"{deadline_s:.0f}s search budget")
            timings["synth"] += time.monotonic() - _t
            if answer:
                result.answer = _validate_citations(answer, len(result.sources))
                result.follow_ups = follow_ups
            else:
                if synth_err:
                    result.diagnostics.append(f"Synthesis failed: {synth_err}")
                result.answer = _cite_grounded_summary(
                    grounded_summary, grounded_supports, len(result.sources)
                )
        else:
            result.answer = _cite_grounded_summary(
                grounded_summary, grounded_supports, len(result.sources)
            )

        # Last line of defence: never hand back a bare list of links. If no
        # model wrote an answer (no key, 429, synth error), quote the sources.
        if not result.answer.strip():
            result.answer = _extractive_answer(query, result.sources, passages)
            if result.answer:
                result.stats["answer_mode"] = "extractive"
        elif result.stats:
            result.stats["answer_mode"] = "synthesized"

        # Per-stage wall clock, stamped AFTER synthesis — "search feels slow" is
        # otherwise unfalsifiable, and a 135s quick search turned out to be one
        # runaway stage rather than the engine being generally heavy.
        timings["total"] = _elapsed()
        result.stats["ms"] = {k: round(v * 1000) for k, v in timings.items()}

        if read_n == 0 and result.sources:
            result.diagnostics.append(
                "No source page could be fetched — the answer rests on search "
                "snippets only."
            )
        # Name the engines that were switched on but produced nothing. Without
        # this a bot-challenged DuckDuckGo silently narrows the whole search to
        # Wikipedia and the result just looks thin for no visible reason.
        silent = [n for n, _ in providers if n not in engines_with_hits]
        if silent and len(silent) == len(providers):
            result.diagnostics.append(
                f"Every enabled engine returned nothing ({', '.join(silent)}); "
                "only Google grounding contributed."
            )
        elif silent:
            hint = (" Add a Brave, Serper or Tavily key in Settings › Search for "
                    "coverage that does not depend on scraping."
                    if not any(n in engines_with_hits
                               for n in ("brave", "serper", "tavily", "exa", "searxng"))
                    else "")
            result.diagnostics.append(
                f"No results from: {', '.join(silent)} (rate-limited or "
                f"bot-challenged from this host).{hint}"
            )

    return result
