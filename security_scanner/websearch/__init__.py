"""Deep web-search answer engine for the scanner (vendored from the veilguard stack).

WHAT THIS IS
    A Perplexity-style *answer engine*: one query fans out into sub-queries across
    several providers in parallel (DuckDuckGo / Wikipedia / Mojeek need no key;
    Gemini Google-Search grounding, Brave, SearXNG join when configured), results
    are fused with Reciprocal Rank Fusion, the top source pages are **actually
    fetched and read**, an iterative search -> reason-about-gaps -> search-again
    loop fills holes, passages are re-ranked with BM25, and a Gemini model
    synthesizes an answer with inline ``[n]`` citations + a real Sources list.

    ``web_answer.py`` / ``search_providers.py`` / ``search_config.py`` are vendored
    VERBATIM so they can be re-synced from upstream (see VENDORED.md). Everything
    scanner-specific lives in THIS file.

WHY A WRAPPER
    Upstream resolves its Gemini key from the Command Centre credential vault
    (an internal HTTP route + Node secret). The scanner has no Command Centre, so
    ``scanner_search_config()`` builds the config from the process env instead and
    is passed as ``config=`` — which short-circuits that lookup entirely (no
    wasted request, no timeout, no log noise).

CONFIG (scanner .env)
    GOOGLE_API_KEY      Google AI Studio (Gemini) key. Without it the engine still
                        runs — free providers + fused snippets — but there is NO
                        grounding, NO query expansion and NO synthesized answer.
                        Upstream shipped exactly that state on prod by accident for
                        weeks (see search_config.py's header), so ``deep_search()``
                        reports ``configured`` and ``key_source`` explicitly rather
                        than degrading silently.
    GEMINI_SEARCH_MODEL / GEMINI_SYNTH_MODEL   optional model overrides.
    BRAVE_API_KEY / SEARXNG_URL                optional extra providers.

USAGE (sync — the scanner's checkers are threaded, the engine is async)
    from websearch import deep_search
    res = deep_search("Has Dis-Chem had a data breach?", depth="quick")
    res["answer"]; res["sources"]; res["configured"]
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any, Optional

# The vendored modules import each other flatly (``from search_providers import
# ...``), so their own directory has to be importable.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

__all__ = ["deep_search", "deep_search_async", "scanner_search_config", "is_configured"]

DEFAULT_TIMEOUT_S = 150.0


def scanner_search_config(api_key: Optional[str] = None):
    """Env-only :class:`SearchConfig` — never contacts the Command Centre.

    Passing the result as ``web_answer(config=...)`` short-circuits upstream's
    credential-vault lookup, which would otherwise fire an HTTP request (and eat
    its timeout) on every single query in an environment that has no such service.
    """
    from search_config import SearchConfig  # local import: keeps httpx optional

    key = (api_key
           or os.environ.get("GOOGLE_API_KEY", "")
           or os.environ.get("GEMINI_API_KEY", "")).strip()
    engine_keys = {}
    for field, envs in (("brave_api_key", ("BRAVE_API_KEY", "BRAVE_SEARCH_API_KEY")),
                        ("searxng_url", ("SEARXNG_URL",))):
        for e in envs:
            v = (os.environ.get(e) or "").strip()
            if v:
                engine_keys[field] = v
                break
    return SearchConfig(
        gemini_api_key=key,
        gemini_key_source="env" if key else "none",
        search_model=(os.environ.get("GEMINI_SEARCH_MODEL", "") or "").strip(),
        synth_model=(os.environ.get("GEMINI_SYNTH_MODEL", "") or "").strip(),
        engine_keys=engine_keys,
        source="env",
    )


def is_configured() -> bool:
    """True when a Gemini key is present, i.e. grounding + synthesis will run."""
    return bool((os.environ.get("GOOGLE_API_KEY", "")
                 or os.environ.get("GEMINI_API_KEY", "")).strip())


async def deep_search_async(query: str, *, depth: str = "deep",
                            api_key: Optional[str] = None, **kwargs) -> dict[str, Any]:
    """Async form. Returns the engine's ``to_dict()`` plus scanner provenance."""
    from web_answer import web_answer

    cfg = scanner_search_config(api_key)
    res = await web_answer(query, depth=depth, config=cfg, **kwargs)
    out = res.to_dict()
    out["configured"] = bool(cfg.gemini_api_key)
    out["key_source"] = cfg.gemini_key_source
    return out


def deep_search(query: str, *, depth: str = "deep", timeout_s: float = DEFAULT_TIMEOUT_S,
                api_key: Optional[str] = None, **kwargs) -> dict[str, Any]:
    """Blocking wrapper. Never raises — failures come back as ``error``.

    Args:
        query: the question to answer.
        depth: ``"deep"`` (2 rounds, fan-out, more page reads) or ``"quick"``.
        timeout_s: hard ceiling for the whole answer.
    """
    async def _run():
        return await asyncio.wait_for(
            deep_search_async(query, depth=depth, api_key=api_key, **kwargs),
            timeout=timeout_s)

    try:
        return asyncio.run(_run())
    except Exception as e:  # incl. TimeoutError, missing httpx
        return {"query": query, "answer": "", "sources": [], "follow_ups": [],
                "search_queries": [], "providers_used": [],
                "error": f"{type(e).__name__}: {e}",
                "configured": is_configured(), "key_source": "none"}
