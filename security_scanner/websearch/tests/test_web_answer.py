"""Tests for the deep multi-provider web answer engine — fully mocked (no live
network). Runnable as a script (`python test_web_answer.py`) or via pytest.
"""

import asyncio
import re
import sys
import time
from pathlib import Path

import httpx

# _shared on path (tests/ -> _shared/).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import web_answer as wa  # noqa: E402
import search_config as sc  # noqa: E402
import search_providers as sp  # noqa: E402
from search_providers import (  # noqa: E402
    SearchResult,
    normalize_url,
    registrable_domain,
    rrf_merge,
    _parse_ddg,
)


def _isolate_config():
    """Force the ENV path of search_config: no internal secret => no HTTP, and
    drop the memo so a previous test's env doesn't leak into this one."""
    import os
    os.environ.pop("VEILGUARD_INTERNAL_SECRET", None)
    sc.invalidate_cache()


# ── pure-unit tests (no network) ─────────────────────────────────────────


def test_normalize_url_dedupes_variants():
    a = normalize_url("https://www.Example.com/Path/?utm_source=x&id=7#frag")
    b = normalize_url("http://example.com/Path?id=7")
    assert a == b == "example.com/Path?id=7", (a, b)


def test_rrf_rewards_multi_provider_and_dedupes():
    lists = [
        [SearchResult("A", "https://a.com/x", "snip a", "duckduckgo"),
         SearchResult("B", "https://b.com/y", "", "duckduckgo")],
        [SearchResult("A2", "https://www.a.com/x/", "longer snippet for a", "wikipedia"),
         SearchResult("C", "https://c.com/z", "", "wikipedia")],
    ]
    merged = rrf_merge(lists)
    # a.com surfaced by both → ranked first, providers joined, longest snippet kept.
    assert merged[0].url.rstrip("/").endswith("a.com/x"), merged[0].url
    assert merged[0].provider == "duckduckgo,wikipedia", merged[0].provider
    assert merged[0].snippet == "longer snippet for a"
    urls = {normalize_url(m.url) for m in merged}
    assert len(urls) == len(merged) == 3  # deduped


def test_parse_grounding_extracts_chunks_supports_queries():
    data = {
        "candidates": [{
            "content": {"parts": [{"text": "The sky is blue."}]},
            "groundingMetadata": {
                "groundingChunks": [
                    {"web": {"uri": "https://x.com/a", "title": "X"}},
                    {"web": {"uri": "https://y.com/b", "title": "Y"}},
                ],
                "groundingSupports": [
                    {"segment": {"endIndex": 15}, "groundingChunkIndices": [0, 1]},
                ],
                "webSearchQueries": ["why is the sky blue", "sky color physics"],
            },
        }]
    }
    g = wa._parse_grounding(data)
    assert g["summary"] == "The sky is blue."
    assert len(g["chunks"]) == 2 and g["chunks"][0]["uri"] == "https://x.com/a"
    assert g["queries"] == ["why is the sky blue", "sky color physics"]


def test_cite_grounded_summary_inserts_markers():
    summary = "The sky is blue."  # 16 bytes; endIndex 15 = before final '.'
    supports = [{"segment": {"endIndex": 15}, "groundingChunkIndices": [0, 1]}]
    cited = wa._cite_grounded_summary(summary, supports, n_sources=2)
    assert "[1][2]" in cited, cited


def test_split_answer_followups():
    txt = "Main answer [1].\n### Related\n- One?\n- Two?\n- Three?"
    ans, fus = wa._split_answer_followups(txt)
    assert ans == "Main answer [1]."
    assert fus == ["One?", "Two?", "Three?"]


def test_parse_ddg_regex_fallback_decodes_uddg():
    # Force the regex path (works regardless of bs4 availability).
    html = (
        '<div class="result results_links">'
        '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa&rut=z">Title A</a>'
        '<a class="result__snippet" href="x">Snippet A</a>'
        '</div>'
    )
    saved = sp._BS
    sp._BS = None
    try:
        res = _parse_ddg(html, limit=5)
    finally:
        sp._BS = saved
    assert len(res) == 1
    assert res[0].url == "https://example.com/a", res[0].url
    assert res[0].title == "Title A"
    assert res[0].snippet == "Snippet A"


def test_to_markdown_renders_sources_and_related():
    r = wa.WebAnswer(query="q", answer="Answer [1].",
                     sources=[wa.Source(1, "T", "https://t.com", "snip", providers="duckduckgo,google")],
                     follow_ups=["More?"])
    md = r.to_markdown()
    assert "Answer [1]." in md and "## Sources" in md and "https://t.com" in md
    assert "duckduckgo,google" in md and "## Related" in md and "- More?" in md


def test_to_markdown_error_passthrough():
    r = wa.WebAnswer(query="q", error="Error: boom")
    assert r.to_markdown() == "Error: boom"


# ── end-to-end with httpx mocked ─────────────────────────────────────────

_GROUND = {
    "candidates": [{
        "content": {"parts": [{"text": "Grounded summary."}]},
        "groundingMetadata": {
            "groundingChunks": [{"web": {"uri": "https://news.com/story", "title": "News"}}],
            "groundingSupports": [{"segment": {"endIndex": 16}, "groundingChunkIndices": [0]}],
            "webSearchQueries": ["alt query one", "alt query two"],
        },
    }]
}
_SYNTH = {"candidates": [{"content": {"parts": [{
    "text": "Deep synthesized answer [1][2].\n### Related\n- Follow up one?\n- Follow up two?"
}]}}]}
_DDG_HTML = (
    '<div class="result results_links">'
    '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa">DDG A</a>'
    '<a class="result__snippet">snippet a</a></div>'
    '<div class="result results_links">'
    '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fnews.com%2Fstory">DDG News</a>'
    '<a class="result__snippet">news snippet</a></div>'
)
_WIKI = {"query": {"search": [{"title": "Example", "snippet": "<span>wiki snippet</span>"}]}}


def _gap_json(text):
    return {"candidates": [{"content": {"parts": [{"text": text}]}}]}


_SEARX = {"results": [
    {"title": "Searx Sky", "url": "https://news.com/story", "content": "searx snippet"},
    {"title": "Searx Extra", "url": "https://searxonly.com/p", "content": "only via searxng"},
]}


def _handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if "generativelanguage.googleapis.com" in url:
        body = request.content.decode("utf-8") if request.content else ""
        if "google_search" in body:
            return httpx.Response(200, json=_GROUND)
        if "REMAINING gaps" in body:               # the agentic gap-analysis step
            return httpx.Response(200, json=_gap_json("sky rayleigh scattering data"))
        return httpx.Response(200, json=_SYNTH)     # final synthesis
    if "html.duckduckgo.com" in url or "lite.duckduckgo.com" in url:
        return httpx.Response(200, text=_DDG_HTML)
    if "searxng:8080/search" in url:
        return httpx.Response(200, json=_SEARX)
    if "en.wikipedia.org/w/api.php" in url:
        return httpx.Response(200, json=_WIKI)
    # Any other GET = a source page fetch. Include query terms so passage
    # reranking has something to score.
    return httpx.Response(
        200,
        text="<html><body><p>The sky is blue because of Rayleigh scattering of "
             "sunlight by the atmosphere. Shorter blue wavelengths scatter more.</p>"
             "</body></html>",
        headers={"content-type": "text/html"})


def _patched_client():
    class _Factory:
        def __getattr__(self, name):
            return getattr(httpx, name)

        def AsyncClient(self, *a, **k):
            k["transport"] = httpx.MockTransport(_handler)
            return httpx.AsyncClient(*a, **k)
    return _Factory()


def _run_e2e(depth):
    import os
    os.environ["GOOGLE_API_KEY"] = "test-key"
    os.environ["SEARXNG_URL"] = "http://searxng:8080"   # 3rd provider on the net
    os.environ.pop("BRAVE_API_KEY", None)
    _isolate_config()
    saved = wa.httpx
    wa.httpx = _patched_client()
    try:
        return asyncio.run(wa.web_answer("why is the sky blue", depth=depth))
    finally:
        wa.httpx = saved
        os.environ.pop("SEARXNG_URL", None)
        sc.invalidate_cache()


def test_e2e_deep_multi_provider():
    res = _run_e2e("deep")
    assert res.error == "", res.error
    assert res.answer.startswith("Deep synthesized answer"), res.answer
    assert res.follow_ups == ["Follow up one?", "Follow up two?"]
    # Multi-provider: google (grounding) + duckduckgo + wikipedia + searxng present.
    assert {"google", "duckduckgo", "wikipedia", "searxng"} <= set(res.providers_used), res.providers_used
    # A result only SearXNG surfaced still makes it into the fused pool.
    assert any("searxonly.com" in s.url for s in res.sources), [s.url for s in res.sources]
    # Deep mode fanned out to Gemini's expanded sub-queries.
    assert "alt query one" in res.search_queries, res.search_queries
    # ITERATIVE: round-2 ran the gap-analysis query → proves search→reason→search.
    assert "sky rayleigh scattering data" in res.search_queries, res.search_queries
    # news.com/story surfaced by BOTH grounding and DDG → fused to one source.
    news = [s for s in res.sources if "news.com/story" in s.url]
    assert len(news) == 1 and "google" in news[0].providers and "duckduckgo" in news[0].providers
    # Top sources were actually fetched & read.
    assert any(s.fetched for s in res.sources)
    md = res.to_markdown()
    assert "## Sources" in md and "## Related" in md


def test_select_passages_picks_relevant_window():
    s = wa.Source(1, "T", "https://t.com",
                  content=("Totally unrelated boilerplate about cookies and privacy. " * 8)
                          + " The capital of Australia is Canberra, chosen as a compromise.")
    passages = wa._select_passages("capital of australia canberra", [s], win=120, stride=100)
    assert passages, "no passages selected"
    # The relevant window (mentions canberra/capital/australia) should be chosen.
    assert any("Canberra" in p for _n, p in passages), passages


def test_validate_citations_drops_out_of_range():
    out = wa._validate_citations("Claim A [1] and B [9] and C [3].", n_sources=3)
    assert "[1]" in out and "[3]" in out and "[9]" not in out, out


def test_detect_recency():
    assert wa._detect_recency("latest iPhone 2026 specs") == "month"
    assert wa._detect_recency("what happened today in markets") == "week"
    assert wa._detect_recency("history of the roman empire") is None


def test_searxng_provider_parses_json_and_recency():
    import os
    os.environ["SEARXNG_URL"] = "http://searxng:8080"
    captured = {}

    def handler(req):
        captured["url"] = str(req.url)
        if "/search" in str(req.url):
            return httpx.Response(200, json={"results": [
                {"title": "R1", "url": "https://r1.com/a", "content": "snip 1"},
                {"title": "R2", "url": "https://r2.com/b", "content": "snip 2"},
            ]})
        return httpx.Response(404)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await sp.searxng_search(c, "q", 5, recency="week")

    try:
        res = asyncio.run(run())
    finally:
        os.environ.pop("SEARXNG_URL", None)
    assert len(res) == 2 and res[0].provider == "searxng"
    assert res[0].url == "https://r1.com/a"
    assert "time_range=week" in captured["url"], captured["url"]


def test_enabled_providers_gating():
    import os
    for k in ("SEARXNG_URL", "VEILGUARD_SEARXNG_URL", "BRAVE_API_KEY", "BRAVE_SEARCH_API_KEY"):
        os.environ.pop(k, None)
    # No keys / no container → three native always-on providers.
    assert {n for n, _ in sp.enabled_providers()} == {"duckduckgo", "wikipedia", "mojeek"}
    os.environ["SEARXNG_URL"] = "http://x:8080"   # external instance, opt-in
    os.environ["BRAVE_API_KEY"] = "k"
    try:
        assert {n for n, _ in sp.enabled_providers()} == {
            "duckduckgo", "wikipedia", "mojeek", "searxng", "brave"}
    finally:
        os.environ.pop("SEARXNG_URL", None)
        os.environ.pop("BRAVE_API_KEY", None)


def test_mojeek_provider_parses_results():
    html = (
        '<h2><a class="title" href="https://a.com/x">Title A</a></h2>'
        '<p class="s">Snippet A about things.</p>'
        '<h2><a class="title" href="https://b.com/y">Title B</a></h2>'
        '<p class="s">Snippet B.</p>'
    )

    def handler(req):
        return httpx.Response(200, text=html)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await sp.mojeek_search(c, "q", 5)

    res = asyncio.run(run())
    assert len(res) == 2 and res[0].provider == "mojeek"
    assert res[0].url == "https://a.com/x" and res[0].snippet == "Snippet A about things."


def test_e2e_quick_single_query():
    res = _run_e2e("quick")
    assert res.error == ""
    assert res.search_queries == ["why is the sky blue"]  # no fan-out in quick mode


def test_e2e_synth_failure_falls_back_to_grounded_summary():
    import os
    os.environ["GOOGLE_API_KEY"] = "test-key"
    _isolate_config()

    def handler(request):
        url = str(request.url)
        if "generativelanguage" in url:
            body = request.content.decode() if request.content else ""
            if "google_search" in body:
                return httpx.Response(200, json=_GROUND)
            return httpx.Response(500, text="synth boom")  # synth fails
        if "duckduckgo" in url:
            return httpx.Response(200, text=_DDG_HTML)
        if "wikipedia.org/w/api.php" in url:
            return httpx.Response(200, json=_WIKI)
        return httpx.Response(200, text="<p>page</p>", headers={"content-type": "text/html"})

    class _F:
        def __getattr__(self, n):
            return getattr(httpx, n)

        def AsyncClient(self, *a, **k):
            k["transport"] = httpx.MockTransport(handler)
            return httpx.AsyncClient(*a, **k)

    saved = wa.httpx
    wa.httpx = _F()
    try:
        res = asyncio.run(wa.web_answer("q", depth="quick"))
    finally:
        wa.httpx = saved
    # Falls back to grounded summary, with [1] citation rebuilt from supports
    # (the marker is spliced in, so check the text + marker separately).
    assert "Grounded summary" in res.answer, res.answer
    assert "[1]" in res.answer, res.answer


def test_no_key_no_optional_still_uses_free_providers():
    import os
    os.environ.pop("GOOGLE_API_KEY", None)
    os.environ.pop("GEMINI_API_KEY", None)
    os.environ.pop("SEARXNG_URL", None)
    os.environ.pop("BRAVE_API_KEY", None)
    _isolate_config()
    saved = wa.httpx
    wa.httpx = _patched_client()
    try:
        res = asyncio.run(wa.web_answer("q", depth="quick"))
    finally:
        wa.httpx = saved
        sc.invalidate_cache()
    # No grounding/synth (no key) but DDG + Wikipedia still return sources.
    assert res.error == "", res.error
    assert len(res.sources) >= 1
    assert {"duckduckgo", "wikipedia"} & set(res.providers_used)
    # ...and the run SAYS it was degraded instead of quietly looking fine.
    assert any("No Gemini key" in d for d in res.diagnostics), res.diagnostics


# ── [SEARCH_CONFIG_2026-07-25] config resolution ─────────────────────────


def test_config_falls_back_to_env_without_internal_secret():
    import os
    os.environ.pop("VEILGUARD_INTERNAL_SECRET", None)
    os.environ["GOOGLE_API_KEY"] = "env-key"
    os.environ["TAVILY_API_KEY"] = "tv-key"
    sc.invalidate_cache()
    try:
        cfg = asyncio.run(sc.resolve_search_config("u@x.com"))
    finally:
        os.environ.pop("TAVILY_API_KEY", None)
        sc.invalidate_cache()
    assert cfg.source == "env"
    assert cfg.gemini_api_key == "env-key" and cfg.gemini_key_source == "env"
    assert cfg.key_for("tavily_api_key") == "tv-key"
    assert "INTERNAL_SECRET" in cfg.error


def test_config_reads_db_and_keeps_env_as_floor():
    """DB wins per field; anything the DB leaves blank still comes from env, so
    an operator can rescue search with a container var."""
    import os
    os.environ["VEILGUARD_INTERNAL_SECRET"] = "s3cret"
    os.environ["BRAVE_API_KEY"] = "brave-from-env"
    os.environ["GOOGLE_API_KEY"] = "env-key"
    sc.invalidate_cache()

    def handler(req):
        assert req.headers.get("x-internal-secret") == "s3cret"
        return httpx.Response(200, json={
            "gemini_api_key": "vault-key",
            "gemini_key_source": "user",
            "search_model": "gemini-3.1-flash-lite",
            "synth_model": "",
            "providers": {"mojeek": False},
            "engine_keys": {"tavily_api_key": "tv"},
            "num_results": 11,
        })

    class _F:
        def __getattr__(self, n):
            return getattr(httpx, n)

        def AsyncClient(self, *a, **k):
            k["transport"] = httpx.MockTransport(handler)
            return httpx.AsyncClient(*a, **k)

    saved = sc.httpx
    sc.httpx = _F()
    try:
        cfg = asyncio.run(sc.resolve_search_config("u@x.com"))
    finally:
        sc.httpx = saved
        os.environ.pop("VEILGUARD_INTERNAL_SECRET", None)
        os.environ.pop("BRAVE_API_KEY", None)
        sc.invalidate_cache()
    assert cfg.source == "db" and cfg.error == ""
    assert cfg.gemini_api_key == "vault-key"          # DB beats env
    assert cfg.gemini_key_source == "user"
    assert cfg.num_results == 11
    assert cfg.key_for("tavily_api_key") == "tv"
    assert cfg.key_for("brave_api_key") == "brave-from-env"   # env floor
    assert cfg.providers == {"mojeek": False}


def test_enabled_providers_honours_config_keys_and_toggles():
    import os
    for k in ("SEARXNG_URL", "VEILGUARD_SEARXNG_URL", "BRAVE_API_KEY",
              "BRAVE_SEARCH_API_KEY", "TAVILY_API_KEY", "EXA_API_KEY",
              "SERPER_API_KEY"):
        os.environ.pop(k, None)
    cfg = sc.SearchConfig(
        engine_keys={"tavily_api_key": "k", "serper_api_key": "k"},
        providers={"mojeek": False, "brave": True},  # brave has NO key → stays off
    )
    names = {n for n, _ in sp.enabled_providers(cfg)}
    assert names == {"duckduckgo", "wikipedia", "tavily", "serper"}, names


# ── new engines ──────────────────────────────────────────────────────────


def _one_shot(fn, payload, *, status=200, capture=None):
    def handler(req):
        if capture is not None:
            capture["url"] = str(req.url)
            capture["body"] = req.content.decode() if req.content else ""
            capture["headers"] = dict(req.headers)
        return httpx.Response(status, json=payload)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await fn(c, "q", 5, None, cfg=_cfg_with(fn))
    return asyncio.run(run())


def _cfg_with(fn):
    field = {
        sp.tavily_search: "tavily_api_key",
        sp.exa_search: "exa_api_key",
        sp.serper_search: "serper_api_key",
        sp.brave_search: "brave_api_key",
    }[fn]
    return sc.SearchConfig(engine_keys={field: "test-key"})


def test_tavily_returns_page_content_not_just_snippets():
    cap = {}
    res = _one_shot(sp.tavily_search, {"results": [
        {"title": "T1", "url": "https://t1.com/a", "content": "x" * 900},
    ]}, capture=cap)
    assert len(res) == 1 and res[0].provider == "tavily"
    # The point of Tavily: it hands back page text, so the engine skips a fetch.
    assert len(res[0].content) == 900
    assert res[0].snippet == "x" * 400
    assert cap["headers"].get("authorization") == "Bearer test-key"


def test_exa_parses_results_and_sets_recency_window():
    cap = {}

    def handler(req):
        cap["body"] = req.content.decode()
        return httpx.Response(200, json={"results": [
            {"title": "E1", "url": "https://e1.com/a", "text": "neural body text"},
        ]})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await sp.exa_search(c, "q", 5, "week",
                                       cfg=sc.SearchConfig(engine_keys={"exa_api_key": "k"}))

    res = asyncio.run(run())
    assert len(res) == 1 and res[0].provider == "exa"
    assert res[0].content == "neural body text"
    assert "startPublishedDate" in cap["body"], cap["body"]


def test_serper_lifts_answer_box_above_organic():
    res = _one_shot(sp.serper_search, {
        "answerBox": {"title": "Repo rate", "link": "https://sarb.co.za/x",
                      "answer": "7.00%"},
        "organic": [{"title": "O1", "link": "https://o1.com/a", "snippet": "s1"}],
    })
    assert [r.url for r in res] == ["https://sarb.co.za/x", "https://o1.com/a"]
    assert res[0].snippet == "7.00%"


def test_keyed_provider_without_key_returns_empty_not_error():
    async def run():
        async with httpx.AsyncClient() as c:
            return await sp.tavily_search(c, "q", 5, None, cfg=sc.SearchConfig())
    assert asyncio.run(run()) == []


# ── fusion quality ───────────────────────────────────────────────────────


def test_rrf_weights_stronger_providers_above_weaker_at_same_rank():
    lists = [
        [SearchResult("W", "https://wiki.org/a", "", "wikipedia")],
        [SearchResult("S", "https://serp.com/a", "", "serper")],
    ]
    merged = rrf_merge(lists)
    assert merged[0].url == "https://serp.com/a", [m.url for m in merged]


def test_rrf_per_domain_cap_demotes_but_never_drops():
    lists = [[
        SearchResult("1", "https://hog.com/a", "", "serper"),
        SearchResult("2", "https://hog.com/b", "", "serper"),
        SearchResult("3", "https://hog.com/c", "", "serper"),
        SearchResult("4", "https://other.com/z", "", "duckduckgo"),
    ]]
    merged = rrf_merge(lists, per_domain=2)
    urls = [m.url for m in merged]
    assert len(urls) == 4, urls                       # nothing dropped
    assert urls.index("https://other.com/z") == 2     # promoted past hog #3
    assert urls[-1] == "https://hog.com/c"


def test_registrable_domain_handles_two_label_suffixes():
    assert registrable_domain("https://www.news24.co.za/a/b") == "news24.co.za"
    assert registrable_domain("https://sub.example.com/x") == "example.com"
    assert registrable_domain("https://example.com") == "example.com"


def test_rrf_keeps_longest_provider_supplied_content():
    lists = [
        [SearchResult("A", "https://a.com/x", "s", "duckduckgo")],
        [SearchResult("A", "https://a.com/x", "s", "tavily", content="full page text")],
    ]
    merged = rrf_merge(lists)
    assert merged[0].content == "full page text"


# ── extraction + citation hygiene ────────────────────────────────────────


def test_html_to_text_drops_chrome_when_html2text_absent():
    saved = wa._H2T
    wa._H2T = None
    try:
        txt = wa._html_to_text(
            "<html><head><style>.a{color:red}</style></head><body>"
            "<nav>Home About Contact</nav><p>The actual article body.</p>"
            "<footer>Copyright 2026</footer></body></html>"
        )
    finally:
        wa._H2T = saved
    assert "actual article body" in txt
    assert "Home About Contact" not in txt and "Copyright" not in txt


def test_validate_citations_tidies_space_left_by_dropped_marker():
    out = wa._validate_citations("A claim [9]. Another [1].", n_sources=1)
    assert out == "A claim. Another [1].", repr(out)


def test_extractive_answer_quotes_sources_when_no_model():
    srcs = [
        wa.Source(1, "SARB", "https://sarb.co.za/x",
                  content="Cookie notice and navigation. "
                          "The repo rate was left unchanged at 7.00% in July 2026. "
                          "Subscribe to our newsletter."),
        wa.Source(2, "Nedbank", "https://nedbank.co.za/y",
                  content="The prime lending rate therefore stays at 10.50% "
                          "following the repo rate decision."),
    ]
    passages = wa._select_passages("repo rate south africa", srcs, win=400, stride=300)
    out = wa._extractive_answer("what is the repo rate in south africa", srcs, passages)
    assert "7.00%" in out, out
    assert "[1]" in out and "[2]" in out, out
    # Boilerplate must not win over the sentence that answers the question.
    assert "Subscribe to our newsletter" not in out, out


def test_extractive_answer_prefers_the_top_ranked_source():
    """Live failure this guards: on "who won the 2026 World Cup" the 1986 final
    page matched as many query terms as the 2026 one, so the digest led with a
    1986 match report. Source rank has to break that tie."""
    srcs = [
        wa.Source(1, "2026 final", "https://en.wikipedia.org/wiki/2026_final",
                  content="Spain beat Argentina in the 2026 FIFA World Cup final "
                          "to win the trophy at MetLife Stadium."),
        wa.Source(2, "1986 final", "https://en.wikipedia.org/wiki/1986_final",
                  content="Argentina beat West Germany in the 1986 FIFA World Cup "
                          "final to win the trophy at the Estadio Azteca."),
    ]
    passages = wa._select_passages("who won the fifa world cup final", srcs,
                                   win=400, stride=300)
    out = wa._extractive_answer("who won the 2026 fifa world cup final", srcs, passages)
    first = out.strip().splitlines()[2]
    assert "2026" in first and "1986" not in first, out


def test_extractive_answer_empty_without_passages():
    assert wa._extractive_answer("q", [], []) == ""


def test_fallback_subqueries_strips_interrogative_scaffolding():
    assert wa._fallback_subqueries(
        "What is the current SARB repo rate?") == ["current SARB repo rate"]
    # Nothing meaningfully different → no extra query (don't burn a fan-out).
    assert wa._fallback_subqueries("SARB repo rate") == []
    assert wa._fallback_subqueries("why?") == []


def test_no_key_run_still_produces_an_answer_not_just_links():
    """The prod failure this guards: Gemini 429s, synthesis returns nothing, and
    web_search hands back an empty answer above a list of URLs."""
    import os
    for k in ("GOOGLE_API_KEY", "GEMINI_API_KEY", "SEARXNG_URL", "BRAVE_API_KEY"):
        os.environ.pop(k, None)
    _isolate_config()
    saved = wa.httpx
    wa.httpx = _patched_client()
    try:
        res = asyncio.run(wa.web_answer("why is the sky blue", depth="quick"))
    finally:
        wa.httpx = saved
        sc.invalidate_cache()
    assert res.answer.strip(), "degraded run produced no answer at all"
    assert res.stats.get("answer_mode") == "extractive", res.stats
    assert re.search(r"\[\d\]", res.answer), res.answer
    assert "Rayleigh" in res.answer, res.answer


def test_html_to_text_drops_whitespace_only_lines():
    """A JS-heavy page used to come back as hundreds of single-space lines."""
    saved = wa._H2T
    wa._H2T = None
    try:
        txt = wa._html_to_text(
            "<div><span></span></div>" * 40 + "<p>Real content here.</p>"
            + "<div><i></i></div>" * 40 + "<p>More content.</p>"
        )
    finally:
        wa._H2T = saved
    assert "Real content here." in txt and "More content." in txt
    assert not [ln for ln in txt.splitlines() if ln and not ln.strip()], repr(txt[:200])
    assert len(txt) < 120, repr(txt)


def test_wikipedia_is_capped_so_it_cannot_crowd_the_fused_list():
    def handler(req):
        assert "srlimit=4" in str(req.url), str(req.url)
        return httpx.Response(200, json={"query": {"search": [
            {"title": f"Stub {i}", "snippet": "s"} for i in range(8)
        ]}})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await sp.wikipedia_search(c, "q", 8)

    assert len(asyncio.run(run())) == 4


def test_grounding_chunks_resolve_to_real_urls_before_fusion():
    """Resolving redirects at RENDER time hid the real domain from dedup and the
    per-domain cap; they must be resolved before anything is fused."""
    real = "https://en.wikipedia.org/wiki/2026_FIFA_World_Cup"

    def handler(req):
        if "vertexaisearch" in str(req.url):
            return httpx.Response(302, headers={"location": real})
        return httpx.Response(200, text="ok")

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await wa._resolve_grounding_chunks(c, [
                {"uri": "https://vertexaisearch.cloud.google.com/grounding-api-redirect/AB", "title": "t"},
                {"uri": "https://direct.example.com/a", "title": "d"},
            ])

    out = asyncio.run(run())
    assert out[0]["uri"] == real, out
    assert out[1]["uri"] == "https://direct.example.com/a", out


def test_run_reports_per_stage_timings_and_respects_a_deadline():
    """A 'quick' search was measured at 135s with no budget and no way to see
    which stage ate it."""
    import os
    os.environ["GOOGLE_API_KEY"] = "test-key"
    _isolate_config()
    saved = wa.httpx
    wa.httpx = _patched_client()
    try:
        res = asyncio.run(wa.web_answer("why is the sky blue", depth="deep",
                                        deadline_s=15))
    finally:
        wa.httpx = saved
        sc.invalidate_cache()
    ms = res.stats.get("ms") or {}
    assert {"ground", "search", "fetch", "synth", "total"} <= set(ms), ms
    assert all(isinstance(v, int) and v >= 0 for v in ms.values()), ms
    # `ms` must be stamped AFTER synthesis, else synth always reports 0 and
    # total under-counts — which is exactly what the first version did.
    assert ms["total"] >= ms["ground"] + ms["search"] + ms["synth"], ms
    # Mocked transport is instant, so the budget must not have tripped.
    assert not any("budget" in d for d in res.diagnostics), res.diagnostics
    assert res.answer, res.answer


def test_deadline_floor_prevents_a_zero_budget():
    """deadline_s is clamped, so a caller passing 0 cannot disable synthesis."""
    import os
    os.environ["GOOGLE_API_KEY"] = "test-key"
    _isolate_config()
    saved = wa.httpx
    wa.httpx = _patched_client()
    try:
        res = asyncio.run(wa.web_answer("why is the sky blue", depth="quick",
                                        deadline_s=0))
    finally:
        wa.httpx = saved
        sc.invalidate_cache()
    assert res.answer.startswith("Deep synthesized answer"), res.answer


def test_ddg_ladder_retries_a_fast_reject_but_abandons_a_hang():
    """The two failure shapes need opposite responses: another host/verb may
    beat a 202 challenge cheaply, but retrying a HANGING host just multiplies
    the timeout."""
    saved = sp._DDG_ATTEMPT_TIMEOUT_S
    sp._DDG_ATTEMPT_TIMEOUT_S = 0.2
    calls: list[str] = []

    def rejecting(req):
        calls.append(str(req.url))
        # First two shapes challenge fast, the third (GET html) succeeds.
        if len(calls) < 3:
            return httpx.Response(202, text="challenge")
        return httpx.Response(200, text=_DDG_HTML)

    async def run(handler):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await sp.ddg_search(c, "q", 5)

    try:
        res = asyncio.run(run(rejecting))
        assert res, "fast rejects should have been retried through to a 200"
        assert len(calls) == 3, calls

        calls.clear()
        hang_calls = {"n": 0}

        def hanging(req):
            hang_calls["n"] += 1
            raise httpx.ReadTimeout("hang", request=req)

        assert asyncio.run(run(hanging)) == []
        assert hang_calls["n"] == 1, f"a hang must not be retried, got {hang_calls['n']}"
    finally:
        sp._DDG_ATTEMPT_TIMEOUT_S = saved


def test_a_hung_engine_cannot_hold_the_round_open():
    """Measured: a hanging DuckDuckGo turned the fan-out into a 33.7s `search`
    stage because the shared client's 30s default was the only limit."""
    import os
    os.environ["GOOGLE_API_KEY"] = "test-key"
    _isolate_config()
    saved_timeout = wa._PROVIDER_TIMEOUT_S
    wa._PROVIDER_TIMEOUT_S = 0.3

    async def hung(client, query, limit=10, recency=None, *, cfg=None):
        await asyncio.sleep(30)
        return [SearchResult("never", "https://never.com/x", "", "duckduckgo")]

    saved_providers = sp._ALL_PROVIDERS.copy()
    sp._ALL_PROVIDERS["duckduckgo"] = hung
    saved = wa.httpx
    wa.httpx = _patched_client()
    try:
        t0 = time.monotonic()
        res = asyncio.run(wa.web_answer("why is the sky blue", depth="quick"))
        elapsed = time.monotonic() - t0
    finally:
        wa.httpx = saved
        wa._PROVIDER_TIMEOUT_S = saved_timeout
        sp._ALL_PROVIDERS.clear()
        sp._ALL_PROVIDERS.update(saved_providers)
        sc.invalidate_cache()
    assert elapsed < 10, f"hung engine held the round for {elapsed:.1f}s"
    # The other engines still carried the search.
    assert res.sources, res.diagnostics
    assert not any("never.com" in s.url for s in res.sources)


def test_low_yield_hosts_are_demoted_for_the_read_stage():
    """The Python 3.14 UAT: docs.python.org ranked 4th and was never read
    because two of three fetch slots went to YouTube watch pages."""
    assert wa._low_yield("https://www.youtube.com/watch?v=abc")
    assert wa._low_yield("https://youtu.be/abc")
    assert wa._low_yield("https://x.com/someone/status/1")
    assert not wa._low_yield("https://docs.python.org/3/whatsnew/3.14.html")
    assert not wa._low_yield("https://realpython.com/python-news/")


def test_unreadable_extension_is_not_fetched():
    async def run():
        sem = asyncio.Semaphore(2)
        async with httpx.AsyncClient() as c:
            return await wa._fetch_one(c, "https://x.com/report.pdf?v=2", sem)
    assert asyncio.run(run()) is None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL {fn.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed out of {passed + failed}")
    sys.exit(1 if failed else 0)
