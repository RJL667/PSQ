# Vendored: veilguard deep web-search answer engine

`web_answer.py`, `search_providers.py` and `search_config.py` are copied
**verbatim** from the veilguard stack so they can be re-synced cleanly. Do not
edit them — scanner-specific behaviour belongs in `__init__.py`.

| | |
|---|---|
| **Upstream** | `RJL667/veilguard-stack` (private) |
| **Path** | `veilguard/services/_shared/` |
| **Vendored** | 2026-07-27 |
| **Spec** | `veilguard/docs/WEB_SEARCH_PERPLEXITY_PARITY_SPEC.md` (2026-06-30) |
| **Runtime dep** | `httpx` only (plus stdlib) |

Also vendored: `tests/test_web_answer.py` (upstream's own suite, unmodified).

> The older public `RJL667/veilguard` repo is **stale** (last push 2026-06-13) and
> does not contain this engine — always re-sync from `veilguard-stack`.

## Re-syncing

```bash
for f in web_answer search_providers search_config; do
  gh api "repos/RJL667/veilguard-stack/contents/veilguard/services/_shared/$f.py" \
    -H "Accept: application/vnd.github.raw" > "security_scanner/websearch/$f.py"
done
```

Then re-run `python -m websearch.selftest` (or the breach-discovery tool) to confirm
nothing upstream changed the `web_answer(config=...)` seam described below.

## The one deviation we rely on

Upstream resolves its Gemini key from the Command Centre credential vault over an
internal HTTP route (`COMMAND_CENTRE_URL` + `VEILGUARD_INTERNAL_SECRET`, backed by
Postgres `cc_search_settings`). The scanner has no Command Centre, so
`__init__.scanner_search_config()` builds a `SearchConfig` from the process env and
passes it as `web_answer(config=...)`, which **short-circuits that lookup**
(`web_answer.py`: `cfg = config if config is not None else await resolve_search_config(user_id)`).

If a future upstream version removes or renames the `config=` parameter, that is the
seam to re-check.

## Configuration

| Env var | Effect |
|---|---|
| `GOOGLE_API_KEY` | Google AI Studio (Gemini) key. **Without it there is no grounding, no query expansion and no synthesized answer** — only fused snippets from the free providers. |
| `GEMINI_SEARCH_MODEL` / `GEMINI_SYNTH_MODEL` | model overrides |
| `BRAVE_API_KEY`, `SEARXNG_URL` | optional extra providers |

Upstream shipped with `GOOGLE_API_KEY` blank on prod for weeks and the engine
degraded *silently* to snippets (see the header of `search_config.py`). Our wrapper
therefore returns an explicit `configured` / `key_source` on every call, and the
breach checker records it, so that failure mode can never be silent here.
