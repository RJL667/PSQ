"""Where web search gets its keys and knobs (shared).

[SEARCH_CONFIG_2026-07-25] Search used to read ``GOOGLE_API_KEY`` /
``BRAVE_API_KEY`` / ``SEARXNG_URL`` straight from the process env. On prod
``GOOGLE_API_KEY`` was **empty**, so every ``web_search`` ran with no Gemini
grounding, no query expansion and no synthesis — it returned fused snippets and
looked stupid, silently, for as long as that env var had been blank.

Now the configuration lives in Postgres (``cc_search_settings``) and the Gemini
key comes from the SAME credential vault the chat / OCR / TCMM-NLP lanes use.
Command Centre owns the decryption (the ciphertext is AES-GCM under
``CC_CREDS_KEY``, a Node secret), so this module fetches the resolved config
from its internal route in one call:

    GET {COMMAND_CENTRE_URL}/api/llm/internal/search-settings/{user_id}
        x-internal-secret: {VEILGUARD_INTERNAL_SECRET}

Contract, deliberately conservative:

* **Never raises.** A missing secret, an unreachable Command Centre, a stale
  route — any of them degrade to the process env, which is exactly the old
  behaviour. Search keeps working; ``config.source`` and ``config.error`` record
  what happened so ``web_search``'s diagnostics can say WHY the key is missing
  instead of silently answering from snippets.
* **Env is the floor, DB is the override.** A field the DB doesn't set falls
  back to env, then to the engine's compiled default. So an operator can still
  fix search from the container env in an emergency.
* **Cached briefly** (``SEARCH_CONFIG_TTL_S``, default 60s) per user id, because
  every ``web_search`` call resolves it and a chat turn can fire several.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

# Engine-key fields inside the encrypted bag. MIRRORS ``ENGINE_KEY_FIELDS`` in
# command-centre/src/lib/searchSettings.ts — keep the two lists in step.
_ENGINE_KEY_FIELDS = (
    "brave_api_key",
    "tavily_api_key",
    "exa_api_key",
    "serper_api_key",
    "searxng_url",
)

# Per-field env fallbacks, tried in order. First non-empty wins.
_ENGINE_KEY_ENV: dict[str, tuple[str, ...]] = {
    "brave_api_key": ("BRAVE_API_KEY", "BRAVE_SEARCH_API_KEY"),
    "tavily_api_key": ("TAVILY_API_KEY",),
    "exa_api_key": ("EXA_API_KEY",),
    "serper_api_key": ("SERPER_API_KEY", "SERPER_DEV_API_KEY"),
    "searxng_url": ("SEARXNG_URL", "VEILGUARD_SEARXNG_URL"),
}

_TTL_S = float(os.environ.get("SEARCH_CONFIG_TTL_S", "60"))


@dataclass
class SearchConfig:
    """Everything the answer engine needs to run one query."""

    gemini_api_key: str = ""
    # user | configured | owner | system | env | none — surfaced in diagnostics
    # so "search has no key" is never a mystery again.
    gemini_key_source: str = "none"
    gemini_credential_user_id: str = ""
    search_model: str = ""
    synth_model: str = ""
    depth: str = ""
    rounds: int | None = None
    num_results: int | None = None
    fetch_sources: int | None = None
    #: explicit per-engine on/off overrides ONLY; engines absent here keep their
    #: own default (no-key engines on, keyed engines on iff a key is present).
    providers: dict[str, bool] = field(default_factory=dict)
    engine_keys: dict[str, str] = field(default_factory=dict)
    #: "db" (Command Centre answered) | "env" (fell back) — for diagnostics.
    source: str = "env"
    #: populated when the DB read failed; empty on the happy path.
    error: str = ""

    def key_for(self, field_name: str) -> str:
        return (self.engine_keys.get(field_name) or "").strip()

    def describe(self) -> str:
        """One-line provenance string for logs / the tool's debug footer."""
        keyed = sorted(k.rsplit("_", 2)[0] for k in self.engine_keys if self.engine_keys[k])
        return (
            f"config={self.source} gemini_key={'yes' if self.gemini_api_key else 'NO'}"
            f"({self.gemini_key_source}) engines={keyed or 'none'}"
            + (f" error={self.error}" if self.error else "")
        )


def _cc_base_url() -> str:
    return os.environ.get(
        "COMMAND_CENTRE_URL", "http://host.docker.internal:3000"
    ).rstrip("/")


def _internal_secret() -> str:
    return os.environ.get("VEILGUARD_INTERNAL_SECRET", "")


def _env_config() -> SearchConfig:
    """The pre-DB behaviour: everything from the process env."""
    key = (
        os.environ.get("GOOGLE_API_KEY", "")
        or os.environ.get("GEMINI_API_KEY", "")
    ).strip()
    keys: dict[str, str] = {}
    for f, envs in _ENGINE_KEY_ENV.items():
        for e in envs:
            v = (os.environ.get(e) or "").strip()
            if v:
                keys[f] = v
                break
    return SearchConfig(
        gemini_api_key=key,
        gemini_key_source="env" if key else "none",
        search_model=(os.environ.get("GEMINI_SEARCH_MODEL", "")
                      or os.environ.get("VERTEX_SEARCH_MODEL", "")).strip(),
        synth_model=(os.environ.get("GEMINI_SYNTH_MODEL", "") or "").strip(),
        engine_keys=keys,
        source="env",
    )


def _merge_env_floor(cfg: SearchConfig) -> SearchConfig:
    """Fill anything the DB left blank from the env, so an operator can still
    rescue search by setting a container var."""
    env = _env_config()
    if not cfg.gemini_api_key and env.gemini_api_key:
        cfg.gemini_api_key = env.gemini_api_key
        cfg.gemini_key_source = "env"
    cfg.search_model = cfg.search_model or env.search_model
    cfg.synth_model = cfg.synth_model or env.synth_model
    for f, v in env.engine_keys.items():
        if not (cfg.engine_keys.get(f) or "").strip():
            cfg.engine_keys[f] = v
    return cfg


def _parse(payload: dict) -> SearchConfig:
    def _int(v):
        try:
            return int(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    provs = payload.get("providers")
    keys = payload.get("engine_keys")
    return SearchConfig(
        gemini_api_key=str(payload.get("gemini_api_key") or "").strip(),
        gemini_key_source=str(payload.get("gemini_key_source") or "none"),
        gemini_credential_user_id=str(payload.get("gemini_credential_user_id") or ""),
        search_model=str(payload.get("search_model") or "").strip(),
        synth_model=str(payload.get("synth_model") or "").strip(),
        depth=str(payload.get("depth") or "").strip(),
        rounds=_int(payload.get("rounds")),
        num_results=_int(payload.get("num_results")),
        fetch_sources=_int(payload.get("fetch_sources")),
        providers={str(k): bool(v) for k, v in (provs or {}).items()}
        if isinstance(provs, dict) else {},
        engine_keys={
            str(k): str(v).strip()
            for k, v in (keys or {}).items()
            if k in _ENGINE_KEY_FIELDS and str(v or "").strip()
        } if isinstance(keys, dict) else {},
        source="db",
    )


# user_id -> (expires_at, SearchConfig)
_cache: dict[str, tuple[float, SearchConfig]] = {}
_cache_lock = asyncio.Lock()


async def resolve_search_config(user_id: str = "", *, refresh: bool = False) -> SearchConfig:
    """Resolve the effective search config for ``user_id``. Never raises.

    ``user_id`` may be an email or a uuid (whatever the caller's request context
    carries); "" resolves the fleet-global row plus the owner/system credential.
    """
    uid = (user_id or "").strip()
    now = time.time()
    if not refresh:
        hit = _cache.get(uid)
        if hit and hit[0] > now:
            return hit[1]

    secret = _internal_secret()
    if not secret:
        cfg = _env_config()
        cfg.error = "VEILGUARD_INTERNAL_SECRET unset — cannot read search settings"
        async with _cache_lock:
            _cache[uid] = (now + _TTL_S, cfg)
        return cfg

    url = (
        f"{_cc_base_url()}/api/llm/internal/search-settings/"
        f"{quote(uid or '-', safe='')}"
    )
    cfg: SearchConfig | None = None
    last_err = ""
    # One retry: Command Centre runs `next dev` in this deployment, so the very
    # first hit after a restart can land on a route that is still compiling.
    for attempt, tmo in ((1, 6.0), (2, 15.0)):
        try:
            async with httpx.AsyncClient(timeout=tmo) as client:
                r = await client.get(url, headers={"x-internal-secret": secret})
        except Exception as e:  # transport — retry once, then fall back to env
            last_err = f"{type(e).__name__}: {e}"
            continue
        try:
            body = r.json()
        except Exception:
            body = None
        if not isinstance(body, dict) or r.status_code >= 500:
            last_err = f"HTTP {r.status_code}, non-JSON or server error"
            if attempt == 1:
                continue
            break
        if r.status_code != 200:
            last_err = f"HTTP {r.status_code}: {str(body.get('error'))[:120]}"
            break
        cfg = _parse(body)
        break

    if cfg is None:
        cfg = _env_config()
        cfg.error = f"search settings unreachable ({last_err})"
    cfg = _merge_env_floor(cfg)
    async with _cache_lock:
        _cache[uid] = (now + _TTL_S, cfg)
    return cfg


def invalidate_cache() -> None:
    """Drop the memo (used by tests and after a settings save)."""
    _cache.clear()


__all__ = [
    "SearchConfig",
    "resolve_search_config",
    "invalidate_cache",
]
