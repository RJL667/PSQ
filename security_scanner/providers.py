"""Central registry of per-provider egress clients (WS0).

One `ProviderClient` per external provider, so every paid/quota'd call routes
through a single controllable seam instead of a bare `requests.*`. Checkers import
the client they need (`from providers import SHODAN`) and call `SHODAN.get(...)`.

Current stance — *seam established, resilience + metering ON* (WS0 routing with
WS6b/WS7/WS9 now activated; see `_client` below). NOTE: only the success path is
covered by the record/replay regression gates — the failure-path behaviour below is
live but exercised by the non-200 cassettes added under tooling/regression:
  * **Retry ON** (`max_attempts=3`, exp backoff + jitter) for transient failures.
    Checkers that own an outer retry loop (crt.sh, OSV / IntelX polling) keep their
    own semantics; the success path is unchanged (a healthy first-try 2xx never
    retries), which is why the migration gates stay green.
  * **Circuit breaker ON** (`failure_threshold=5`) — after sustained failure a
    provider returns `None` with no network call, so the scan degrades (checker
    marked skipped, scoring redistributes) instead of stalling. A breaker can trip
    mid-loop (e.g. per-CVE NVD enrichment), zeroing the remaining enrichment.
  * **Usage ledger ON** — per-provider daily caps + a retry budget bound an outage
    so it can't retry-storm into rate limits or paid cost. In-process today; the
    distributed (Redis counters mirrored to a Postgres `usage` table) version swaps
    in via the same interface.
  * **Result cache slot** — `make_result_cache()`: Redis single-flight when
    `REDIS_URL` is set, no-op single-box by default (keeps the gates deterministic).
  * **Per-provider pacing bucket** — politeness only; WS5a tightens it into the
    distributed quota bucket.

`ProviderClient.request` returns a `requests.Response` (incl. terminal 4xx/5xx,
which the caller still inspects) or `None` when all attempts fail / the breaker is
open — i.e. exactly the cases the old `try/except` around `requests.*` handled.
Migrated call sites map `None` to their existing failure path.
"""
from __future__ import annotations

import os

from provider_client import ProviderClient
from resilience import CircuitBreaker, RetryPolicy
from usage_ledger import InMemoryUsageLedger
from result_cache import make_result_cache

# WS6b: one shared result cache (Redis single-flight when REDIS_URL is set; None
# single-box by default — see make_result_cache).
_CACHE = make_result_cache()

# WS7 is now ON: clients retry transient failures, trip a breaker on sustained
# failure (-> checker marked skipped, scoring redistributes), and are bounded by a
# shared usage ledger so an outage can't retry-storm into rate limits / paid cost.
#
# The ledger is in-process (single-box scanner). The distributed version swaps in
# with the same interface: Redis counters (provider+day / provider+window) mirrored
# to a Postgres `usage` table (SCALE-17/18). Daily caps below are conservative
# placeholders — tune against real quotas. Free providers are uncapped.
class DurableUsageLedger(InMemoryUsageLedger):
    """Daily caps that survive a restart, and that know the real quotas.

    The in-process ledger was decorative on this deployment for two reasons, both
    found on 2026-07-28:

      * the caps were placeholders an order of magnitude above the real quota —
        1000/day for IntelX against a free tier of 50/day, so the guard could
        never fire before the provider did; and
      * the counters live in memory, so every deploy handed the box a fresh
        allowance it did not have.

    The durable `usage` table already recorded every call (``record_usage``) —
    it simply had no reader. This consults it, cached for a minute to keep it off
    the hot path, and adds the calls made SINCE that snapshot.

    The delta matters: taking max(durable, in-process) looks equivalent and is
    not. With a cached durable count of 48 and two fresh calls, max() still reads
    48 and hands out an allowance that was already spent — the cap then overruns
    by up to one TTL's worth of calls. Anchoring to the in-process counter at
    fetch time and adding the difference counts each call exactly once.
    """

    def __init__(self, *args, db_ttl_s: float = 60.0, **kw):
        super().__init__(*args, **kw)
        self._db_ttl = db_ttl_s
        self._db_cache: dict = {}     # provider -> (fetched_at, durable, inmem_at_fetch)

    def _durable_spend(self, provider: str) -> int:
        try:
            import scanner_db
            return int(scanner_db.usage_for(provider))
        except Exception:
            return 0                   # never let metering block a scan

    def spend_today(self, provider: str) -> int:
        import time as _t
        inmem = super().spend_today(provider)
        hit = self._db_cache.get(provider)
        if not hit or (_t.time() - hit[0]) >= self._db_ttl:
            hit = (_t.time(), self._durable_spend(provider), inmem)
            self._db_cache[provider] = hit
        _, durable, inmem_at_fetch = hit
        # durable already includes everything up to the snapshot; add only what
        # this process has spent since.
        return durable + max(0, inmem - inmem_at_fetch)

    def allow_call(self, provider: str) -> bool:
        cap = self._cap_for(provider)
        if cap is None:
            return True
        return self.spend_today(provider) < cap

    def remaining(self, provider: str):
        """Calls left today, or None when the provider is uncapped."""
        cap = self._cap_for(provider)
        if cap is None:
            return None
        return max(0, cap - self.spend_today(provider))

    def caps(self) -> dict:
        return dict(self._daily_caps)


def _cap(env: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(env, "").strip() or default))
    except ValueError:
        return default


# Real quotas, env-tunable so a plan change needs no deploy.
# NOTE THE UNIT: this ledger counts HTTP CALLS, not searches. Measured on a live
# scan 2026-07-28: one scan spends 1 dehashed call but FOUR intelx calls (1
# search-initiate + up to 3 result polls). A cap expressed in searches would
# therefore throttle at a quarter of the real quota, so these are call budgets.
#   intelx   — free tier is 50 SEARCHES/day (reset midnight UTC), i.e. up to 200
#              calls. Deliberately the loose direction: firing EARLY would mark
#              dark-web sections unassessed while quota remained, whereas real
#              exhaustion is now honest and visible on its own.
#   dehashed — a credit POOL rather than a daily allowance, so this cap is a
#              burn-rate limit: it stops a runaway loop draining the balance in
#              an afternoon, it is not the balance itself. 1 call per scan.
# The exact fix for intelx is its FREE /authenticate/info balance endpoint, which
# reports remaining searches authoritatively; see OUTSTANDING.
_LEDGER = DurableUsageLedger(
    default_daily_cap=None,
    daily_caps={
        "shodan": 1000, "hibp": 1000,
        "dehashed": _cap("DEHASHED_DAILY_CAP", 150),
        "intelx": _cap("INTELX_DAILY_CAP", 200),
        "securitytrails": 2000, "virustotal": 500, "snusbase": 2000,
        "leakcheck": 2000, "whiteintel": 500,
    },
    retry_cap_per_window=50,
    retry_window_seconds=300,
)

# Metered providers whose remaining budget is worth reporting to an operator.
METERED = ("dehashed", "intelx")


def budget_report() -> dict:
    """Per-provider {used, cap, remaining} for the readiness probe."""
    out = {}
    for name in METERED:
        cap = _LEDGER.caps().get(name)
        out[name] = {"used": _LEDGER.spend_today(name), "cap": cap,
                     "remaining": _LEDGER.remaining(name)}
    return out


def _client(name: str, *, rate: float = 5.0, burst: int = 10,
            default_timeout: float = 15.0, max_attempts: int = 3,
            failure_threshold: int = 5, reset_timeout: float = 60.0) -> ProviderClient:
    """A WS7 client: route + pace + retry (exp backoff/jitter) + per-provider
    breaker + ledger-enforced budget. Success path is unchanged from WS0 (no
    retry/trip on a healthy 2xx), so the migration gates stay green."""
    return ProviderClient(
        name, rate=rate, burst=burst, default_timeout=default_timeout,
        retry=RetryPolicy(max_attempts=max_attempts),
        breaker=CircuitBreaker(failure_threshold=failure_threshold,
                               reset_timeout=reset_timeout, name=name),
        ledger=_LEDGER,
        cache=_CACHE,
        on_call=_record_call,   # WS9: per-provider Prometheus counter (credit burn)
    )


def _record_call(provider, method=""):
    # WS9 metric + WS10/SCALE-17 durable usage mirror (Redis counters are a cache of
    # this). Both best-effort — metering must never break a provider call.
    try:
        from observability import record_provider_call
        record_provider_call(provider, method)
    except Exception:
        pass
    try:
        import scanner_db
        scanner_db.record_usage(provider)
    except Exception:
        pass


# Backwards-compatible alias (WS0 call sites built clients via _ws0).
_ws0 = _client


# --- paid / quota'd providers --------------------------------------------
SHODAN = _ws0("shodan")                 # api.shodan.io (host + cert search/count)
HIBP = _ws0("hibp")                     # haveibeenpwned.com (breach + metadata)
DEHASHED = _ws0("dehashed", default_timeout=30.0)
INTELX = _ws0("intelx")                 # free.intelx.io (search initiate + poll)
SECURITYTRAILS = _ws0("securitytrails")
VIRUSTOTAL = _ws0("virustotal")
SNUSBASE = _ws0("snusbase")
LEAKCHECK = _ws0("leakcheck")
WHITEINTEL = _ws0("whiteintel")

# --- free / unauthenticated providers ------------------------------------
CRTSH = _ws0("crtsh", default_timeout=30.0)   # crt.sh (CT logs — primary, but flaky)
CERTSPOTTER = _ws0("certspotter", default_timeout=30.0)  # api.certspotter.com CT logs
                                              # (keyless free tier) — secondary CT
                                              # source so subdomain enumeration
                                              # doesn't collapse to brute-only when
                                              # crt.sh flakes (the #7 non-determinism)
OSV = _ws0("osv")                       # api.osv.dev
NVD = _ws0("nvd")                       # services.nvd.nist.gov
EPSS = _ws0("epss")                     # api.first.org/data/v1/epss
EXPLOITDB = _ws0("exploitdb")           # gitlab.com/.../exploitdb CSV
MSF = _ws0("msf")                       # raw.githubusercontent metasploit modules
TRANCO = _ws0("tranco", default_timeout=30.0)
INTERNETDB = _ws0("internetdb")         # internetdb.shodan.io (free, != paid Shodan)
HUDSONROCK = _ws0("hudsonrock")         # cavalier.hudsonrock.com (free domain API)
KEV = _ws0("kev")                       # CISA Known Exploited Vulns catalog + mirror
