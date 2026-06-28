"""Per-provider usage ledger — spend tracking, credit kill-switch, retry budget
(SCALE-17 / WS5b + WS7).

The scaling design makes a usage-counting store the prerequisite for *enabling*
retries: "No ledger ⇒ no enforceable retry budget" — without it, a provider outage
retry-storms into rate limits and paid-API cost. This is that store.

`InMemoryUsageLedger` is single-process (fine for the current one-box scanner). The
distributed version swaps in later with the **same interface**: Redis counters keyed
by `provider+day` for the kill-switch and `provider+window` for the retry budget,
each metered call also mirrored to an append-only Postgres `usage` table so the
Redis counters are a rebuildable cache, not the durable billing record (SCALE-18).

Three guards a client consults:
  * ``allow_call(provider)``  — WS5b kill-switch: False once daily spend hits the
    provider's cap (the call is skipped, not made).
  * ``record_call(provider)`` — count one metered outbound call (daily spend++).
  * ``allow_retry(provider)`` — WS7 retry budget: False once retries in the rolling
    window hit the cap; increments the retry counter when it returns True.

Caps are per-provider with a default; ``None`` daily cap == unlimited (free
providers). The clock is injectable for deterministic tests.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional

DAY_SECONDS = 86400


class UsageLedger:
    """Interface. Implementations decide where counters live (memory now, Redis +
    Postgres `usage` table later)."""

    def allow_call(self, provider: str) -> bool:
        raise NotImplementedError

    def record_call(self, provider: str) -> None:
        raise NotImplementedError

    def allow_retry(self, provider: str) -> bool:
        raise NotImplementedError

    def spend_today(self, provider: str) -> int:
        raise NotImplementedError


class InMemoryUsageLedger(UsageLedger):
    def __init__(self, *, default_daily_cap: Optional[int] = None,
                 daily_caps: Optional[dict] = None,
                 retry_cap_per_window: int = 50,
                 retry_window_seconds: int = 300,
                 now: Callable[[], float] = time.time):
        self._default_daily_cap = default_daily_cap
        self._daily_caps = dict(daily_caps or {})
        self._retry_cap = int(retry_cap_per_window)
        self._retry_window = int(retry_window_seconds)
        self._now = now
        self._spend: dict = {}   # (provider, day_index) -> count
        self._retries: dict = {}  # (provider, window_index) -> count
        self._lock = threading.Lock()

    # ---- helpers ---------------------------------------------------------
    def _day(self) -> int:
        return int(self._now() // DAY_SECONDS)

    def _window(self) -> int:
        return int(self._now() // self._retry_window)

    def _cap_for(self, provider: str) -> Optional[int]:
        return self._daily_caps.get(provider, self._default_daily_cap)

    # ---- guards ----------------------------------------------------------
    def allow_call(self, provider: str) -> bool:
        cap = self._cap_for(provider)
        if cap is None:
            return True
        with self._lock:
            return self._spend.get((provider, self._day()), 0) < cap

    def record_call(self, provider: str) -> None:
        with self._lock:
            key = (provider, self._day())
            self._spend[key] = self._spend.get(key, 0) + 1

    def allow_retry(self, provider: str) -> bool:
        with self._lock:
            key = (provider, self._window())
            used = self._retries.get(key, 0)
            if used >= self._retry_cap:
                return False
            self._retries[key] = used + 1
            return True

    # ---- introspection ---------------------------------------------------
    def spend_today(self, provider: str) -> int:
        with self._lock:
            return self._spend.get((provider, self._day()), 0)

    def snapshot(self) -> dict:
        """Current per-provider daily spend — for ops dashboards / tests."""
        day = self._day()
        with self._lock:
            return {p: c for (p, d), c in self._spend.items() if d == day and c}
