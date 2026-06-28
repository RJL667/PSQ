"""Distributed rate limiting (WS5a / SCALE-04a).

The in-process `http_client.DomainRateLimiter` token bucket can't coordinate across
the gunicorn workers (`--workers 2`), so the per-apex politeness limit is ~2x its
configured value today and the per-provider quotas aren't shared at all. This adds
a **Redis-backed token bucket** with the same algorithm, shared across all workers.

Selection by ``REDIS_URL``: present -> `RedisRateLimiter` (shared); absent -> the
in-process `DomainRateLimiter` (unchanged single-box behaviour). Both expose
``acquire(key) -> slept_seconds``. The Redis bucket guards its read-modify-write
with a short per-key lock (correct across workers; ``time.sleep`` for the pacing
wait happens OUTSIDE the lock). Clock/sleep are injectable for deterministic tests.
"""
from __future__ import annotations

import json
import time
from typing import Callable

from redis_support import get_redis


class RedisRateLimiter:
    """Per-key token bucket in Redis. `rate` tokens/sec, capacity `burst`."""

    def __init__(self, redis, rate: float = 2.0, burst: int = 5,
                 namespace: str = "rl", now: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep):
        self.r = redis
        self.rate = float(rate)
        self.burst = int(burst)
        self.ns = namespace
        self._now = now
        self._sleep = sleep

    def acquire(self, key: str) -> float:
        if not key:
            return 0.0
        bkey = f"{self.ns}:bucket:{key}"
        lkey = f"{self.ns}:lock:{key}"
        # short lock so the read-modify-write is atomic across workers
        deadline = self._now() + 2.0
        got_lock = False
        while True:
            if self.r.set(lkey, "1", nx=True, px=1000):
                got_lock = True
                break
            if self._now() > deadline:
                break  # degraded: proceed without the lock rather than stall
            self._sleep(0.005)
        try:
            now = self._now()
            raw = self.r.get(bkey)
            if raw:
                b = json.loads(raw)
                tokens, ts = float(b["t"]), float(b["ts"])
            else:
                tokens, ts = float(self.burst), now
            tokens = min(float(self.burst), tokens + max(0.0, now - ts) * self.rate)
            if tokens >= 1.0:
                tokens -= 1.0
                wait, new_ts = 0.0, now
            else:
                wait = (1.0 - tokens) / self.rate
                tokens, new_ts = 0.0, now + wait
            self.r.set(bkey, json.dumps({"t": tokens, "ts": new_ts}), ex=3600)
        finally:
            if got_lock:
                self.r.delete(lkey)
        if wait > 0:
            self._sleep(wait)
        return wait

    def stats(self, key: str) -> dict:
        raw = self.r.get(f"{self.ns}:bucket:{key}")
        if not raw:
            return {"apex": key, "tokens": self.burst, "active": False, "backend": "redis"}
        b = json.loads(raw)
        return {"apex": key, "tokens": round(float(b["t"]), 2), "active": True,
                "backend": "redis"}


def make_rate_limiter(rate: float = 2.0, burst: int = 5, namespace: str = "rl"):
    """Redis limiter when REDIS_URL is set, else the in-process token bucket."""
    r = get_redis()
    if r is not None:
        return RedisRateLimiter(r, rate, burst, namespace)
    from http_client import DomainRateLimiter
    return DomainRateLimiter(rate=rate, burst=burst)


def maybe_redis_limiter(rate: float = 2.0, burst: int = 5, namespace: str = "rl"):
    """A RedisRateLimiter if REDIS_URL is set, else None (caller keeps its default)."""
    r = get_redis()
    return RedisRateLimiter(r, rate, burst, namespace) if r is not None else None
