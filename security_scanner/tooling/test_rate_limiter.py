"""Unit tests for redis_support.FakeRedis + rate_limiter (WS5a).
py tooling/test_rate_limiter.py  (offline; uses FakeRedis)
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import redis_support as rs
from redis_support import FakeRedis
import rate_limiter as rl

_p = _f = 0
def check(n, c):
    global _p, _f
    print(f"  {'PASS' if c else 'FAIL'}  {n}")
    _p += 1 if c else 0
    _f += 0 if c else 1


# --- FakeRedis basics -----------------------------------------------------
r = FakeRedis()
r.set("a", "1"); check("set/get", r.get("a") == "1")
check("set nx on existing returns None", r.set("a", "2", nx=True) is None and r.get("a") == "1")
check("set nx on new returns True", r.set("b", "x", nx=True) is True)
check("delete", r.delete("b") == 1 and r.get("b") is None)
check("incr", r.incr("c") == 1 and r.incr("c", 2) == 3)
import time as _t
r.set("ttl", "1", px=10)
check("px expiry", r.get("ttl") == "1")
_t.sleep(0.02)
check("px expired", r.get("ttl") is None)


# --- RedisRateLimiter token bucket (injected clock/sleep) -----------------
clk = [1000.0]
slept = []
def now():
    return clk[0]
def sleep(s):
    slept.append(round(s, 4))
    clk[0] += s

bucket_r = FakeRedis()
limiter = rl.RedisRateLimiter(bucket_r, rate=2.0, burst=3, namespace="t",
                              now=now, sleep=sleep)
w = [limiter.acquire("k") for _ in range(3)]
check("burst of 3 -> no wait", w == [0.0, 0.0, 0.0])
w4 = limiter.acquire("k")
check("over-budget acquire waits 1/rate (0.5s)", w4 == 0.5 and 0.5 in slept)
clk[0] += 2.0  # idle 2s -> bucket refills
w5 = limiter.acquire("k")
check("after idle, acquire is free again", w5 == 0.0)
check("empty key -> no wait", limiter.acquire("") == 0.0)
check("stats reports redis backend", limiter.stats("k")["backend"] == "redis")


# --- factory selection ----------------------------------------------------
rs.reset_for_tests(FakeRedis())
made = rl.make_rate_limiter(2.0, 5, "apex")
check("make_rate_limiter -> Redis when client present",
      isinstance(made, rl.RedisRateLimiter))
check("maybe_redis_limiter -> limiter when client present",
      rl.maybe_redis_limiter() is not None)

rs.reset_for_tests(None)  # no redis
made2 = rl.make_rate_limiter(2.0, 5, "apex")
check("make_rate_limiter -> in-process DomainRateLimiter when no redis",
      type(made2).__name__ == "DomainRateLimiter")
check("maybe_redis_limiter -> None when no redis", rl.maybe_redis_limiter() is None)

rs.reset_for_tests(None)  # leave clean
print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
