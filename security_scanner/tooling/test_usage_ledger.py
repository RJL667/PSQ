"""Unit tests for usage_ledger + its wiring into ProviderClient (WS7).
Runnable without pytest:  py tooling/test_usage_ledger.py

Offline. Proves the ledger's kill-switch / spend / retry-budget guards, and that a
ledger-wired ProviderClient honours them: skips calls when the daily cap is hit,
meters every attempt, and stops retrying when the retry budget is exhausted.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import requests
import provider_client as pc
from usage_ledger import InMemoryUsageLedger
from resilience import RetryPolicy, CircuitBreaker

_passed = 0
_failed = 0


def check(name: str, cond: bool) -> None:
    global _passed, _failed
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if cond:
        _passed += 1
    else:
        _failed += 1


class _Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


# --- ledger unit ----------------------------------------------------------
clk = _Clock()
led = InMemoryUsageLedger(default_daily_cap=None,
                          daily_caps={"paid": 2}, retry_cap_per_window=2,
                          retry_window_seconds=300, now=clk)

check("uncapped provider always allowed", led.allow_call("free") and led.allow_call("free"))

check("capped provider allowed under cap", led.allow_call("paid"))
led.record_call("paid")
check("spend_today tracks", led.spend_today("paid") == 1)
led.record_call("paid")
check("kill-switch trips at cap", led.allow_call("paid") is False)

check("retry budget allows up to cap",
      led.allow_retry("x") and led.allow_retry("x"))
check("retry budget denies past cap", led.allow_retry("x") is False)
clk.t += 301  # next window
check("retry budget resets in a new window", led.allow_retry("x") is True)

clk.t += 86400  # next day
check("daily spend resets next day", led.allow_call("paid") is True
      and led.spend_today("paid") == 0)


# --- ledger-wired client --------------------------------------------------
def _resp(status):
    r = requests.models.Response()
    r.status_code = status
    r._content = b"{}"
    r._content_consumed = True
    r.url = "https://api.x/y"
    r.encoding = "utf-8"
    r.headers = requests.structures.CaseInsensitiveDict()
    return r


class FakeTransport:
    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def __call__(self, method, url, **kwargs):
        self.calls += 1
        item = self.script.pop(0) if self.script else 200
        return _resp(item)


_orig = requests.request
try:
    # kill-switch: cap=1 -> first call goes, second is skipped (None) w/o calling out
    fake = FakeTransport([200, 200])
    requests.request = fake
    led2 = InMemoryUsageLedger(daily_caps={"p": 1})
    client = pc.ProviderClient("p", rate=100, burst=100, ledger=led2,
                               retry=RetryPolicy(max_attempts=1))
    r1 = client.get("https://api.x/y")
    r2 = client.get("https://api.x/y")
    check("ledger kill-switch: 1st call made, 2nd skipped",
          r1 is not None and r2 is None and fake.calls == 1)
    check("ledger metered the made call", led2.spend_today("p") == 1)

    # retry budget exhausted -> no retry even on retriable status
    fake = FakeTransport([503, 503, 200])
    requests.request = fake
    led3 = InMemoryUsageLedger(retry_cap_per_window=0)
    client = pc.ProviderClient("p", rate=100, burst=100, ledger=led3,
                               retry=RetryPolicy(max_attempts=3, sleep=lambda _: None))
    r = client.get("https://api.x/y")
    check("retry budget 0 -> no retry (1 call, returns the 503)",
          r is not None and r.status_code == 503 and fake.calls == 1)

    # retry budget available -> retries through to success, metering each attempt
    fake = FakeTransport([503, 503, 200])
    requests.request = fake
    led4 = InMemoryUsageLedger(retry_cap_per_window=10)
    client = pc.ProviderClient("p", rate=100, burst=100, ledger=led4,
                               retry=RetryPolicy(max_attempts=3, sleep=lambda _: None))
    r = client.get("https://api.x/y")
    check("retry budget available -> retries to success (3 calls)",
          r.status_code == 200 and fake.calls == 3)
    check("ledger metered all 3 attempts", led4.spend_today("p") == 3)

finally:
    requests.request = _orig

print(f"\n{_passed} passed, {_failed} failed")
sys.exit(1 if _failed else 0)
