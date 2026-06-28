"""Unit tests for resilience.py — runnable without pytest:  py tooling/test_resilience.py

Deterministic: sleep, jitter, and the breaker clock are all injected, so no real
time passes and the backoff schedule is exact.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import resilience as R

_passed = 0
_failed = 0


def check(name: str, cond: bool) -> None:
    global _passed, _failed
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    _passed += int(bool(cond))
    _failed += int(not cond)


class FakeResp:
    def __init__(self, status, headers=None):
        self.status_code = status
        self.headers = headers or {}


class Timeout(Exception):       # name in RETRIABLE_EXC_NAMES
    pass


class AuthError(Exception):     # terminal
    pass


def raiser(exc):
    def f():
        raise exc
    return f


def sequence(items):
    """Return a fn that yields items[0], items[1], ... on successive calls."""
    state = {"i": 0}

    def f():
        v = items[state["i"]]
        state["i"] += 1
        return v
    return f, state


# --- classification -------------------------------------------------------
check("status 200 -> success", R.classify_status(200) == R.SUCCESS)
check("status 301 -> success", R.classify_status(301) == R.SUCCESS)
check("status 429 -> retriable", R.classify_status(429) == R.RETRIABLE)
check("status 503 -> retriable", R.classify_status(503) == R.RETRIABLE)
check("status 400 -> terminal", R.classify_status(400) == R.TERMINAL)
check("status 401 -> terminal", R.classify_status(401) == R.TERMINAL)
check("status None -> success", R.classify_status(None) == R.SUCCESS)
check("Timeout exc -> retriable", R.classify_exception(Timeout()) == R.RETRIABLE)
check("ConnectionResetError -> retriable",
      R.classify_exception(ConnectionResetError()) == R.RETRIABLE)
check("ValueError -> terminal", R.classify_exception(ValueError()) == R.TERMINAL)
check("Retry-After header parsed",
      R.retry_after_of(FakeResp(429, {"Retry-After": "5"})) == 5.0)
_e = Timeout()
_e.retry_after = 3
check("Retry-After exc attr parsed", R.retry_after_of(_e) == 3.0)
check("no Retry-After -> None", R.retry_after_of(FakeResp(200)) is None)

# --- backoff schedule (jitter off => exact) -------------------------------
_p = R.RetryPolicy(base_delay=0.5, backoff_factor=2.0, max_delay=10.0, jitter=False)
check("backoff exponential", [_p.backoff(n) for n in (1, 2, 3)] == [0.5, 1.0, 2.0])
check("backoff capped at max_delay", _p.backoff(6) == 10.0)

# --- retry on retriable exception, then success ---------------------------
slept = []
calls = {"n": 0}


def flaky_then_ok():
    calls["n"] += 1
    if calls["n"] < 3:
        raise Timeout("transient")
    return FakeResp(200)


p = R.RetryPolicy(max_attempts=3, base_delay=0.5, jitter=False, sleep=slept.append)
r = p.run(flaky_then_ok)
check("retries transient exc then succeeds",
      r.status_code == 200 and calls["n"] == 3 and slept == [0.5, 1.0])

# --- terminal exception is NOT retried ------------------------------------
calls2 = {"n": 0}


def always_auth_error():
    calls2["n"] += 1
    raise AuthError("bad key")


p = R.RetryPolicy(max_attempts=4, sleep=lambda d: None)
try:
    p.run(always_auth_error)
    _raised = False
except AuthError:
    _raised = True
check("terminal exc not retried, re-raised", _raised and calls2["n"] == 1)

# --- retriable RESULT (429) retried then 200 ------------------------------
fn, st = sequence([FakeResp(429), FakeResp(429), FakeResp(200)])
slept2 = []
p = R.RetryPolicy(max_attempts=3, base_delay=0.5, jitter=False, sleep=slept2.append)
r = p.run(fn)
check("retries 429 result then 200",
      r.status_code == 200 and st["i"] == 3 and slept2 == [0.5, 1.0])

# --- Retry-After from result honoured -------------------------------------
fn, _ = sequence([FakeResp(429, {"Retry-After": "7"}), FakeResp(200)])
slept3 = []
p = R.RetryPolicy(max_attempts=3, base_delay=0.5, jitter=False, sleep=slept3.append,
                  respect_retry_after=True)
p.run(fn)
check("Retry-After overrides backoff", slept3 == [7.0])

# --- retriable result, attempts exhausted -> return last (no raise) --------
calls3 = {"n": 0}


def always_503():
    calls3["n"] += 1
    return FakeResp(503)


p = R.RetryPolicy(max_attempts=2, jitter=False, sleep=lambda d: None)
r = p.run(always_503)
check("exhausted retriable result returns last", r.status_code == 503 and calls3["n"] == 2)

# --- all attempts raise -> original exception re-raised --------------------
calls4 = {"n": 0}


def always_timeout():
    calls4["n"] += 1
    raise Timeout("down")


p = R.RetryPolicy(max_attempts=2, sleep=lambda d: None)
try:
    p.run(always_timeout)
    _raised = False
except Timeout:
    _raised = True
check("exhausted exceptions re-raise original", _raised and calls4["n"] == 2)

# --- circuit breaker state machine ----------------------------------------
clock = {"t": 1000.0}


def now():
    return clock["t"]


cb = R.CircuitBreaker(failure_threshold=3, reset_timeout=30.0, half_open_max=1, now=now)
check("breaker starts closed", cb.state == R.CLOSED and cb.allow())
cb.record_failure()
cb.record_failure()
check("below threshold stays closed", cb.state == R.CLOSED)
cb.record_failure()
check("threshold reached -> open, rejects", cb.state == R.OPEN and not cb.allow())
clock["t"] += 31
check("after reset_timeout -> half_open", cb.state == R.HALF_OPEN)
check("half_open admits one trial", cb.allow())
check("half_open blocks beyond max", not cb.allow())
cb.record_success()
check("success in half_open closes", cb.state == R.CLOSED and cb.allow())

# half-open failure immediately re-opens
clock2 = {"t": 0.0}
cb2 = R.CircuitBreaker(failure_threshold=1, reset_timeout=10.0, now=lambda: clock2["t"])
cb2.record_failure()
check("threshold-1 opens immediately", cb2.state == R.OPEN)
clock2["t"] += 11
check("re-enters half_open", cb2.state == R.HALF_OPEN)
cb2.allow()
cb2.record_failure()
check("failure in half_open re-opens", cb2.state == R.OPEN)

# --- breaker.call ----------------------------------------------------------
cb3 = R.CircuitBreaker(failure_threshold=1, reset_timeout=10.0, now=lambda: 0.0)
check("call success returns result",
      cb3.call(lambda: FakeResp(200)).status_code == 200)
try:
    cb3.call(raiser(Timeout("x")))
except Timeout:
    pass
check("call exception trips breaker", cb3.state == R.OPEN)
try:
    cb3.call(lambda: FakeResp(200))
    _opened = False
except R.CircuitOpenError:
    _opened = True
check("open breaker rejects call", _opened)

# --- guarded_call ----------------------------------------------------------
cbg = R.CircuitBreaker(failure_threshold=5, now=lambda: 0.0)
pg = R.RetryPolicy(max_attempts=2, jitter=False, sleep=lambda d: None)
check("guarded_call success", R.guarded_call(lambda: FakeResp(200),
                                             breaker=cbg, retry=pg).status_code == 200)
cb_open = R.CircuitBreaker(failure_threshold=1, now=lambda: 0.0)
cb_open.record_failure()
try:
    R.guarded_call(lambda: FakeResp(200), breaker=cb_open, retry=pg)
    _opened = False
except R.CircuitOpenError:
    _opened = True
check("guarded_call respects open breaker", _opened)


print(f"\n{_passed} passed, {_failed} failed")
sys.exit(0 if _failed == 0 else 1)
