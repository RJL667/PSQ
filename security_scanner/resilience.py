"""Retry + circuit-breaker toolkit (WS7 foundation).

Pure stdlib, dependency-light, fully unit-tested. **Not yet wired into anything**
— this is the building block the scaling design's WS7 / SCALE-09 calls for, to be
mounted inside the per-provider client wrappers (WS0b) once the egress seam exists
(see docs/SCALING_DESIGN.md). Importing this module changes no runtime behaviour.

Provides:
  * `classify_status` / `classify_exception` — the retriable-vs-terminal split
    the design specifies (timeout / conn-reset / 429 / 5xx retriable; 4xx auth
    terminal).
  * `RetryPolicy` — exponential backoff + jitter, capped attempts, honours
    `Retry-After`. Time/sleep/rng are injectable for deterministic tests.
  * `CircuitBreaker` — per-key CLOSED/OPEN/HALF_OPEN breaker so a dead provider
    trips out instead of dragging every scan. Thread-safe; clock injectable.
    (In-process for now; the shared/distributed version rides on the WS5 Redis
    ledger later.)
  * `guarded_call` — composes a breaker + a retry policy around one call.

Design note: `RetryPolicy.run` returns the *last* result (so a terminal HTTP 4xx
or an exhausted-retries response flows back to the caller to inspect) and
re-raises the last *exception* only when every attempt raised.
"""
from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

# --- outcomes -------------------------------------------------------------
SUCCESS = "success"
RETRIABLE = "retriable"
TERMINAL = "terminal"

# Per the design: 429 + transient 5xx are worth retrying; everything else 4xx is
# a terminal client error (bad request / auth) that retrying cannot fix.
RETRIABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})

# Matched against the exception's full MRO by class name, so we don't have to
# hard-import `requests` here (keeps the toolkit dependency-light and testable).
RETRIABLE_EXC_NAMES = frozenset({
    "Timeout", "ConnectTimeout", "ReadTimeout", "ConnectionError",
    "ConnectionResetError", "ChunkedEncodingError", "ProxyError",
    "RemoteDisconnected", "IncompleteRead",
})


def classify_status(code: Optional[int]) -> str:
    if code is None:
        return SUCCESS
    if 200 <= code < 400:
        return SUCCESS
    if code in RETRIABLE_STATUS:
        return RETRIABLE
    return TERMINAL


def classify_exception(exc: BaseException) -> str:
    names = {c.__name__ for c in type(exc).__mro__}
    return RETRIABLE if names & RETRIABLE_EXC_NAMES else TERMINAL


def classify_response(resp) -> str:
    """Classify a duck-typed HTTP response (anything with `.status_code`)."""
    return classify_status(getattr(resp, "status_code", None))


def retry_after_of(obj) -> Optional[float]:
    """Pull a Retry-After hint from a response's headers or an exception attr."""
    headers = getattr(obj, "headers", None)
    if headers:
        raw = None
        try:
            raw = headers.get("Retry-After") or headers.get("retry-after")
        except Exception:
            raw = None
        if raw is not None:
            try:
                return float(raw)            # delta-seconds form
            except (TypeError, ValueError):
                return None                  # HTTP-date form: ignored, use backoff
    ra = getattr(obj, "retry_after", None)
    if ra is not None:
        try:
            return float(ra)
        except (TypeError, ValueError):
            return None
    return None


# --- retry ----------------------------------------------------------------
@dataclass
class RetryPolicy:
    max_attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 30.0
    backoff_factor: float = 2.0
    jitter: bool = True
    respect_retry_after: bool = True
    # injectables (overridden in tests for determinism)
    sleep: Callable[[float], None] = time.sleep
    rng: random.Random = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.rng is None:
            self.rng = random.Random()

    def backoff(self, attempt: int) -> float:
        """Delay (seconds) before retry `attempt` (1-based: attempt 1 is the
        wait *after* the first failure). Equal-jitter over the capped backoff."""
        raw = self.base_delay * (self.backoff_factor ** (attempt - 1))
        capped = min(self.max_delay, raw)
        if not self.jitter:
            return capped
        half = capped / 2.0
        return half + self.rng.uniform(0.0, half)

    def _wait(self, attempt: int, retry_after: Optional[float]) -> float:
        if self.respect_retry_after and retry_after is not None:
            delay = min(self.max_delay, max(0.0, retry_after))
        else:
            delay = self.backoff(attempt)
        self.sleep(delay)
        return delay

    def run(self, fn: Callable[[], object], *,
            classify_result: Callable[[object], str] = classify_response,
            on_retry: Optional[Callable[[int, str, object], None]] = None) -> object:
        """Call `fn` with retries. `classify_result` maps a returned value to an
        outcome (default: HTTP-status based). Returns the last result (so a
        terminal 4xx or a retry-exhausted response flows back for inspection);
        re-raises the original exception if the final attempt raised."""
        for attempt in range(1, self.max_attempts + 1):
            try:
                result = fn()
            except Exception as exc:  # noqa: BLE001 — we classify, then re-raise
                if classify_exception(exc) == RETRIABLE and attempt < self.max_attempts:
                    if on_retry:
                        on_retry(attempt, RETRIABLE, exc)
                    self._wait(attempt, retry_after_of(exc))
                    continue
                raise
            outcome = classify_result(result)
            if outcome == RETRIABLE and attempt < self.max_attempts:
                if on_retry:
                    on_retry(attempt, RETRIABLE, result)
                self._wait(attempt, retry_after_of(result) if self.respect_retry_after else None)
                continue
            return result


# --- circuit breaker ------------------------------------------------------
CLOSED, OPEN, HALF_OPEN = "closed", "open", "half_open"


class CircuitOpenError(Exception):
    """Raised by `CircuitBreaker.call` when the circuit is open."""


class CircuitBreaker:
    """Per-key breaker. Opens after `failure_threshold` consecutive failures;
    after `reset_timeout` it admits up to `half_open_max` trial calls — a success
    closes it, a failure re-opens it. Thread-safe; `now` injectable for tests."""

    def __init__(self, failure_threshold: int = 5, reset_timeout: float = 30.0,
                 half_open_max: int = 1, now: Callable[[], float] = time.monotonic,
                 name: str = "breaker"):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_max = half_open_max
        self._now = now
        self.name = name
        self._state = CLOSED
        self._failures = 0
        self._opened_at: Optional[float] = None
        self._half_open_calls = 0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            return self._resolve_state()

    def _resolve_state(self) -> str:
        if self._state == OPEN and self._opened_at is not None \
                and (self._now() - self._opened_at) >= self.reset_timeout:
            self._state = HALF_OPEN
            self._half_open_calls = 0
        return self._state

    def allow(self) -> bool:
        with self._lock:
            state = self._resolve_state()
            if state == CLOSED:
                return True
            if state == HALF_OPEN and self._half_open_calls < self.half_open_max:
                self._half_open_calls += 1
                return True
            return False

    def record_success(self) -> None:
        with self._lock:
            self._state = CLOSED
            self._failures = 0
            self._opened_at = None
            self._half_open_calls = 0

    def record_failure(self) -> None:
        with self._lock:
            if self._state == HALF_OPEN:
                self._trip()
                return
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._trip()

    def _trip(self) -> None:
        self._state = OPEN
        self._opened_at = self._now()
        self._half_open_calls = 0

    def call(self, fn: Callable[[], object]) -> object:
        if not self.allow():
            raise CircuitOpenError(f"{self.name}: circuit open")
        try:
            result = fn()
        except Exception:
            self.record_failure()
            raise
        self.record_failure() if classify_response(result) == RETRIABLE else self.record_success()
        return result


def guarded_call(fn: Callable[[], object], *, breaker: CircuitBreaker,
                 retry: RetryPolicy,
                 classify_result: Callable[[object], str] = classify_response) -> object:
    """Compose a breaker around a retry loop: the breaker gates admission and
    sees the final outcome; the retry policy handles transient failures within
    one admitted attempt-sequence."""
    if not breaker.allow():
        raise CircuitOpenError(f"{breaker.name}: circuit open")
    try:
        result = retry.run(fn, classify_result=classify_result)
    except Exception:
        breaker.record_failure()
        raise
    breaker.record_failure() if classify_result(result) == RETRIABLE else breaker.record_success()
    return result
