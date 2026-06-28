"""Scan lifecycle state machine (WS1 / SCALE-02).

Replaces the ad-hoc ``pending|completed|failed`` with an explicit lifecycle plus the
worker-tracking fields the job queue + heartbeat need:

    queued -> running -> completed | failed | cancelled
                running -> queued        (visibility-timeout requeue of a dead worker)

with ``started_at`` / ``attempts`` / ``worker_id`` / ``last_heartbeat``. The old
stale-scan hack becomes ``should_requeue`` (heartbeat older than the visibility
timeout) and poison-scan detection rides on ``attempts`` (WS7 DLQ). Pure logic, no
DB — `app.py`'s state column adopts these constants/transitions at the Postgres
cutover. **Imported by no runtime code yet.**
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

QUEUED = "queued"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
CANCELLED = "cancelled"

TERMINAL = frozenset({COMPLETED, FAILED, CANCELLED})

# Allowed transitions. running->queued is the visibility-timeout requeue.
_TRANSITIONS = {
    QUEUED:    frozenset({RUNNING, CANCELLED}),
    RUNNING:   frozenset({COMPLETED, FAILED, CANCELLED, QUEUED}),
    COMPLETED: frozenset(),
    FAILED:    frozenset({QUEUED}),          # manual/DLQ replay
    CANCELLED: frozenset(),
}


class InvalidTransition(ValueError):
    pass


def is_terminal(status: str) -> bool:
    return status in TERMINAL


def can_transition(current: str, target: str) -> bool:
    return target in _TRANSITIONS.get(current, frozenset())


def transition(current: str, target: str) -> str:
    if not can_transition(current, target):
        raise InvalidTransition(f"{current} -> {target} is not allowed")
    return target


@dataclass
class ScanState:
    """In-memory view of a scan's lifecycle row. The DB persists the same fields."""
    scan_id: str
    status: str = QUEUED
    attempts: int = 0
    worker_id: Optional[str] = None
    started_at: Optional[float] = None
    last_heartbeat: Optional[float] = None

    def start(self, worker_id: str, now: float) -> None:
        self.status = transition(self.status, RUNNING)
        self.worker_id = worker_id
        self.started_at = now
        self.last_heartbeat = now
        self.attempts += 1

    def heartbeat(self, now: float) -> None:
        if self.status != RUNNING:
            raise InvalidTransition(f"cannot heartbeat in state {self.status}")
        self.last_heartbeat = now

    def complete(self) -> None:
        self.status = transition(self.status, COMPLETED)

    def fail(self) -> None:
        self.status = transition(self.status, FAILED)

    def requeue(self) -> None:
        """Return a running scan to the queue (dead-worker recovery)."""
        self.status = transition(self.status, QUEUED)
        self.worker_id = None
        self.started_at = None
        self.last_heartbeat = None


def should_requeue(state: ScanState, now: float, visibility_timeout: float) -> bool:
    """A running scan whose heartbeat is older than the visibility timeout is
    presumed dead and should be requeued."""
    if state.status != RUNNING or state.last_heartbeat is None:
        return False
    return (now - state.last_heartbeat) > visibility_timeout


def is_poison(state: ScanState, max_attempts: int) -> bool:
    """N failed attempts -> route to the DLQ instead of requeueing forever (WS7)."""
    return state.attempts >= max_attempts
