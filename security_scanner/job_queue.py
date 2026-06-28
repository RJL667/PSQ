"""Job queue + worker tier (WS2 / SCALE-05).

Replaces the fire-and-forget daemon thread in `POST /api/scan` with an enqueue +
worker model, and adds the system's first **submit-time admission control**: when
the queue is full, enqueue returns False and the API returns 429 (the in-process
semaphore never gave request-time backpressure — it bounded execution on the worker
thread and 202'd first).

Backends (factory by ``QUEUE_BACKEND`` / ``DATABASE_URL``):
  * ``InProcessJobQueue`` — default. A bounded `queue.Queue` drained by N worker
    threads in this process; single-box behaviour preserved (same `run_scan`), now
    with a queue + 429 when full.
  * ``PostgresJobQueue`` — durable cross-process queue (``scan_jobs`` table, claimed
    with FOR UPDATE SKIP LOCKED). Enqueue here; run workers out-of-process via
    ``worker.py`` (`run_worker`), with heartbeat + visibility-timeout requeue +
    attempts-based DLQ.
"""
from __future__ import annotations

import os
import queue
import threading
import time
import uuid
from typing import Callable, Optional

import scanner_db

VISIBILITY_TIMEOUT_S = int(os.environ.get("JOB_VISIBILITY_TIMEOUT_S", "1800"))
MAX_ATTEMPTS = int(os.environ.get("JOB_MAX_ATTEMPTS", "3"))


class InProcessJobQueue:
    def __init__(self, handler: Callable[[dict], None], workers: int = 2,
                 maxsize: int = 100):
        self._handler = handler
        self._q: "queue.Queue" = queue.Queue(maxsize=maxsize)
        self._threads = []
        for i in range(max(1, workers)):
            t = threading.Thread(target=self._loop, name=f"scan-worker-{i}", daemon=True)
            t.start()
            self._threads.append(t)

    def _loop(self):
        while True:
            payload = self._q.get()
            try:
                self._handler(payload)
            except Exception:
                pass  # the handler (run_scan) records failure itself
            finally:
                self._q.task_done()

    def enqueue(self, scan_id: str, payload: dict, pool: str = "default") -> bool:
        try:
            self._q.put_nowait(payload)
            return True
        except queue.Full:
            return False

    def depth(self, pool: Optional[str] = None) -> int:
        return self._q.qsize()


class PostgresJobQueue:
    """Durable queue. Enqueue in-process; workers run via worker.py:run_worker."""

    def __init__(self, max_depth: int = 1000):
        self._max_depth = max_depth

    def enqueue(self, scan_id: str, payload: dict, pool: str = "default") -> bool:
        if scanner_db.queue_depth(pool) >= self._max_depth:
            return False
        scanner_db.enqueue_job(str(uuid.uuid4()), scan_id, payload, pool)
        return True

    def depth(self, pool: Optional[str] = None) -> int:
        return scanner_db.queue_depth(pool)


def run_worker(handler: Callable[[dict], None], pool: str = "default",
               worker_id: Optional[str] = None, poll: float = 1.0,
               stop: "threading.Event | None" = None) -> None:
    """Worker loop for the Postgres queue: recover stale jobs, claim, run with a
    heartbeat, complete/fail(+requeue). Runs until ``stop`` is set."""
    worker_id = worker_id or f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
    stop = stop or threading.Event()
    while not stop.is_set():
        try:
            scanner_db.requeue_stale_jobs(VISIBILITY_TIMEOUT_S, MAX_ATTEMPTS)
            job = scanner_db.claim_job(worker_id, pool)
        except Exception:
            job = None
        if not job:
            stop.wait(poll)
            continue
        hb_stop = threading.Event()
        threading.Thread(target=_heartbeat, args=(job["id"], hb_stop),
                         daemon=True).start()
        try:
            handler(job["payload"])
            scanner_db.complete_job(job["id"])
        except Exception as e:
            requeue = int(job.get("attempts", 0)) < MAX_ATTEMPTS
            scanner_db.fail_job(job["id"], str(e), requeue=requeue)
        finally:
            hb_stop.set()


def _heartbeat(job_id: str, stop: "threading.Event", interval: float = 30.0):
    while not stop.wait(interval):
        try:
            scanner_db.heartbeat_job(job_id)
        except Exception:
            pass


def make_job_queue(handler: Callable[[dict], None], workers: int = 2,
                   maxsize: int = 100):
    """Postgres queue when QUEUE_BACKEND=postgres (+ a DB configured); else the
    in-process worker pool (single-box default)."""
    if os.environ.get("QUEUE_BACKEND") == "postgres":
        return PostgresJobQueue(max_depth=maxsize * 10)
    return InProcessJobQueue(handler, workers=workers, maxsize=maxsize)
