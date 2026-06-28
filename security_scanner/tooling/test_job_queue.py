"""Unit tests for job_queue (WS2). py tooling/test_job_queue.py (offline; sqlite)"""
from __future__ import annotations

import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import scanner_db as db
import job_queue as jq

_p = _f = 0
def check(n, c):
    global _p, _f
    print(f"  {'PASS' if c else 'FAIL'}  {n}")
    _p += 1 if c else 0
    _f += 0 if c else 1


# --- InProcessJobQueue: enqueue runs handler; full -> 429 -----------------
done = []
ev = threading.Event()
def handler(payload):
    done.append(payload["scan_id"])
    ev.set()

q = jq.InProcessJobQueue(handler, workers=1, maxsize=2)
check("enqueue accepted", q.enqueue("s1", {"scan_id": "s1"}) is True)
ev.wait(2)
check("handler ran the job", done == ["s1"])

# fill the queue with a slow handler to test 'full' -> False
blocker = threading.Event()
def slow(payload):
    blocker.wait(2)
q2 = jq.InProcessJobQueue(slow, workers=1, maxsize=1)
q2.enqueue("a", {"scan_id": "a"})   # picked up by the worker (blocks)
time.sleep(0.1)
q2.enqueue("b", {"scan_id": "b"})   # fills the size-1 queue
full = q2.enqueue("c", {"scan_id": "c"})  # should be rejected
check("enqueue returns False when full (-> 429)", full is False)
blocker.set()


# --- PostgresJobQueue + run_worker against sqlite -------------------------
tmp = Path(tempfile.mkdtemp()) / "jobs.db"
db.configure(database_url="", sqlite_path=str(tmp))
db.init_schema()

pq = jq.PostgresJobQueue(max_depth=5)
check("durable enqueue", pq.enqueue("s2", {"scan_id": "s2", "v": 1}) is True)
check("queue depth reflects enqueue", pq.depth() == 1)

ran = []
def run_handler(payload):
    ran.append(payload["scan_id"])

stop = threading.Event()
t = threading.Thread(target=jq.run_worker,
                     args=(run_handler,), kwargs={"poll": 0.05, "stop": stop},
                     daemon=True)
t.start()
time.sleep(0.6)
stop.set(); t.join(timeout=2)
check("worker claimed + ran the job", ran == ["s2"])
check("queue drained after completion", pq.depth() == 0)

# --- visibility-timeout requeue ------------------------------------------
import uuid
db.enqueue_job(str(uuid.uuid4()), "s3", {"scan_id": "s3"})
job = db.claim_job("worker-x")
check("claim marks running + attempts=1", job["status"] == "running" and job["attempts"] == 1)
# force a stale heartbeat
db._run("UPDATE scan_jobs SET last_heartbeat=? WHERE scan_id='s3'",
        ("2000-01-01T00:00:00+00:00",))
n = db.requeue_stale_jobs(visibility_timeout_s=60, max_attempts=3)
check("stale running job requeued", n == 1)
again = db.claim_job("worker-y")
check("requeued job is claimable again (attempts=2)",
      again is not None and again["scan_id"] == "s3" and again["attempts"] == 2)

try:
    tmp.unlink()
except OSError:
    pass
print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
