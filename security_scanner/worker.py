"""WS2 worker entrypoint — drains the durable Postgres scan-job queue.

Run one or more alongside the web tier (which then only enqueues):

    QUEUE_BACKEND=postgres DATABASE_URL=postgresql://... python worker.py [pool]

Each worker claims jobs with FOR UPDATE SKIP LOCKED, runs the scan with a heartbeat,
and on completion/failure marks the job done / requeues it (visibility timeout +
attempts-based DLQ handled in job_queue.run_worker).
"""
import os
import sys

os.environ.setdefault("QUEUE_BACKEND", "postgres")

import app  # noqa: E402  — registers run_scan + configures scanner_db
from job_queue import run_worker  # noqa: E402


def main() -> int:
    pool = sys.argv[1] if len(sys.argv) > 1 else "default"
    print(f"[worker] pid={os.getpid()} draining pool={pool!r} "
          f"(backend={type(app.SCAN_QUEUE).__name__})")
    run_worker(app._run_scan_job, pool=pool)
    return 0


if __name__ == "__main__":
    sys.exit(main())
