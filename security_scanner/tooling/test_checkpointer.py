"""Unit tests for scanner_db.Checkpointer (WS3) — py tooling/test_checkpointer.py

Offline (throwaway SQLite). Proves: no-op when no scan_id; skip-and-load on resume
(no recompute, no re-spend); failed/skipped results are NOT checkpointed (re-run on
resume); stale checkpoints (TTL) are treated as absent.
"""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import scanner_db as db

_p = _f = 0
def check(name, cond):
    global _p, _f
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    _p += 1 if cond else 0
    _f += 0 if cond else 1


tmp = Path(tempfile.mkdtemp()) / "ckpt.db"
db.configure(database_url="", sqlite_path=str(tmp))
db.init_schema()

calls = {"n": 0}
def compute_ok():
    calls["n"] += 1
    return {"score": 42}  # no 'status' key -> a successful result

# --- no scan_id => pure no-op (compute every time, persist nothing) ---
nop = db.Checkpointer(None)
nop.run("ssl", compute_ok); nop.run("ssl", compute_ok)
check("no scan_id: computes every call", calls["n"] == 2)
check("no scan_id: nothing persisted", db.load_checkpoints("anything") == {})

# --- with scan_id: first run computes + persists ---
calls["n"] = 0
c1 = db.Checkpointer("s1")
r = c1.run("ssl", compute_ok)
check("first run computes", calls["n"] == 1 and r == {"score": 42})
check("result persisted", db.load_checkpoints("s1") == {"ssl": {"score": 42}})

# --- resume: skip-and-load, no recompute ---
calls["n"] = 0
c2 = db.Checkpointer("s1", resume=True)
r = c2.run("ssl", compute_ok)
check("resume skip-and-loads (no recompute)", calls["n"] == 0 and r == {"score": 42})

# --- failed/skipped results are NOT checkpointed ---
def compute_err():
    return {"status": "error", "error": "boom", "issues": []}
def compute_skip():
    return {"status": "no_api_key"}
c3 = db.Checkpointer("s2")
c3.run("breaches", compute_err)
c3.run("shodan", compute_skip)
check("error result not checkpointed", "breaches" not in db.load_checkpoints("s2"))
check("skipped result not checkpointed", "shodan" not in db.load_checkpoints("s2"))

# on resume, a previously-failed checker re-runs (no checkpoint to load)
calls["n"] = 0
c4 = db.Checkpointer("s2", resume=True)
c4.run("breaches", compute_ok)
check("failed checker re-runs on resume", calls["n"] == 1)

# --- TTL: a stale checkpoint is treated as absent ---
db.save_checkpoint("s3", "breaches", {"breach_count": 3})
fresh = db.Checkpointer("s3", resume=True, max_age_seconds=3600)
check("fresh checkpoint loaded within TTL", fresh.has("breaches"))
stale = db.Checkpointer("s3", resume=True, max_age_seconds=-1)  # everything stale
check("stale checkpoint treated as absent", not stale.has("breaches"))

try:
    tmp.unlink()
except OSError:
    pass
print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
