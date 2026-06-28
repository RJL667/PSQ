"""Unit tests for the WS1 foundations — object_store + scan_state.
Runnable without pytest:  py tooling/test_ws1_foundations.py
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import object_store as obj
import scan_state as st

_passed = 0
_failed = 0


def check(name: str, cond: bool) -> None:
    global _passed, _failed
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if cond:
        _passed += 1
    else:
        _failed += 1


def expect_raises(name, exc, fn):
    try:
        fn()
        check(name, False)
    except exc:
        check(name, True)
    except Exception as e:  # noqa: BLE001
        print(f"        (wrong exception: {type(e).__name__})")
        check(name, False)


# --- object_store ---------------------------------------------------------
TMP = Path(__file__).parent / "_ws1_store_tmp"
if TMP.exists():
    shutil.rmtree(TMP)
store = obj.LocalObjectStore(str(TMP))

store.put("pdfs/scan1/full.pdf", b"%PDF-1.7 data", content_type="application/pdf")
check("put+get round trips", store.get("pdfs/scan1/full.pdf") == b"%PDF-1.7 data")
check("exists true for written key", store.exists("pdfs/scan1/full.pdf"))
check("get missing returns None", store.get("pdfs/none.pdf") is None)
check("exists false for missing", store.exists("pdfs/none.pdf") is False)
check("url present for existing key", (store.url("pdfs/scan1/full.pdf") or "").startswith("file:"))
check("url None for missing key", store.url("pdfs/none.pdf") is None)

store.put("archive/x.io/a.json", b"{}")
store.put("archive/x.io/b.json", b"{}")
check("list_prefix finds keys under prefix",
      set(store.list_prefix("archive/x.io")) == {"archive/x.io/a.json", "archive/x.io/b.json"})
check("no .tmp files leak", not any(p.name.endswith(".tmp") for p in TMP.rglob("*")))

store.delete("pdfs/scan1/full.pdf")
check("delete removes the blob", not store.exists("pdfs/scan1/full.pdf"))
check("delete missing is a no-op", (store.delete("pdfs/none.pdf") or True))

expect_raises("traversal key rejected", ValueError, lambda: store.put("../escape", b"x"))
expect_raises("absolute-ish backslash key rejected", ValueError, lambda: store.get("a\\b"))

if TMP.exists():
    shutil.rmtree(TMP)


# --- scan_state -----------------------------------------------------------
check("queued is not terminal", not st.is_terminal(st.QUEUED))
check("completed is terminal", st.is_terminal(st.COMPLETED))
check("queued->running allowed", st.can_transition(st.QUEUED, st.RUNNING))
check("queued->completed NOT allowed", not st.can_transition(st.QUEUED, st.COMPLETED))
check("running->queued allowed (requeue)", st.can_transition(st.RUNNING, st.QUEUED))
expect_raises("invalid transition raises", st.InvalidTransition,
              lambda: st.transition(st.COMPLETED, st.RUNNING))

s = st.ScanState(scan_id="abc")
s.start(worker_id="w1", now=100.0)
check("start -> running, attempt counted, worker set",
      s.status == st.RUNNING and s.attempts == 1 and s.worker_id == "w1")
s.heartbeat(now=105.0)
check("heartbeat updates last_heartbeat", s.last_heartbeat == 105.0)
check("not stale within timeout", not st.should_requeue(s, now=120.0, visibility_timeout=60))
check("stale past timeout -> requeue", st.should_requeue(s, now=200.0, visibility_timeout=60))

s.requeue()
check("requeue -> queued, worker cleared", s.status == st.QUEUED and s.worker_id is None)
check("attempts retained across requeue", s.attempts == 1)
s.start(worker_id="w2", now=300.0)
check("second start increments attempts", s.attempts == 2)
check("is_poison at attempt ceiling", st.is_poison(s, max_attempts=2))
s.complete()
check("running->completed", s.status == st.COMPLETED)
expect_raises("heartbeat in terminal state raises", st.InvalidTransition,
              lambda: s.heartbeat(now=400.0))

print(f"\n{_passed} passed, {_failed} failed")
sys.exit(1 if _failed else 0)
