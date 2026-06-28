"""Unit tests for result_diff — runnable without pytest:  py test_result_diff.py

Proves the comparator (a) treats identical/volatile-only blobs as equivalent,
(b) catches real value/shape changes, and (c) honours numeric tolerance.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import result_diff as rd

_passed = 0
_failed = 0


def check(name: str, cond: bool) -> None:
    global _passed, _failed
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if cond:
        _passed += 1
    else:
        _failed += 1


# --- equivalence ---------------------------------------------------------
check("identical blobs are equivalent",
      rd.equivalent({"a": 1, "b": [1, 2], "c": {"d": "x"}},
                    {"a": 1, "b": [1, 2], "c": {"d": "x"}}))

check("volatile-only differences are ignored",
      rd.equivalent({"a": 1, "scan_id": "AAA", "took_seconds": 3.1, "checker_durations": {"ssl": 9}},
                    {"a": 1, "scan_id": "ZZZ", "took_seconds": 99.9, "checker_durations": {"ssl": 1}}))

check("int vs float of equal value is equivalent",
      rd.equivalent({"a": 1}, {"a": 1.0}))

# --- caught differences ---------------------------------------------------
check("scalar value change is caught",
      not rd.equivalent({"a": 1}, {"a": 2}))

_d = rd.diff({"x": {"y": 1}}, {"x": {"y": 2}})
check("nested change reports correct path/kind",
      len(_d) == 1 and _d[0].path == "$.x.y" and _d[0].kind == "value")

check("added key is caught",
      not rd.equivalent({"a": 1}, {"a": 1, "b": 2}))

check("removed key is caught",
      not rd.equivalent({"a": 1, "b": 2}, {"a": 1}))

check("list length change is caught",
      not rd.equivalent({"l": [1, 2]}, {"l": [1, 2, 3]}))

check("list reorder is caught (order-sensitive)",
      not rd.equivalent({"l": [1, 2]}, {"l": [2, 1]}))

check("type change str-vs-int is caught",
      not rd.equivalent({"a": 1}, {"a": "1"}))

check("bool is not coerced to int (True != 1)",
      not rd.equivalent({"a": True}, {"a": 1}))

# --- numeric tolerance ----------------------------------------------------
_tol = rd.DiffConfig(rel_tol=0.01)
check("tolerance accepts within-band drift",
      rd.equivalent({"a": 100.0}, {"a": 100.4}, _tol))
check("tolerance rejects out-of-band drift",
      not rd.equivalent({"a": 100.0}, {"a": 110.0}, _tol))

# --- strip_volatile -------------------------------------------------------
_stripped = rd.strip_volatile({"a": 1, "scan_timestamp": "t", "n": {"b": 2, "elapsed_ms": 5}})
check("strip_volatile removes volatile keys recursively",
      _stripped == {"a": 1, "n": {"b": 2}})


print(f"\n{_passed} passed, {_failed} failed")
sys.exit(0 if _failed == 0 else 1)
