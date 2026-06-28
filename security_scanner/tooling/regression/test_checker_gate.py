"""Unit tests for checker_gate — runnable without pytest:  py test_checker_gate.py

Fully offline. A synthetic "checker" (a function that makes HTTP calls and derives
a result) stands in for a real scanner checker, and a router fake stands in for the
network. The tests prove the gate:
  * PASSES when a refactor is genuinely behaviour-preserving (incl. a WS0-style
    reroute that only adds a User-Agent + timeout);
  * FAILS, with the right signal, for each WS0 failure mode:
      - a new/changed outbound call   -> CassetteMiss (error)
      - same calls, changed output    -> result-blob diff
      - a dropped outbound call       -> fidelity "missing"
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import checker_gate as cg
import http_cassette as hc
import requests
import requests.sessions as _S

_passed = 0
_failed = 0


def check(name: str, cond: bool) -> None:
    global _passed, _failed
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if cond:
        _passed += 1
    else:
        _failed += 1


# --- router fake: response varies by URL path, never touches the network ----

def _router(session_self, method, url, **kwargs):
    if "/breaches" in url:
        body = b'{"count": 3}'
    elif "/score" in url:
        body = b'{"score": 88}'
    else:
        body = b'{}'
    r = requests.models.Response()
    r.status_code = 200
    r._content = body
    r._content_consumed = True
    r.url = url
    r.encoding = "utf-8"
    r.headers = requests.structures.CaseInsensitiveDict({"Content-Type": "application/json"})
    return r


def _boom(session_self, method, url, **kwargs):
    raise AssertionError(f"network hit during replay: {method} {url}")


# --- the synthetic checker, in several variants -----------------------------

def checker_v1():
    r1 = requests.get("https://api.demo.io/breaches",
                      params={"domain": "x.io", "key": "SECRET"})
    r2 = requests.get("https://api.demo.io/score", params={"domain": "x.io"})
    return {"breach_count": r1.json()["count"], "score": r2.json()["score"],
            "status": "ok"}


def checker_v2_ws0_reroute():
    # Simulates WS0: same calls, but routed "through the seam" — adds an
    # identifying User-Agent and an explicit timeout. Key must be unchanged.
    hdrs = {"User-Agent": "Phishield-Scanner/1.0 (+/scanner-info)"}
    r1 = requests.get("https://api.demo.io/breaches",
                      params={"domain": "x.io", "key": "ROTATED"},
                      headers=hdrs, timeout=10)
    r2 = requests.get("https://api.demo.io/score", params={"domain": "x.io"},
                      headers=hdrs, timeout=10)
    return {"breach_count": r1.json()["count"], "score": r2.json()["score"],
            "status": "ok"}


def checker_v3_new_url():
    # /breaches identical to v1 (served from cassette), then a brand-new call.
    r1 = requests.get("https://api.demo.io/breaches",
                      params={"domain": "x.io", "key": "SECRET"})
    requests.get("https://api.demo.io/NEW-ENDPOINT")  # never recorded
    return {"breach_count": r1.json()["count"], "status": "ok"}


def checker_v4_changed_output():
    # exactly v1's two calls, only the processing differs.
    r1 = requests.get("https://api.demo.io/breaches",
                      params={"domain": "x.io", "key": "SECRET"})
    r2 = requests.get("https://api.demo.io/score", params={"domain": "x.io"})
    return {"breach_count": r1.json()["count"], "score": r2.json()["score"] + 1,
            "status": "ok"}


def checker_v5_dropped_call():
    # v1's /breaches call, but the /score call is dropped entirely.
    r1 = requests.get("https://api.demo.io/breaches",
                      params={"domain": "x.io", "key": "SECRET"})
    return {"breach_count": r1.json()["count"], "status": "ok"}


# --- run ---------------------------------------------------------------------

TMP = HERE / "_gate_test_tmp"
if TMP.exists():
    shutil.rmtree(TMP)

_orig = _S.Session.request
try:
    _S.Session.request = _router
    summary = cg.record_baseline("demo", checker_v1, baseline_dir=TMP)
    check("baseline records both outbound calls", summary["requests"] == 2)
    check("baseline result blob written",
          (TMP / "demo.result.json").exists())

    # From here on the network explodes if touched — replay must be offline.
    _S.Session.request = _boom

    r = cg.verify("demo", checker_v1, baseline_dir=TMP)
    check("identical checker passes the gate", r.ok and not r.error)

    r = cg.verify("demo", checker_v2_ws0_reroute, baseline_dir=TMP)
    check("WS0-style reroute (UA+timeout, rotated key) passes", r.ok and not r.error)

    r = cg.verify("demo", checker_v3_new_url, baseline_dir=TMP)
    check("a new outbound call is caught (CassetteMiss)",
          (not r.ok) and r.error is not None and "NEW-ENDPOINT" in r.error)

    r = cg.verify("demo", checker_v4_changed_output, baseline_dir=TMP)
    check("changed output (same calls) is caught by blob diff",
          (not r.ok) and r.error is None and len(r.diffs) >= 1
          and any("score" in d.path for d in r.diffs))

    r = cg.verify("demo", checker_v5_dropped_call, baseline_dir=TMP)
    check("a dropped outbound call is caught by fidelity",
          (not r.ok) and any("score" in m for m in r.fidelity["missing"]))

    r = cg.verify("missing-name", checker_v1, baseline_dir=TMP)
    check("verify without a baseline fails cleanly",
          (not r.ok) and r.error is not None and "no baseline" in r.error)

finally:
    _S.Session.request = _orig
    if TMP.exists():
        shutil.rmtree(TMP)


print(f"\n{_passed} passed, {_failed} failed")
sys.exit(1 if _failed else 0)
