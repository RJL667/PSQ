"""Unit tests for observability (WS9). py tooling/test_observability.py"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import observability as obs

_p = _f = 0
def check(n, c):
    global _p, _f
    print(f"  {'PASS' if c else 'FAIL'}  {n}")
    _p += 1 if c else 0
    _f += 0 if c else 1


def val(counter, **labels):
    return counter.labels(**labels)._value.get()


# observe_scan: completed path
c0 = val(obs.SCANS, status="completed")
with obs.observe_scan("s1", "x.io"):
    pass
check("observe_scan increments completed", val(obs.SCANS, status="completed") == c0 + 1)

# observe_scan: failed path re-raises + counts
f0 = val(obs.SCANS, status="failed")
raised = False
try:
    with obs.observe_scan("s2", "x.io"):
        raise RuntimeError("boom")
except RuntimeError:
    raised = True
check("observe_scan re-raises and counts failed",
      raised and val(obs.SCANS, status="failed") == f0 + 1)

# provider call metric
p0 = val(obs.PROVIDER_CALLS, provider="hibp")
obs.record_provider_call("hibp", "GET")
check("record_provider_call increments", val(obs.PROVIDER_CALLS, provider="hibp") == p0 + 1)

# checker durations
obs.record_checker_durations({"ssl": 9.0, "breaches": 3.0})
check("record_checker_durations accepted", True)

# queue depth gauge
obs.set_queue_depth(7)
check("queue depth gauge set", obs.QUEUE_DEPTH._value.get() == 7)

# /metrics text contains the metric families
text = obs.metrics_text().decode()
check("metrics_text exposes scans_total", "scans_total" in text)
check("metrics_text exposes scan_duration_seconds", "scan_duration_seconds" in text)
check("metrics_text exposes provider_calls_total", "provider_calls_total" in text)

# structured logger + tracer no-op
log = obs.get_logger("test")
check("get_logger returns a logger", hasattr(log, "info"))
with obs.scan_span("s3", "x.io"):
    pass
check("scan_span no-op works without exporter", True)

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
