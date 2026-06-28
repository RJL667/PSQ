"""checker_gate.py — checker-level golden gate (the WS0 safety net).

Composes :mod:`http_cassette` and :mod:`result_diff` into a record/verify
workflow that proves a behaviour-preserving egress refactor (WS0 — routing every
direct ``requests.*`` call through a controllable client) changed **neither which
outbound calls a checker makes nor what it computes from the responses**.

This is the checker-level half of SCALE-00c. The existing ``golden.py`` gates the
scoring/financial layer offline; this gates the network checkers, which the design
treated as blocked on WS0. They are not: every outbound call funnels through
``requests`` (verified by egress audit), so :mod:`http_cassette` makes the checker
re-runnable offline today. Because the baseline (cassette + result blob) is
committed to the repo, this gate's correctness evidence does **not** depend on
durable infra — which removes one of the two reasons the design made Phase −1 a
hard predecessor of the WS0 refactor.

Workflow
--------
``record_baseline(name, fn)`` — run ``fn()`` once for real (network on) and freeze
  * ``<name>.cassette.json`` — every outbound request+response, secrets redacted
  * ``<name>.result.json``   — ``fn()``'s return blob, volatile fields stripped

``verify(name, fn)`` — re-run ``fn()`` with the cassette **replayed (network off)**
and assert:
  1. **request fidelity** — the multiset of outbound calls is unchanged. The
     cassette key ignores request headers + timeout, so a WS0 reroute that merely
     adds an identifying User-Agent / default timeout is *permitted*.
  2. **output equivalence** — ``result_diff.diff(baseline, fresh)`` is empty.
  3. **no network** — a call absent from the cassette raises
     :class:`http_cassette.CassetteMiss`.

Each WS0 failure mode trips a distinct signal:
  * a changed / added outbound call  -> ``CassetteMiss``
  * a dropped outbound call          -> fidelity ``missing``
  * same calls, changed processing   -> result-blob diff

Scope boundary: the cassette captures HTTP only. A checker that also depends on
DNS / TLS / sockets / whois is not made fully deterministic by replay alone — but
WS0 changes *only* the HTTP egress path, so request-fidelity + output-equivalence
over a frozen cassette is exactly the right contract for it. For checkers with
non-HTTP nondeterminism, stub those sources in ``fn`` or rely on the fidelity
half (which is unaffected by non-HTTP variation).
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import http_cassette as hc      # noqa: E402
import result_diff as rd        # noqa: E402

DEFAULT_BASELINE_DIR = HERE / "checker_baselines"


def _paths(name: str, baseline_dir: Path):
    return (baseline_dir / f"{name}.cassette.json",
            baseline_dir / f"{name}.result.json")


def record_baseline(name: str, fn, *, baseline_dir: Path = DEFAULT_BASELINE_DIR) -> dict:
    """Run ``fn()`` for real, freezing its HTTP cassette and result blob.

    ``fn`` is a zero-arg callable returning the JSON-able result to gate (e.g.
    ``lambda: BreachChecker().check("phishield.com")``). Returns a small summary.
    """
    baseline_dir.mkdir(parents=True, exist_ok=True)
    cas_path, res_path = _paths(name, baseline_dir)
    with hc.record(str(cas_path)) as cas:
        result = fn()
    view = rd.strip_volatile(result)
    res_path.write_text(json.dumps(view, indent=2, sort_keys=True, default=str),
                        encoding="utf-8")
    return {"name": name, "requests": len(cas.entries),
            "cassette": str(cas_path), "result": str(res_path)}


@dataclass
class GateResult:
    name: str
    ok: bool
    fidelity: dict = field(default_factory=lambda: {"missing": [], "unexpected": []})
    diffs: list = field(default_factory=list)
    error: str | None = None

    def __str__(self) -> str:
        if self.error:
            return f"[FAIL] {self.name}: {self.error}"
        if self.ok:
            return f"[PASS] {self.name}: requests + output equivalent under replay"
        lines = [f"[FAIL] {self.name}:"]
        if self.fidelity["missing"]:
            lines.append(f"  dropped {len(self.fidelity['missing'])} recorded call(s):")
            lines += [f"    - {m}" for m in self.fidelity["missing"][:10]]
        if self.fidelity["unexpected"]:
            lines.append(f"  made {len(self.fidelity['unexpected'])} unrecorded call(s):")
            lines += [f"    + {u}" for u in self.fidelity["unexpected"][:10]]
        if self.diffs:
            lines.append(f"  output drifted in {len(self.diffs)} field(s):")
            lines.append(rd.format_report(self.diffs[:20], "    output"))
        return "\n".join(lines)


def verify(name: str, fn, *, baseline_dir: Path = DEFAULT_BASELINE_DIR) -> GateResult:
    """Re-run ``fn()`` under cassette replay and compare to the frozen baseline."""
    cas_path, res_path = _paths(name, baseline_dir)
    if not cas_path.exists() or not res_path.exists():
        return GateResult(name, ok=False,
                          error=f"no baseline for {name!r} — run record_baseline first")
    baseline = json.loads(res_path.read_text(encoding="utf-8"))
    try:
        with hc.replay(str(cas_path)) as cas:
            result = fn()
        fidelity = cas.fidelity_diff()
    except hc.CassetteMiss as e:
        # An outbound call whose shape the refactor changed/added.
        return GateResult(name, ok=False,
                          error=f"unrecorded outbound request under replay:\n    {e.key}")
    view = rd.strip_volatile(result)
    diffs = rd.diff(baseline, view)
    ok = not diffs and not fidelity["missing"] and not fidelity["unexpected"]
    return GateResult(name, ok=ok, fidelity=fidelity, diffs=diffs)
