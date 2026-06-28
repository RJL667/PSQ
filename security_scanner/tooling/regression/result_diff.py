"""Structural-equivalence comparator for scanner result blobs.

Core of the SCALE-00c golden-output regression harness (see README.md).
Pure stdlib, no scanner imports — safe to reuse anywhere (scoring layer now,
checker-level diffs once WS0's egress seam makes record/replay possible).

Given two JSON-able structures — a frozen *baseline* and a fresh *candidate* —
report whether they are structurally equivalent, ignoring a configurable set of
*volatile* fields (timestamps, durations, scan ids) and optionally allowing a
numeric tolerance. Differences are returned as JSON-path-addressed records, so a
refactor that changes a checker's or scorer's output shape is caught exactly.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass


# Keys whose VALUES are inherently run-to-run volatile and must be ignored when
# comparing two scans of the same target. Matched by exact name anywhere in the
# tree (the whole sub-tree under the key is dropped).
DEFAULT_VOLATILE_KEYS = frozenset({
    "scan_id", "scan_timestamp", "timestamp", "completed_at", "created_at",
    "started_at", "generated_at", "scan_date", "scan_duration",
    "checker_durations", "per_checker_seconds", "total_checker_seconds",
    "slowest_checker", "_scan_completeness",
})

# Keys matching any of these regexes are also treated as volatile.
DEFAULT_VOLATILE_PATTERNS = (
    re.compile(r".*_seconds$"),
    re.compile(r".*_duration(_.*)?$"),
    re.compile(r".*elapsed.*"),
    re.compile(r".*wall.?time.*"),
    re.compile(r"^duration$"),
)


@dataclass(frozen=True)
class Difference:
    path: str
    kind: str            # "value" | "type" | "added" | "removed" | "length"
    baseline: object = None
    candidate: object = None

    def __str__(self) -> str:
        if self.kind == "added":
            return f"  + {self.path}  (only in candidate: {_short(self.candidate)})"
        if self.kind == "removed":
            return f"  - {self.path}  (only in baseline: {_short(self.baseline)})"
        if self.kind == "length":
            return f"  ~ {self.path}  list length {self.baseline} -> {self.candidate}"
        if self.kind == "type":
            return (f"  ~ {self.path}  type "
                    f"{type(self.baseline).__name__} -> {type(self.candidate).__name__}")
        return f"  ~ {self.path}  {_short(self.baseline)} -> {_short(self.candidate)}"


def _short(v, n: int = 80) -> str:
    s = repr(v)
    return s if len(s) <= n else s[:n - 1] + "…"


@dataclass
class DiffConfig:
    volatile_keys: frozenset = DEFAULT_VOLATILE_KEYS
    volatile_patterns: tuple = DEFAULT_VOLATILE_PATTERNS
    rel_tol: float = 0.0     # default: exact numeric comparison
    abs_tol: float = 0.0

    def is_volatile(self, key) -> bool:
        if not isinstance(key, str):
            return False
        if key in self.volatile_keys:
            return True
        return any(p.match(key) for p in self.volatile_patterns)


def _is_number(x) -> bool:
    # bool is a subclass of int — exclude it so True/1 stay distinguishable.
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _nums_equal(a, b, cfg: DiffConfig) -> bool:
    return math.isclose(a, b, rel_tol=cfg.rel_tol, abs_tol=cfg.abs_tol)


def diff(baseline, candidate, cfg: DiffConfig | None = None, _path: str = "$") -> list:
    """Return a list of Difference records. Empty list == structurally equivalent."""
    cfg = cfg or DiffConfig()
    out: list = []

    if _is_number(baseline) and _is_number(candidate):
        if not _nums_equal(baseline, candidate, cfg):
            out.append(Difference(_path, "value", baseline, candidate))
        return out

    if type(baseline) is not type(candidate):
        out.append(Difference(_path, "type", baseline, candidate))
        return out

    if isinstance(baseline, dict):
        bkeys = {k for k in baseline if not cfg.is_volatile(k)}
        ckeys = {k for k in candidate if not cfg.is_volatile(k)}
        for k in sorted(bkeys - ckeys, key=str):
            out.append(Difference(f"{_path}.{k}", "removed", baseline[k]))
        for k in sorted(ckeys - bkeys, key=str):
            out.append(Difference(f"{_path}.{k}", "added", None, candidate[k]))
        for k in sorted(bkeys & ckeys, key=str):
            out.extend(diff(baseline[k], candidate[k], cfg, f"{_path}.{k}"))
        return out

    if isinstance(baseline, list):
        if len(baseline) != len(candidate):
            out.append(Difference(_path, "length", len(baseline), len(candidate)))
        for i, (a, b) in enumerate(zip(baseline, candidate)):
            out.extend(diff(a, b, cfg, f"{_path}[{i}]"))
        return out

    # str / None / bool
    if baseline != candidate:
        out.append(Difference(_path, "value", baseline, candidate))
    return out


def equivalent(baseline, candidate, cfg: DiffConfig | None = None) -> bool:
    return not diff(baseline, candidate, cfg)


def strip_volatile(obj, cfg: DiffConfig | None = None):
    """Deep copy with volatile keys removed — used when freezing a baseline."""
    cfg = cfg or DiffConfig()
    if isinstance(obj, dict):
        return {k: strip_volatile(v, cfg) for k, v in obj.items()
                if not cfg.is_volatile(k)}
    if isinstance(obj, list):
        return [strip_volatile(v, cfg) for v in obj]
    return obj


def format_report(diffs: list, title: str = "") -> str:
    if not diffs:
        return f"{title}: EQUIVALENT (0 differences)"
    return "\n".join([f"{title}: {len(diffs)} difference(s)"] + [str(d) for d in diffs])
