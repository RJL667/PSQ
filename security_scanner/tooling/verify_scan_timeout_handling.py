# -*- coding: utf-8 -*-
"""BLOCKING guard: scan()-level as_completed(timeout=...) loops must catch the
concurrent.futures TimeoutError, never the builtin one.

THE BUG THIS PREVENTS (found 2026-06-30, real takealot.com scan on the VM):
    `as_completed(futures, timeout=180)` raises concurrent.futures.TimeoutError.
    On Python <3.11 that is a DISTINCT class from the builtin TimeoutError
    (builtin TimeoutError subclasses OSError; the futures one subclasses
    Exception). Production runs Python 3.10, so a bare `except TimeoutError`
    silently fails to catch it — and the WHOLE scan crashes with an unhandled
    exception the moment a phase exceeds its 180s budget (a target with many
    discovered IPs: takealot = 68 IPs -> 272 futures -> timeout -> crash, no
    output at all). Local dev runs Python 3.12 where the two classes ARE the
    same, so the crash never reproduces in testing — it is production-only.

This guard parses scanner.py and asserts every `try` block that iterates an
`as_completed(..., timeout=...)` call has an `except` that names
FuturesTimeoutError (the concurrent.futures alias) — or a tuple containing it.
A bare `except TimeoutError` (builtin) is rejected. Static + deterministic +
offline, so it runs in the pre-push hook on the dev Python yet enforces the
production-Python invariant.

Run: py tooling/verify_scan_timeout_handling.py   (exit 1 on any violation)
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SEC = os.path.dirname(HERE)
SCANNER = os.path.join(SEC, "scanner.py")
# The checker modules ALSO run as_completed(timeout=) loops. scanner.scan()'s
# own loops crash the whole scan on 3.10; a checker's loop is caught by the
# per-checker seam, but a bare `except TimeoutError` there STILL defeats its own
# purpose on 3.10 — the checker errors and loses the partial results it collected
# instead of returning them (found 2026-07-02: RelatedDomains / DependencyManifest
# / CMSPluginSBOM). So the guard now covers the checker modules too.
CHECKER_MODULES = [os.path.join(SEC, f) for f in (
    "checkers_core.py", "checkers_network.py",
    "checkers_threats.py", "checkers_supply_chain.py")]

# Handler names that correctly catch concurrent.futures.TimeoutError.
# FuturesTimeoutError is `from concurrent.futures import TimeoutError as ...`.
# `Exception` / `BaseException` are ALSO safe — the futures TimeoutError subclasses
# Exception, so a broad `except Exception` catches it. The bug this guards is the
# NARROW-but-wrong `except TimeoutError` (builtin), which does NOT catch the futures
# class on Python <3.11 — that name is deliberately absent here.
SAFE_NAMES = {"FuturesTimeoutError", "Exception", "BaseException"}


def _as_completed_timeout_calls(node: ast.AST) -> bool:
    """True if *node*'s body directly contains a call to as_completed(timeout=...)."""
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "as_completed":
            has_timeout = any(kw.arg == "timeout" for kw in n.keywords) or len(n.args) >= 2
            if has_timeout:
                return True
    return False


def _handler_names(handler: ast.ExceptHandler) -> set:
    t = handler.type
    if t is None:
        return {"<bare>"}
    elts = t.elts if isinstance(t, ast.Tuple) else [t]
    return {e.id for e in elts if isinstance(e, ast.Name)}


def _audit(path: str):
    """(checked, violations) for one file. violations = [(lineno, sorted_caught)].
    Only `try` blocks whose body iterates as_completed(timeout=) are inspected —
    those are the ones that can raise the futures TimeoutError."""
    tree = ast.parse(open(path, encoding="utf-8").read(), filename=path)
    checked, violations = 0, []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        if not any(_as_completed_timeout_calls(stmt) for stmt in node.body):
            continue
        checked += 1
        caught = set()
        for h in node.handlers:
            caught |= _handler_names(h)
        if not (caught & SAFE_NAMES):
            violations.append((node.lineno, sorted(caught)))
    return checked, violations


def main() -> None:
    # Optional path arg lets the gate be pointed at a synthetic copy for its own
    # fails-without/passes-with self-test; defaults to scanner.py + every checker
    # module (a try/as_completed loop in ANY of them must catch the futures class).
    targets = [sys.argv[1]] if len(sys.argv) > 1 else [SCANNER] + CHECKER_MODULES

    total = 0
    violations = []  # (filename, lineno, caught)
    for path in targets:
        checked, viols = _audit(path)
        total += checked
        for lineno, caught in viols:
            violations.append((os.path.basename(path), lineno, caught))

    print(f"try/as_completed(timeout=) loops inspected: {total} across {len(targets)} file(s)")
    if total == 0:
        print("FAIL: expected at least one try/as_completed(timeout=) loop — the guard "
              "may be looking at the wrong file(s) or the structure changed.")
        sys.exit(1)
    if violations:
        print(f"TIMEOUT-HANDLING GUARD FAILED ({len(violations)}):")
        for fname, lineno, caught in violations:
            print(f"  - {fname}:{lineno}: try/as_completed guarded by {caught}, none of "
                  f"which catch concurrent.futures.TimeoutError. On Python 3.10 (the VM) "
                  f"that class is DISTINCT from builtin TimeoutError — use "
                  f"`except (TimeoutError, FuturesTimeoutError)`.")
        sys.exit(1)
    print(f"TIMEOUT-HANDLING GUARD PASS — all {total} try/as_completed(timeout=) loops "
          f"across {len(targets)} file(s) catch FuturesTimeoutError")


if __name__ == "__main__":
    main()
