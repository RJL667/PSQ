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

# The exception name(s) that correctly catch concurrent.futures.TimeoutError.
# FuturesTimeoutError is `from concurrent.futures import TimeoutError as ...`.
SAFE_NAMES = {"FuturesTimeoutError"}


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


def main() -> None:
    # Optional path arg lets the gate be pointed at a synthetic copy for its own
    # fails-without/passes-with self-test; defaults to the real scanner.py.
    target = sys.argv[1] if len(sys.argv) > 1 else SCANNER
    src = open(target, encoding="utf-8").read()
    tree = ast.parse(src, filename=target)

    checked = 0
    violations = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        # Only the try blocks that actually iterate as_completed with a timeout
        # can raise the futures TimeoutError, so only those need the guard.
        if not any(_as_completed_timeout_calls(stmt) for stmt in node.body):
            continue
        checked += 1
        caught = set()
        for h in node.handlers:
            caught |= _handler_names(h)
        if not (caught & SAFE_NAMES):
            violations.append((node.lineno, sorted(caught)))

    print(f"scan() as_completed(timeout=) loops inspected: {checked}")
    if checked == 0:
        print("FAIL: expected at least one as_completed(timeout=) loop in scanner.py "
              "— guard may be looking at the wrong file or the structure changed.")
        sys.exit(1)
    if violations:
        print(f"TIMEOUT-HANDLING GUARD FAILED ({len(violations)}):")
        for lineno, caught in violations:
            print(f"  - scanner.py:{lineno}: try/as_completed guarded by {caught}, "
                  f"none of which catch concurrent.futures.TimeoutError. Use "
                  f"`except FuturesTimeoutError`.")
        sys.exit(1)
    print(f"TIMEOUT-HANDLING GUARD PASS — all {checked} as_completed(timeout=) loops "
          f"catch FuturesTimeoutError")


if __name__ == "__main__":
    main()
