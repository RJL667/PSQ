"""WS0 migration gate for flag_inference.py (2 target-apex sites -> HTTP).

Offline. A deterministic fake transport + a stubbed DNS resolver stand in for the
network, so the gate needs no keys and no real outbound calls. Workflow:

    py tooling/regression/mig_flag_inference.py --record   # BEFORE the edit
    # ... migrate flag_inference.py requests.get -> HTTP.get ...
    py tooling/regression/mig_flag_inference.py            # AFTER: must pass

The fake returns a homepage whose body carries a JSE ticker + <title>, so both
infer_listed_company (footer scrape) and run_preflight (title + B2C hints) exercise
their real parsing. Equivalence is asserted by checker_gate over the cassette.
"""
from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
for p in (str(ROOT), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import requests
import checker_gate as cg

_HTML = (b"<html><head><title>Example Listed Co (Pty) Ltd</title></head>"
         b"<body>Welcome. Investor relations. JSE: ABC. "
         b"Login to your account. Add to cart. Checkout securely.</body></html>")


def _fake(session_self, method, url, **kwargs):
    r = requests.models.Response()
    r.status_code = 200
    r._content = _HTML
    r._content_consumed = True
    r.url = url
    r.encoding = "utf-8"
    r.headers = requests.structures.CaseInsensitiveDict({"Content-Type": "text/html"})
    return r


def _cases():
    # imported fresh so the edit is picked up between --record and verify
    import flag_inference as fi
    return {
        "flag_infer_listed_company":
            lambda: fi.infer_listed_company("examplelisted.co.za"),
        "flag_run_preflight":
            lambda: fi.run_preflight("examplelisted.co.za", sub_industry="other"),
    }


def _with_stubs(fn):
    """Run fn() with the fake transport + a stubbed DNS resolver installed."""
    import requests.sessions as S
    orig_req, orig_dns = S.Session.request, socket.gethostbyname
    S.Session.request = _fake
    socket.gethostbyname = lambda host: "203.0.113.7"
    try:
        return fn()
    finally:
        S.Session.request = orig_req
        socket.gethostbyname = orig_dns


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", action="store_true")
    args = ap.parse_args()

    cases = _cases()
    if args.record:
        # The cassette is recorded under the fake; DNS is stubbed only so the
        # ORIGINAL code path runs to completion while we freeze it.
        for name, fn in cases.items():
            summary = _with_stubs(lambda fn=fn: cg.record_baseline(name, fn))
            print(f"[record] {name:28s} {summary['requests']} request(s) frozen")
        print("\nBaselines frozen. Now migrate flag_inference.py, then re-run "
              "without --record.")
        return 0

    failures = 0
    for name, fn in cases.items():
        # DNS still stubbed; HTTP comes from the cassette (replay), not the fake.
        r = _with_stubs(lambda fn=fn: cg.verify(name, fn))
        print(r)
        failures += 0 if r.ok else 1
    print()
    if failures:
        print(f"MIGRATION GATE FAILED — {failures} case(s) drifted.")
        return 1
    print("MIGRATION GATE PASSED — flag_inference behaviour preserved.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
