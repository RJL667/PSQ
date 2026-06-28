"""WS0 gate for the subdomain-takeover HTTP probe (checkers_network 109/116) — the
one path mig_checkers_network.py couldn't reach (it sits behind a CNAME + socket
check). Drives _check_cname_takeover directly with a stubbed CNAME resolver
(pointing at a dangling github.io target) and a fake HTTP that returns the
takeover fingerprint, so the HTTPS probe (109) runs and flags is_dangling.

    git checkout 349de12 -- security_scanner/checkers_network.py   # pre-migration
    py tooling/regression/mig_network_takeover.py --record
    git checkout HEAD -- security_scanner/checkers_network.py      # migrated
    py tooling/regression/mig_network_takeover.py
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


class _CNAME:
    target = "deleted-app-xyz.github.io."


def _fake(session_self, method, url, **kwargs):
    r = requests.models.Response()
    r.status_code = 200
    # GitHub Pages dangling fingerprint -> is_dangling = True
    r._content = b"<html><body>There isn't a GitHub Pages site here.</body></html>"
    r._content_consumed = True
    r.encoding = "utf-8"
    r.url = url
    r.headers = requests.structures.CaseInsensitiveDict({"Content-Type": "text/html"})
    return r


def _cases():
    import checkers_network as cn
    return {
        "net_takeover": lambda: cn.SubdomainChecker()._check_cname_takeover(
            "pages.examplecorp.co.za") or {"vulnerable": False},
    }


def _with_stubs(fn):
    import requests.sessions as S
    import dns.resolver
    orig_req = S.Session.request
    orig_resolve = dns.resolver.resolve
    orig_gai = socket.getaddrinfo
    S.Session.request = _fake
    dns.resolver.resolve = lambda *a, **k: [_CNAME()]
    socket.getaddrinfo = lambda *a, **k: [(2, 1, 6, "", ("185.199.108.153", 0))]
    try:
        return fn()
    finally:
        S.Session.request = orig_req
        dns.resolver.resolve = orig_resolve
        socket.getaddrinfo = orig_gai


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", action="store_true")
    args = ap.parse_args()
    cases = _cases()
    if args.record:
        for name, fn in cases.items():
            s = _with_stubs(lambda fn=fn: cg.record_baseline(name, fn))
            print(f"[record] {name:16s} {s['requests']} request(s) frozen")
        print("\nBaselines frozen. Restore migrated file, then re-run without --record.")
        return 0
    failures = 0
    for name, fn in cases.items():
        r = _with_stubs(lambda fn=fn: cg.verify(name, fn))
        print(r)
        failures += 0 if r.ok else 1
    print()
    print("TAKEOVER GATE PASSED — subdomain-takeover probe preserved." if not failures
          else f"TAKEOVER GATE FAILED — {failures} case(s) drifted.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
