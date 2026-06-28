"""WS0 migration gate for checkers_core.py (4 target-apex sites -> HTTP).

Sites: SSLChecker._check_hsts (314), EmailHardeningChecker._check_mta_sts (668,
behind a DNS TXT lookup), HTTPHeaderChecker.check (844), WAFChecker.check (970).

Offline. A fake transport serves a rich apex response (HSTS + CSP + Cloudflare
markers) and an mta-sts.txt policy; DNS is stubbed so the MTA-STS path reaches its
HTTP fetch. Workflow:

    py tooling/regression/mig_checkers_core.py --record   # BEFORE the edit
    # ... migrate the 4 requests.get sites -> HTTP.get ...
    py tooling/regression/mig_checkers_core.py            # AFTER: must pass
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
for p in (str(ROOT), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import requests
import checker_gate as cg

_APEX_HEADERS = {
    "Content-Type": "text/html",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "cf-ray": "8a1b2c3d4e5f-JNB",          # -> Cloudflare WAF detection
    "Server": "cloudflare",
}
_MTA_STS_BODY = b"version: STSv1\nmode: enforce\nmx: mail.example.co.za\nmax_age: 604800\n"


def _resp(body: bytes, headers: dict, status: int = 200):
    r = requests.models.Response()
    r.status_code = status
    r._content = body
    r._content_consumed = True
    r.encoding = "utf-8"
    r.headers = requests.structures.CaseInsensitiveDict(headers)
    return r


def _fake(session_self, method, url, **kwargs):
    if "/.well-known/mta-sts.txt" in url:
        r = _resp(_MTA_STS_BODY, {"Content-Type": "text/plain"})
    else:
        r = _resp(b"<html><head><title>Example</title></head><body>ok</body></html>",
                  _APEX_HEADERS)
    r.url = url
    return r


class _FakeRdata:
    strings = [b"v=STSv1; id=20260101T000000Z"]


def _with_stubs(fn):
    import requests.sessions as S
    import dns.resolver
    orig_req = S.Session.request
    orig_resolve = dns.resolver.resolve
    S.Session.request = _fake
    dns.resolver.resolve = lambda *a, **k: [_FakeRdata()]
    try:
        return fn()
    finally:
        S.Session.request = orig_req
        dns.resolver.resolve = orig_resolve


def _cases():
    import checkers_core as cc
    return {
        "core_ssl_hsts": lambda: {"hsts": cc.SSLChecker()._check_hsts("example.co.za")},
        "core_mta_sts": lambda: cc.EmailHardeningChecker()._check_mta_sts("example.co.za"),
        "core_http_headers": lambda: cc.HTTPHeaderChecker().check("example.co.za"),
        "core_waf": lambda: cc.WAFChecker().check("example.co.za"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", action="store_true")
    args = ap.parse_args()

    cases = _cases()
    if args.record:
        for name, fn in cases.items():
            s = _with_stubs(lambda fn=fn: cg.record_baseline(name, fn))
            print(f"[record] {name:22s} {s['requests']} request(s) frozen")
        print("\nBaselines frozen. Migrate checkers_core.py, then re-run without --record.")
        return 0

    failures = 0
    for name, fn in cases.items():
        r = _with_stubs(lambda fn=fn: cg.verify(name, fn))
        print(r)
        failures += 0 if r.ok else 1
    print()
    print("MIGRATION GATE PASSED — checkers_core behaviour preserved." if not failures
          else f"MIGRATION GATE FAILED — {failures} case(s) drifted.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
