"""WS0 migration gate for checkers_network.py — the pure-HTTP target-apex probes.

Covers SecurityPolicyChecker.check (security.txt 959 + robots 976),
VPNRemoteAccessChecker.check (421), DNSInfrastructureChecker._fingerprint_server
(728). The crt.sh call in SubdomainChecker.check (168) and the subdomain-takeover
probes (_check_cname_takeover 109/116) are migrated too but sit behind brute-force
DNS/socket enumeration that can't be driven deterministically offline — crt.sh is
the identical pattern already gated in mig_small_providers (related_domain_discovery),
and the takeover fallback is covered by review.

Offline, no keys. Workflow (files already migrated, so record under a stash):
    git stash push -- security_scanner/checkers_network.py
    py tooling/regression/mig_checkers_network.py --record
    git stash pop
    py tooling/regression/mig_checkers_network.py
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


def _fake(session_self, method, url, **kwargs):
    if "robots.txt" in url:
        body, hdrs = b"User-agent: *\nDisallow: /admin\nDisallow: /private\n", {}
    elif "security.txt" in url:
        body, hdrs = b"Contact: mailto:security@examplecorp.co.za\nEncryption: https://x/pgp\n", {}
    else:
        body = b"<html><body>Welcome to Example Corp. Nothing to see here.</body></html>"
        hdrs = {"Server": "nginx/1.24", "X-Powered-By": "PHP/8.2"}
    r = requests.models.Response()
    r.status_code = 200
    r._content = body
    r._content_consumed = True
    r.encoding = "utf-8"
    r.url = url
    r.headers = requests.structures.CaseInsensitiveDict({"Content-Type": "text/plain", **hdrs})
    return r


def _cases():
    import checkers_network as cn
    return {
        "net_security_policy": lambda: cn.SecurityPolicyChecker().check("examplecorp.co.za"),
        "net_vpn": lambda: cn.VPNRemoteAccessChecker().check("examplecorp.co.za"),
        "net_fingerprint": lambda: cn.DNSInfrastructureChecker()._fingerprint_server("examplecorp.co.za"),
    }


def _with_fake(fn):
    import requests.sessions as S
    orig = S.Session.request
    S.Session.request = _fake
    try:
        return fn()
    finally:
        S.Session.request = orig


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", action="store_true")
    args = ap.parse_args()
    cases = _cases()
    if args.record:
        for name, fn in cases.items():
            s = _with_fake(lambda fn=fn: cg.record_baseline(name, fn))
            print(f"[record] {name:22s} {s['requests']} request(s) frozen")
        print("\nBaselines frozen. Restore migrated file, then re-run without --record.")
        return 0
    failures = 0
    for name, fn in cases.items():
        r = _with_fake(lambda fn=fn: cg.verify(name, fn))
        print(r)
        failures += 0 if r.ok else 1
    print()
    print("MIGRATION GATE PASSED — checkers_network apex probes preserved." if not failures
          else f"MIGRATION GATE FAILED — {failures} case(s) drifted.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
