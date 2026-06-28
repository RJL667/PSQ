"""WS0 migration gate for checkers_threats.py — free providers + target apex.

Per the "test with the free providers" directive, this gates the no-key call sites:
TechStack apex (98), OSV (query_version), and the ShodanVuln enrichment feeds
NVD/KEV/MSF/ExploitDB/EPSS. The paid-provider sites in this module (HIBP, Shodan,
IntelX, DeHashed, VirusTotal, SecurityTrails, HudsonRock, InternetDB-enrichment)
are migrated with the identical pattern already gated in origin_discovery /
darkweb_providers / credential_export / mig_small_providers, and are import-smoke
tested; real-key gold baselines are the remaining follow-up.

Offline. Workflow (file already migrated, so record under a stash):
    git stash push -- security_scanner/checkers_threats.py
    py tooling/regression/mig_checkers_threats.py --record
    git stash pop
    py tooling/regression/mig_checkers_threats.py
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

_J = {
    "osv.dev": b'{"vulns":[{"id":"GHSA-jfh8-c2jp-5v3q","summary":"Log4Shell",'
               b'"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L"}],'
               b'"aliases":["CVE-2021-44228"],"affected":[]}]}',
    "nvd.nist.gov": b'{"vulnerabilities":[{"cve":{"id":"CVE-2021-44228",'
                    b'"descriptions":[{"lang":"en","value":"Log4Shell RCE"}],'
                    b'"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":10.0,'
                    b'"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N"}}]},'
                    b'"published":"2021-12-10T00:00Z","references":[{"tags":["Patch"]}]}}]}',
    "cisa.gov": b'{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}',
    "metasploit": b'{"mod1":{"references":["CVE-2021-44228","URL-https://x"]}}',
    "exploit": b"id,file,description,codes,date\n50592,x.py,Log4Shell,CVE-2021-44228,2021-12-10\n",
    "first.org": b'{"data":[{"cve":"CVE-2021-44228","epss":"0.97560","percentile":"0.99"}]}',
}


def _fake(session_self, method, url, **kwargs):
    body = b"{}"
    if "/CHANGELOG.txt" in url:
        body = b"Drupal 7.0, 2011-01-05\n"
    else:
        for needle, b in _J.items():
            if needle in url:
                body = b
                break
        else:
            body = (b"<html><head><title>Example Corp</title></head>"
                    b"<body>Welcome</body></html>")
    r = requests.models.Response()
    r.status_code = 200
    r._content = body
    r._content_consumed = True
    r.encoding = "utf-8"
    r.url = url
    r.headers = requests.structures.CaseInsensitiveDict(
        {"Content-Type": "application/json", "Server": "nginx/1.24"})
    return r


def _cases():
    import checkers_threats as ct
    return {
        "threats_techstack": lambda: ct.TechStackChecker().check("examplecorp.co.za"),
        "threats_osv": lambda: {"v": ct.OSVChecker().query_version("django", "3.0.0", "PyPI")},
        "threats_nvd": lambda: ct.ShodanVulnChecker()._fetch_cvss("CVE-2021-44228"),
        "threats_kev": lambda: {"kev": sorted(ct.ShodanVulnChecker()._load_kev())},
        "threats_msf": lambda: {"msf": sorted(ct.ShodanVulnChecker()._load_msf_modules())},
        "threats_exploitdb": lambda: {"edb": sorted(ct.ShodanVulnChecker()._load_exploitdb_cves())},
        "threats_epss": lambda: ct.ShodanVulnChecker()._fetch_epss(["CVE-2021-44228"]),
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
    print("MIGRATION GATE PASSED — checkers_threats free-provider sites preserved." if not failures
          else f"MIGRATION GATE FAILED — {failures} case(s) drifted.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
