# -*- coding: utf-8 -*-
"""Adversarial ground-truth gate for the network/port checkers (BLOCKING).

The golden-replay and cassette harnesses prove *stability* (output == baseline)
and HTTP-replay fidelity. Neither tests *plausibility* against adversarial
inputs, and neither covers the raw-socket port scan. This gate does: it drives
the real checker code with socket-level mocks for known adversarial cases and
asserts the CORRECT classification — the thing a human analyst would assert on
sight, encoded once so it runs on every change with no human in the loop.

Each scenario is a labelled ground truth:
  - tarpit            : SYN-ACKs every port, no banners  -> ALL findings dropped
  - real_mail_host    : 21/110/143 w/ banners, TLS ports -> kept, banner-confirmed
  - cdn_edge          : 80/443, cloudflare 403 on 80     -> kept
  - real_exposed_db   : MongoDB 27017 genuinely open      -> REPORTED (no over-drop)

Run: py tooling/regression/adversarial_gate.py   (exit 1 on any mismatch)
This file is wired into the pre-push hook so the tarpit false-positive — and any
regression of the saturated-host gate — can never ship again.
"""
import os, sys, socket
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SEC = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, SEC)

import checkers_network as cn
import checkers_threats as ct
import ip_classification as ipc
import scanner as sc


class _FakeSocket:
    """Per-probe fake. `open` is a set of open ports or the string "ALL"."""
    def __init__(self, scenario):
        self._sc = scenario
        self._port = None

    def settimeout(self, _):
        pass

    def connect_ex(self, addr):
        self._port = addr[1]
        openset = self._sc["open"]
        is_open = (openset == "ALL") or (self._port in openset)
        return 0 if is_open else 111  # 111 = ECONNREFUSED (closed)

    def sendall(self, _):
        pass

    def recv(self, _):
        return self._sc["banners"].get(self._port, b"")

    def close(self):
        pass


def _run(scenario):
    """Run both network checkers against a mocked host; return (scan, hrp)."""
    cn._saturated_host_cache.clear()
    factory = lambda *a, **k: _FakeSocket(scenario)
    with mock.patch.object(cn.socket, "socket", factory):
        scan = cn.DNSInfrastructureChecker()._scan_ports("target.example", scenario["ip"])
        hrp = cn.HighRiskProtocolChecker().check("target.example", scenario["ip"])
    return scan, hrp


# ---- ground-truth scenarios -------------------------------------------------
SCENARIOS = {
    "tarpit": {
        "ip": "10.9.9.1", "open": "ALL", "banners": {},
        "expect_scan_ports": set(),          # everything discarded
        "expect_hrp_ports": set(),
    },
    "real_mail_host": {
        "ip": "10.9.9.2", "open": {21, 110, 143, 443, 993, 995},
        "banners": {21: b"220 Pure-FTPd", 110: b"+OK Dovecot ready",
                    143: b"* OK Dovecot ready"},
        "expect_scan_ports": {21, 110, 143, 443, 993, 995},
        "expect_hrp_ports": set(),            # no CRITICAL_SERVICES port open
        "expect_confirmed": {21: True, 443: False},
    },
    "cdn_edge": {
        "ip": "10.9.9.3", "open": {80, 443},
        "banners": {80: b"HTTP/1.1 403 Forbidden\r\nServer: cloudflare"},
        "expect_scan_ports": {80, 443},
        "expect_hrp_ports": set(),
    },
    "real_exposed_db": {                      # TRUE positive — must NOT be dropped
        "ip": "10.9.9.4", "open": {443, 27017},
        "banners": {},
        "expect_scan_ports": {443},           # 27017 not in port-scan ALL_PORTS
        "expect_hrp_ports": {27017},          # but IS a CRITICAL_SERVICE -> reported
    },
}


# ---- IP-attribution ground truth (real takealot.com hosts, 2026-06-30) -------
# (label, ip, reverse_dns, org, banner) -> expected ip_classification bucket.
# Encodes the own-vs-vendor judgment that keeps third-party infrastructure (a
# HostRocket shared host's FTP / "exposed Jupyter", CDN edges, managed LBs) out
# of the insured's OWN attack surface, while still scanning the insured's own
# IaaS VMs (an exposed Jenkins/Elasticsearch on their EC2/GCE is THEIR risk).
# Without this gate the subdomain-IP path attributes 41 third-party hosts to the
# target as its own exposure (the bug this audit found).
CLASSIFY_SCENARIOS = [
    # --- vendor-operated -> third-party (NOT scanned/attributed as own) ---
    ("hostrocket_sharedhost", "66.147.238.15", "dirapp84.directorysecure.com",
     "HostRocket Web Services", "220 Pure-FTPd", ipc.SAAS),
    ("cloudfront_edge", "143.204.4.4", "server-143-204-4-4.jnb51.r.cloudfront.net",
     None, "CloudFront", ipc.CDN),
    ("akamai_edge", "23.196.227.231", "a23-196-227-231.deploy.static.akamaitechnologies.com",
     None, "AkamaiGHost", ipc.CDN),
    ("cloudflare_no_ptr", "104.16.71.64", None, None,
     "HTTP/1.1 403 Forbidden\r\nServer: cloudflare", ipc.CDN),
    ("salesforce_exacttarget", "13.111.150.233", "ja233.mta.exacttarget.com",
     None, None, ipc.SAAS),
    ("zendesk_org_only", "216.198.54.99", None, "Zendesk, Inc.", "", ipc.SAAS),
    ("aws_elb_managed", "108.132.68.82", "ec2-108-132-68-82.eu-west-1.compute.amazonaws.com",
     None, "awselb/2.0", ipc.CDN),   # ec2-style PTR but managed LB banner -> NOT owned
    # --- insured-operated -> OWNED (scanned + attributed as the insured's) ---
    ("aws_ec2_vm", "3.92.120.28", "ec2-3-92-120-28.compute-1.amazonaws.com",
     "Amazon Data Services", "", ipc.OWNED),
    ("gce_vm", "104.199.105.60", "60.105.199.104.bc.googleusercontent.com",
     None, "", ipc.OWNED),
    ("insured_dc_no_signal", "102.219.50.40", None, None, "", ipc.OWNED),
    # --- private (internal host leaked in public DNS) -> never scanned ---
    ("rfc1918_fortiauth", "10.0.1.250", None, None, None, ipc.PRIVATE),
    ("rfc1918_elasticsearch", "10.28.32.100", None, None, None, ipc.PRIVATE),
]


def _check_classification(failures):
    for label, ip, rdns, org, banner, expected in CLASSIFY_SCENARIOS:
        got, _provider = ipc.classify_ip(ip, reverse_dns=rdns, org=org, banner=banner)
        ok = (got == expected)
        if not ok:
            failures.append(f"classify[{label}]: {ip} -> {got!r} != expected {expected!r}")
        print(f"  [{'PASS' if ok else 'FAIL'}] classify:{label:<24} -> {got}")


# ---- CVE<->software matching ground truth (checker audit, 2026-07-01) ---------
# (label, port, detected_version, cves_kept?, confidence), driven through the REAL
# DNSInfrastructureChecker._assess_risk. Port-template CVEs must DROP when the
# banner names a different product (Pure-FTPd must not carry ProFTPD CVEs; a
# Postfix host must not carry Exim CVEs), and be KEPT + flagged version-unconfirmed
# when the software matches or can't be fingerprinted. Also guards the two data
# errors this audit removed (Sudo CVE-2021-3156 on :25, Postfix CVE-2011-1720 on :110).
CVE_GATE_SCENARIOS = [
    ("ftp_pure_ftpd_drops_proftpd", 21,  "Pure-FTPd 1.0.47",     False, "software_mismatch"),
    ("ftp_proftpd_keeps",           21,  "ProFTPD 1.3.5 Server", True,  "software_match"),
    ("ftp_no_banner_keeps",         21,  "",                     True,  "port_inferred"),
    ("ssh_openssh_keeps",           22,  "OpenSSH_8.9p1 Ubuntu", True,  "software_match"),
    ("ssh_dropbear_drops",          22,  "Dropbear sshd",        False, "software_mismatch"),
    ("smtp_postfix_drops_exim",     25,  "mail ESMTP Postfix",   False, "software_mismatch"),
    ("smtp_exim_keeps",             25,  "mail ESMTP Exim 4.94", True,  "software_match"),
    ("pop3_dovecot_keeps",          110, "Dovecot ready.",       True,  "software_match"),
]


def _check_cve_gating(failures):
    for label, port, ver, kept, conf in CVE_GATE_SCENARIOS:
        p = {"port": port, "service": "x", "risk": "high"}
        if ver:
            p["detected_version"] = ver
        cn.DNSInfrastructureChecker()._assess_risk([p])
        has_cves = bool(p.get("notable_cves"))
        ok = (has_cves == kept) and (p.get("cve_confidence") == conf)
        if not ok:
            failures.append(f"cve_gate[{label}]: kept={has_cves}!={kept} "
                            f"conf={p.get('cve_confidence')!r}!={conf!r}")
        print(f"  [{'PASS' if ok else 'FAIL'}] cve_gate:{label:<28} kept={has_cves} conf={p.get('cve_confidence')}")
    # Data-error guards — the wrong-software/wrong-protocol CVEs must stay removed.
    PI = cn.DNSInfrastructureChecker.PORT_INTEL
    for label, port, bad in (("sudo_off_smtp_25", 25, "CVE-2021-3156"),
                             ("postfix_off_pop3_110", 110, "CVE-2011-1720")):
        gone = bad not in PI[port]["notable_cves"]
        if not gone:
            failures.append(f"cve_gate[{label}]: {bad} still in PORT_INTEL[{port}]")
        print(f"  [{'PASS' if gone else 'FAIL'}] cve_gate:{label:<28} {bad} removed")


# ---- TechStack EOL: header-authoritative, no body-substring FP (2026-07-01) ----
# EOL server-component version tokens (PHP/nginx/Apache/IIS/Tomcat/Node/Python/
# OpenSSL) must be matched against the response HEADERS only. The page BODY was
# previously included, so any incidental mention of an old version — a hosting
# page listing supported PHP versions, a `docs.python.org/2.7` link, an embedded
# code sample — invented a phantom EOL finding (up to a -40 CRITICAL) for software
# the target never runs. Drives the REAL TechStackChecker.check() with a mocked
# HTTP response.
class _FakeResp:
    def __init__(self, headers, body, status=200):
        self.headers = headers
        self.text = body
        self.status_code = status


TECHSTACK_EOL_SCENARIOS = [
    # label, response headers, response body, expected eol `software` set
    ("eol_in_server_header", {"Server": "nginx/1.14"}, "<html>clean</html>", {"nginx/1.14"}),
    ("eol_in_xpoweredby", {"X-Powered-By": "PHP/7.2"}, "<html>clean</html>", {"PHP/7.2"}),
    ("eol_only_in_body_ignored", {"Server": "cloudflare"},
     "<html>We support php/7.2, php/7.4 and php/8.1 - see docs.python.org/2.7</html>", set()),
    ("supported_version_not_flagged", {"Server": "nginx/1.27"}, "<html>clean</html>", set()),
]


def _check_techstack_eol(failures):
    for label, headers, body, expect in TECHSTACK_EOL_SCENARIOS:
        resp = _FakeResp(headers, body)
        with mock.patch.object(ct.HTTP, "get", lambda *a, **k: resp):
            r = ct.TechStackChecker().check("target.example")
        got = {e["software"] for e in r.get("eol_detected", [])}
        ok = (got == expect)
        if not ok:
            failures.append(f"techstack_eol[{label}]: {sorted(got)} != expected {sorted(expect)}")
        print(f"  [{'PASS' if ok else 'FAIL'}] techstack_eol:{label:<28} eol={sorted(got)}")


# ---- VPN apex RDP probe: tarpit-gated (2026-07-02) ----
# VPNRemoteAccessChecker probes 3389 on the apex with a raw socket. A saturated
# host (tarpit / IPS / LB that SYN-ACKs every port) makes that connect() succeed
# and would fabricate "RDP exposed" -- the single largest RSI signal (+0.20) plus
# a 40-pt vpn_risk hit. The probe must gate on is_saturated_host like the port
# scanner does. Drives the REAL VPNRemoteAccessChecker.check() with a mocked
# socket (fake connect_ex) + resolver + HTTP so no packet leaves the box.
VPN_RDP_SCENARIOS = [
    # label, open ports (or "ALL"), expected rdp_exposed
    ("tarpit_apex_suppressed", "ALL", False),  # 3389 + canaries answer -> tarpit -> suppressed
    ("real_rdp_flagged", {3389}, True),         # 3389 open, canaries closed -> real exposure kept
    ("no_rdp", {443}, False),                    # 3389 closed -> not exposed
]


def _check_vpn_rdp_tarpit(failures):
    for label, openset, expect in VPN_RDP_SCENARIOS:
        cn._saturated_host_cache.clear()
        scenario = {"open": openset, "banners": {}, "ip": "10.9.9.9"}
        sock_factory = lambda *a, **k: _FakeSocket(scenario)
        with mock.patch.object(cn.socket, "socket", sock_factory), \
             mock.patch.object(cn.socket, "gethostbyname", lambda *a, **k: scenario["ip"]), \
             mock.patch.object(cn.HTTP, "get", lambda *a, **k: None), \
             mock.patch.object(cn.HTTP, "stop_probing", lambda *a, **k: False):
            r = cn.VPNRemoteAccessChecker().check("target.example")
        got = bool(r.get("rdp_exposed"))
        ok = (got == expect)
        if not ok:
            failures.append(f"vpn_rdp[{label}]: rdp_exposed={got} != expected {expect}")
        print(f"  [{'PASS' if ok else 'FAIL'}] vpn_rdp:{label:<28} rdp_exposed={got}")


# ---- Dehashed corporate/staff attribution: boundary-match not substring (2026-07-02) ----
# DehashedChecker classifies corporate-vs-personal and builds the masked staff list
# by mailbox domain. The old `domain in email` substring counted lookalike / adjacent
# domains (evil-takealot.com, takealot.company.co.za -- both CONTAIN "takealot.com")
# as the insured's OWN staff, inflating the staff-account attribution shown to the
# broker (reporting-only; the score uses Dehashed's server-side `total`). Drives the
# REAL check() with a mocked Dehashed v2 API response.
class _FakeDehashedResp:
    def __init__(self, entries):
        self.status_code = 200
        self._entries = entries

    def json(self):
        return {"entries": self._entries, "total": len(self._entries)}


DEHASHED_ATTR_ENTRIES = [
    {"email": ["ceo@takealot.com"]},            # on-domain       -> staff
    {"email": ["it@mail.takealot.com"]},         # subdomain       -> staff
    {"email": ["victim@evil-takealot.com"]},     # lookalike       -> NOT staff
    {"email": ["user@takealot.company.co.za"]},  # adjacent domain -> NOT staff
    {"email": ["someone@gmail.com"]},            # personal        -> NOT staff
]


def _check_dehashed_attribution(failures):
    resp = _FakeDehashedResp(DEHASHED_ATTR_ENTRIES)
    with mock.patch.object(ct.DEHASHED, "post", lambda *a, **k: resp):
        r = ct.DehashedChecker().check("takealot.com", api_key="gate-test-key")
    staff = int(r.get("staff_accounts_total", -1))
    corp = int((r.get("credential_breakdown") or {}).get("corporate_count", -1))
    ok = (staff == 2 and corp == 2)
    if not ok:
        failures.append(f"dehashed_attr: staff={staff} corporate={corp} != 2/2 "
                        "(lookalike/adjacent domains must not count as own-staff)")
    print(f"  [{'PASS' if ok else 'FAIL'}] dehashed_attr: staff={staff} corporate={corp} (expect 2/2)")


# ---- Credential-risk tier: staff vs customer-only infostealer (Sarel calib 2026-07-02) ----
# hudson_rock "users" (customer-device infections) must NOT reach the same CRITICAL
# credential tier as "employees" (staff = the insured's own corporate-credential
# compromise). Staff-fresh: CRITICAL (breached) / HIGH (alone). Customer-ONLY-fresh:
# capped one tier lower -- HIGH (breached) / MEDIUM (alone). Drives the REAL
# build_credential_correlation() (a pure function -- synthetic cat_results, no mocks).
def _cc_fixture(emp, usr, days, de_total):
    return {
        "hudson_rock": {"status": "completed", "compromised_employees": emp,
                        "compromised_users": usr, "days_since_compromise": days},
        "dehashed": {"total_entries": de_total},
    }


CRED_CALIB_SCENARIOS = [
    # label, employees, users, days_since, dehashed_total, expected severity
    ("staff_fresh_breached", 2, 0, 10, 100, "critical"),
    ("staff_fresh_alone", 2, 0, 10, 0, "high"),
    ("customer_only_fresh_breached", 0, 5000, 10, 100, "high"),   # was CRITICAL pre-calib
    ("customer_only_fresh_alone", 0, 5000, 10, 0, "medium"),      # was HIGH pre-calib
]


def _check_cred_calibration(failures):
    for label, emp, usr, days, det, expect in CRED_CALIB_SCENARIOS:
        out = sc.build_credential_correlation(_cc_fixture(emp, usr, days, det))
        got = out.get("severity")
        ok = (got == expect)
        if not ok:
            failures.append(f"cred_calib[{label}]: severity={got} != expected {expect}")
        print(f"  [{'PASS' if ok else 'FAIL'}] cred_calib:{label:<30} severity={got}")


# ---- Subdomain CT union: crt.sh + certspotter fallback + low-coverage flag (#7, 2026-07-02) ----
# crt.sh is flaky; a single failure used to drop enumeration to brute-only (~16 vs
# ~90 subdomains -- the #7 non-determinism that made scan-to-scan deltas meaningless).
# Now crt.sh + certspotter are queried in parallel and UNIONed; `low_coverage` flags
# the scan ONLY when BOTH CT sources fail. Drives the REAL SubdomainChecker.check()
# with the two CT helpers + the DNS-dependent methods mocked (no packet leaves the box).
SUBDOMAIN_CT_SCENARIOS = [
    # label, crtsh names, certspotter names, (ct_count, ct_source_ok, low_coverage, sources)
    ("both_ct_sources", {"a.x.com", "b.x.com"}, {"b.x.com", "c.x.com"}, 3, True, False, ["certspotter", "crtsh"]),
    ("crtsh_flaked", set(), {"b.x.com", "c.x.com"}, 2, True, False, ["certspotter"]),
    ("certspotter_flaked", {"a.x.com"}, set(), 1, True, False, ["crtsh"]),
    ("both_ct_failed", set(), set(), 0, False, True, []),
]


def _check_subdomain_ct(failures):
    for label, crt, cs, exp_ct, exp_ok, exp_low, exp_src in SUBDOMAIN_CT_SCENARIOS:
        with mock.patch.object(cn.SubdomainChecker, "_ct_crtsh", staticmethod(lambda d, _r=frozenset(crt): set(_r))), \
             mock.patch.object(cn.SubdomainChecker, "_ct_certspotter", staticmethod(lambda d, _r=frozenset(cs): set(_r))), \
             mock.patch.object(cn.SubdomainChecker, "_wildcard_ips", lambda self, d: set()), \
             mock.patch.object(cn.SubdomainChecker, "_resolves", lambda self, h: None), \
             mock.patch.object(cn.SubdomainChecker, "_check_cname_takeover", lambda self, s: None):
            r = cn.SubdomainChecker().check("x.com")
        got = (r.get("ct_count"), r.get("ct_source_ok"), r.get("low_coverage"),
               sorted(r.get("ct_sources") or []))
        want = (exp_ct, exp_ok, exp_low, sorted(exp_src))
        ok = got == want
        if not ok:
            failures.append(f"subdomain_ct[{label}]: {got} != {want}")
        print(f"  [{'PASS' if ok else 'FAIL'}] subdomain_ct:{label:<22} "
              f"ct={got[0]} ok={got[1]} low={got[2]} src={got[3]}")


def main():
    failures = []
    _check_classification(failures)
    _check_cve_gating(failures)
    _check_techstack_eol(failures)
    _check_vpn_rdp_tarpit(failures)
    _check_dehashed_attribution(failures)
    _check_cred_calibration(failures)
    _check_subdomain_ct(failures)
    for name, sc in SCENARIOS.items():
        scan, hrp = _run(sc)
        scan_ports = {e["port"] for e in scan}
        hrp_ports = {e["port"] for e in hrp.get("exposed_services", [])}
        ok = True
        if scan_ports != sc["expect_scan_ports"]:
            failures.append(f"{name}: scan ports {sorted(scan_ports)} != expected {sorted(sc['expect_scan_ports'])}")
            ok = False
        if hrp_ports != sc["expect_hrp_ports"]:
            failures.append(f"{name}: high-risk ports {sorted(hrp_ports)} != expected {sorted(sc['expect_hrp_ports'])}")
            ok = False
        for port, want in sc.get("expect_confirmed", {}).items():
            got = next((e.get("confirmed") for e in scan if e["port"] == port), None)
            if got != want:
                failures.append(f"{name}: port {port} confirmed={got} != expected {want}")
                ok = False
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<18} scan={sorted(scan_ports)} high-risk={sorted(hrp_ports)}")

    print("=" * 70)
    if failures:
        print(f"ADVERSARIAL GATE FAILED ({len(failures)}):")
        for f in failures:
            print("  -", f)
        sys.exit(1)
    print(f"ADVERSARIAL GATE PASS — {len(SCENARIOS)} socket + {len(CLASSIFY_SCENARIOS)} "
          f"ip-attribution + {len(CVE_GATE_SCENARIOS)} cve-gating + "
          f"{len(TECHSTACK_EOL_SCENARIOS)} techstack-eol + {len(VPN_RDP_SCENARIOS)} "
          f"vpn-rdp + 1 dehashed-attr + {len(CRED_CALIB_SCENARIOS)} cred-calib + "
          f"{len(SUBDOMAIN_CT_SCENARIOS)} subdomain-ct ground-truth scenarios")


if __name__ == "__main__":
    main()
