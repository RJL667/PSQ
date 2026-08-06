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
sys.path.insert(0, os.path.join(SEC, "tooling"))   # breach_web_discovery (SCN-040)

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


# ---- credential_correlation REPORTING card: staff vs customer-only tier (2026-07-02) ----
# LABEL NOTE: this tests build_credential_correlation, the REPORTING-ONLY cross-
# correlation join (no scoring weight). It does NOT test the RSI. The RSI-driving
# credential tier (CredentialRiskClassifier.classify) separately + already floors
# customer-only (hr_users) to HIGH and staff (hr_employees) to CRITICAL. This gate
# just locks the reporting card to the SAME staff-vs-customer distinction: staff-fresh
# CRITICAL (breached) / HIGH (alone); customer-ONLY-fresh capped one tier lower, HIGH
# (breached) / MEDIUM (alone). Pure function -- synthetic cat_results, no mocks.
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


# ---- Breach-intel: company matching + fail-safe + recency ladder (SCN-040/041) ----
# Three distinct failure modes, all observed live on the 2026-07-27 mip.co.za scan
# or designed against it:
#
#  (a) COMPANY MATCHING. title_is_about() used a substring test, so the 3-letter
#      token "mip" matched nine unrelated ransomware victims (bMIProjects.de,
#      ekonoMIPoolen.se, MIPa.com.br, luMIPlan.com, MIPS Technologies, MIPe.com,
#      euroMIP.fr). That mattered because a leak-site listing FLOORS the verdict at
#      "confirmed" -- a short company token could have asserted a breach at a
#      company that was never breached. Same class as the Dehashed attribution bug.
#  (b) FAIL-SAFE SCORING. The search engine degrades SILENTLY to snippets when its
#      key is missing/rotated/unfunded. An unresearched scan must therefore never
#      score as clean: researched_breach_risk() must return None for every
#      non-conclusive state so the HIBP value is kept rather than a falsely low one.
#  (c) RECENCY LADDER. Owner calibration: recency drives impact, not count, and the
#      first year is cut into quarters because the post-breach recovery window is
#      itself the elevated-risk period.
BREACH_FP_VICTIMS = [           # live ransomware.live rows for keyword "mip"
    "bmiprojects.de", "ekonomipoolen.se/Sweden/32/GB", "Ekonomipoolen",
    "mipa.com.br", "lumiplan.com", "MIPS Technologies", "mipe.com", "euromip.fr",
]
BREACH_TRUE_MATCHES = [
    ("MIP Holdings", "Mip"), ("mip.co.za", "Mip"), ("BELFOR", "BELFOR"),
    ("Takealot Fulfilment Solutions employee blunder leads to leak", "Takealot"),
    ("Dis-Chem data breach affects 3.68 million customers", "Dis-Chem"),
]
BREACH_TRUE_NEGATIVES = [
    ("Naspers reports jump in ecommerce profit", "Takealot"),
    ("Chemical spill at DisChemicals plant", "Dis-Chem"),
]
# (months_since, verdict) -> expected category risk, expected RSI impact
BREACH_LADDER = [
    (1,    "confirmed", 90.0, 0.16),   # inside the recovery window
    (4,    "confirmed", 90.0, 0.14),
    (7,    "confirmed", 90.0, 0.12),
    (11,   "confirmed", 90.0, 0.10),
    (18,   "confirmed", 70.0, 0.06),
    (30,   "confirmed", 45.0, 0.03),
    (48,   "confirmed", 25.0, 0.00),   # RSI factor has decayed out
    (80,   "confirmed", 10.0, 0.00),
    (1,    "reported",  63.0, 0.112),  # single-source -> x0.70 on both channels
    (None, "confirmed", 50.0, 0.04),   # confirmed but undated
]
BREACH_FAILSAFE = [             # every one must contribute NOTHING
    ("no_api_key", "unknown"), ("error", "unknown"),
    ("completed", "none"), ("completed", "possible"),
]
# Mid-scan key failure: the key is probed BEFORE the research, so it can die
# during it (revoked, rotated, or -- as happened in production -- the AI Studio
# credits running out between probe and synthesis). The engine then degrades to
# headline-matching, whose "most recent" date is the earliest ARTICLE date, not
# the incident date: for Dis-Chem that is a 2025 follow-up piece about a 2022
# breach, which would score a three-year-old incident as if it were last quarter.
# A degraded result must therefore never reach the recency lever.
BREACH_DEGRADED = [
    ("researched confirmed",     {"researched": True},  True),
    ("degraded confirmed",       {"researched": False}, False),
    ("legacy (flag absent)",     {},                    True),
]
# (d) KEY-PROBE STATUS MAPPING. Everything above depends on check_key() correctly
# calling a dead key dead — it is the trigger for the 503 readiness alarm, the
# submission-time warning and the UNASSESSED verdict. Google rejects a bad key
# with a code that depends on the key FORMAT, which the 2026-07-27 alarm drill
# exposed: our production key is the new "AQ.…" style, whose rejection is 401,
# and 401 was NOT in the rejected set — so a genuinely revoked production key
# fell through to the generic "error" branch, which reported no fingerprint and
# no remediation hint. The alarm still fired, but the on-call operator would have
# been told "error" instead of "key rejected — rotated or revoked", and could not
# see WHICH key was failing. Mapping is asserted here per HTTP code, offline.
#   (label, listing_code, generation_code, expected_status, expect_fingerprint)
KEY_PROBE_SCENARIOS = [
    ("revoked AQ.-style",    401, None, "inactive",         True),
    ("revoked AIza-style",   400, None, "inactive",         True),
    ("wrong key type",       403, None, "inactive",         True),
    ("valid but unfunded",   200,  429, "quota_exhausted",  True),
    ("healthy",              200,  200, "active",           True),
    ("transient upstream",   503, None, "error",            True),
]


# (e) DATASTORE FALLBACK. scanner_db silently falls back to SQLite when
# DATABASE_URL is unset. That is right for dev and catastrophic in production:
# on 2026-07-27 a clobbered .env dropped DATABASE_URL and the scanner came up
# serving a stale legacy scans.db while the real Postgres history sat untouched,
# with /health AND /health/providers both green the whole time. Nothing errored,
# so nothing alarmed -- the same shape as a dead web-search key reporting a
# clean breach history. The readiness probe must therefore treat an unasked-for
# SQLite fallback as degraded (503), while still allowing a deliberate dev
# SQLite run via SCANNER_ALLOW_SQLITE.
#   (label, DATABASE_URL set?, SCANNER_ALLOW_SQLITE, expect_degraded, expect_status)
DATASTORE_SCENARIOS = [
    ("postgres configured",     True,  "",  False, "postgres"),
    ("silent sqlite fallback",  False, "",  True,  "sqlite_fallback"),
    ("sqlite asked for (dev)",  False, "1", False, "sqlite"),
    ("postgres + dev flag",     True,  "1", False, "postgres"),
]


def _check_datastore_readiness(failures):
    import importlib
    app_mod = importlib.import_module("app")
    for label, has_url, allow, want_degraded, want_status in DATASTORE_SCENARIOS:
        env = {"SCANNER_ALLOW_SQLITE": allow}
        if has_url:
            env["DATABASE_URL"] = "postgresql://u:p@localhost:5544/db"
        with mock.patch.dict(os.environ, env, clear=False):
            if not has_url:
                os.environ.pop("DATABASE_URL", None)
            # Re-point scanner_db at the patched env, and keep the probe offline.
            import scanner_db
            scanner_db.configure(database_url=os.environ.get("DATABASE_URL"),
                                 sqlite_path=":memory:")
            with mock.patch("websearch.check_key_cached",
                            return_value={"status": "active",
                                          "key_fingerprint": "test", "cached": True}), \
                 app_mod.app.test_client() as client:
                resp = client.get("/health/providers")
                body = resp.get_json() or {}
        ds = (body.get("providers") or {}).get("datastore", {})
        got_status = ds.get("status")
        got_degraded = "datastore" in (body.get("degraded") or [])
        code_ok = resp.status_code == (503 if want_degraded else 200)
        ok = (got_status == want_status) and (got_degraded == want_degraded) and code_ok
        if not ok:
            failures.append(
                f"datastore[{label}]: status={got_status!r} (want {want_status!r}), "
                f"degraded={got_degraded} (want {want_degraded}), "
                f"http={resp.status_code} — an unasked-for SQLite fallback must "
                "raise the readiness alarm, otherwise the scanner can serve a stale "
                "database while every health check reports green")
        print(f"  [{'PASS' if ok else 'FAIL'}] datastore:{label:<22} "
              f"{got_status} degraded={got_degraded} http={resp.status_code}")
    # leave the module pointed somewhere harmless for any later check
    import scanner_db
    scanner_db.configure(database_url=None, sqlite_path=":memory:")


# (g) CREDENTIAL PROVIDERS MUST FAIL CLOSED. A dead or unfunded DeHashed/IntelX
# produced a report that read CLEAN rather than unassessed - the same silent
# degradation the breach-history checker was deliberately built to avoid, never
# applied to these two. Four distinct leaks, all observed in code:
#   * IntelX returns a 200 with NO search id once the daily free allowance is
#     gone; the checker returned status="completed", total_results=0, which is
#     byte-identical to a genuinely clean domain.
#   * A failed result-poll (402/429/5xx) broke out of the loop with records=[]
#     and status still "completed".
#   * The Data Breach Index defaulted total_entries to 0 for any status except
#     no_api_key/auth_failed, taking the FULL-MARKS 20/20 clean branch - so a
#     BROKEN provider scored better than an ABSENT one (10/20 "Unknown").
#   * CredentialRiskClassifier never read the status at all: no records meant
#     class NONE / risk LOW plus the affirmative "exposure is historical and/or
#     email-only" summary. That is the RSI-driving channel.
# Every non-conclusive status must reach the scorer as "we did not look".
NON_CONCLUSIVE = ["error", "timeout", "quota_exhausted", "subscription_required",
                  "no_api_key", "auth_failed"]


def _check_credential_failclosed(failures):
    import importlib
    ct_mod = importlib.import_module("checkers_threats")
    sa = importlib.import_module("scoring_analytics")

    # (1) the classifier must refuse to classify an unsearched estate
    for st in NON_CONCLUSIVE:
        res = ct_mod.CredentialRiskClassifier.classify(
            {"status": st, "breach_details": [], "total_entries": 0}, {}, {})
        lvl, assessed = res.get("risk_level"), res.get("assessed", True)
        ok = (lvl == "UNKNOWN") and (assessed is False) \
            and "NOT ASSESSED" in (res.get("summary") or "")
        if not ok:
            failures.append(
                f"cred_failclosed[classify/{st}]: risk_level={lvl!r} assessed={assessed} "
                "— an unsearched credential estate must report UNKNOWN/unassessed, "
                "never LOW with a reassuring summary; this channel drives the RSI")
        print(f"  [{'PASS' if ok else 'FAIL'}] cred_failclosed:classify/{st:<22} "
              f"{lvl} assessed={assessed}")

    # (2) a healthy-but-genuinely-clean lookup must STILL score clean (no over-correction)
    clean = ct_mod.CredentialRiskClassifier.classify(
        {"status": "completed", "breach_details": [], "total_entries": 0}, {}, {})
    ok = clean.get("risk_level") == "LOW" and clean.get("assessed", True) is not False
    if not ok:
        failures.append(f"cred_failclosed[classify/genuinely-clean]: {clean.get('risk_level')!r} "
                        "— a real empty result must still read LOW, or we have swapped "
                        "one wrong answer for another")
    print(f"  [{'PASS' if ok else 'FAIL'}] cred_failclosed:classify/genuine-clean   "
          f"{clean.get('risk_level')}")

    # (3) the Data Breach Index must not award the clean sweep to a failed lookup
    def _dbi(status):
        cats = {"breaches": {"status": "completed", "breach_count": 0, "issues": []},
                "dehashed": {"status": status, "total_entries": 0}}
        comp = sa.DataBreachIndex().calculate(cats)["components"]["credential_leaks"]
        return comp["points"]
    conclusive_pts = _dbi("completed")
    for st in NON_CONCLUSIVE:
        pts = _dbi(st)
        ok = (pts is not None) and (pts < conclusive_pts)
        if not ok:
            failures.append(
                f"cred_failclosed[dbi/{st}]: {pts} pts vs {conclusive_pts} for a real "
                "clean lookup — a provider that never answered must not earn the "
                "full-marks clean branch")
        print(f"  [{'PASS' if ok else 'FAIL'}] cred_failclosed:dbi/{st:<24} "
              f"{pts} pts (real clean = {conclusive_pts})")

    # (4) the headline scorer must exclude them rather than treat them as valid
    for st in ("quota_exhausted", "subscription_required"):
        ok = st in sa.RiskScorer._FAILED_STATUSES
        if not ok:
            failures.append(f"cred_failclosed[failed_statuses/{st}]: not in _FAILED_STATUSES "
                            "— it would score as a valid, clean category")
        print(f"  [{'PASS' if ok else 'FAIL'}] cred_failclosed:failed_status/{st:<16} {ok}")

    # (5) the PAGE must say so too. Correct scoring is invisible to a broker
    # reading the PDF: an empty dark-web section still reads as good news unless
    # the card states it was never searched.
    pc = importlib.import_module("pdf_cards")
    from pdf_helpers import build_styles
    S = build_styles()

    def _txt(parts):
        return " ".join(getattr(p, "text", "") or "" for p in parts)

    render_cases = [
        ("dehashed/quota", pc.cat_dehashed,
         {"dehashed": {"status": "quota_exhausted", "total_entries": 0, "issues": []}}, True),
        ("dehashed/subscription", pc.cat_dehashed,
         {"dehashed": {"status": "subscription_required", "total_entries": 0, "issues": []}}, True),
        ("dehashed/genuine-clean", pc.cat_dehashed,
         {"dehashed": {"status": "completed", "total_entries": 0, "unique_emails": 0, "issues": []}}, False),
        ("intelx/quota", pc.cat_intelx,
         {"intelx": {"status": "quota_exhausted", "total_results": 0, "issues": []}}, True),
        ("intelx/poll-error", pc.cat_intelx,
         {"intelx": {"status": "error", "total_results": 0, "issues": []}}, True),
        ("intelx/genuine-clean", pc.cat_intelx,
         {"intelx": {"status": "completed", "total_results": 0, "issues": []}}, False),
        ("credrisk/unassessed", pc.cat_credential_risk,
         {"credential_risk": {"risk_level": "UNKNOWN", "assessed": False,
                              "status": "quota_exhausted"}}, True),
        ("credrisk/real-low", pc.cat_credential_risk,
         {"credential_risk": {"risk_level": "LOW", "risk_score": 100, "factors": []}}, False),
    ]
    for label, fn, data, want_caveat in render_cases:
        txt = _txt(fn(data, S))
        has = "Not assessed" in txt
        ok = has == want_caveat
        if not ok:
            failures.append(
                f"cred_failclosed[render/{label}]: caveat_present={has}, expected "
                f"{want_caveat} — a card built from a lookup that never ran must say "
                "'Not assessed'; correct scoring alone is invisible to the reader")
        print(f"  [{'PASS' if ok else 'FAIL'}] cred_failclosed:render/{label:<22} "
              f"caveat={has}")


# (f) CREDENTIAL-EXPORT KILL SWITCH. The export releases a client's ACTUAL
# breached passwords. What makes that lawful is the client's signed consent, and
# the request's `consent: true` field is only a broker attestation -- during the
# 2026-07-28 demo, with testers who have signed nothing, it is not a control at
# all. So the export must FAIL CLOSED unless explicitly enabled, and the DOWNLOAD
# route must be gated too: gating only the POST would still let a token minted
# before the flip be redeemed after it. Asserted here so a future refactor cannot
# quietly reopen it.
#   (label, env value, expect_blocked)
EXPORT_SWITCH_SCENARIOS = [
    ("unset (default)",  None,    True),
    ("explicit off",     "0",     True),
    ("garbage value",    "maybe", True),   # anything but a true-ish value = closed
    ("enabled",          "1",     False),
]


def _check_export_switch(failures):
    # Two halves, deliberately: reloading app to re-read the env would re-run
    # init_db() against whatever DB the env points at, so instead patch the flag
    # the decorator reads at call time (route behaviour), and check the env
    # parsing separately against the same values (config behaviour).
    import importlib
    app_mod = importlib.import_module("app")
    for label, val, want_blocked in EXPORT_SWITCH_SCENARIOS:
        parsed = str(val or "").strip().lower() in ("1", "true", "yes", "on")
        with mock.patch.object(app_mod, "CREDENTIAL_EXPORT_ENABLED", parsed), \
             app_mod.app.test_client() as c:
            post = c.post("/api/credential-export", json={
                "domain": "example.com", "consent": True, "authorised_by": "T",
                "age_public_key": "age1" + "q" * 50})
            dl = c.get("/api/credential-export/download/tok")
            st = (c.get("/api/credential-export/status").get_json() or {})
        blocked = (post.status_code == 503 and dl.status_code == 503)
        env_ok = (parsed != want_blocked)      # env string -> the flag we expect
        ok = (blocked == want_blocked) and (st.get("enabled") == (not want_blocked)) and env_ok
        if not ok:
            failures.append(
                f"export_switch[{label}]: env={val!r} parsed={parsed} "
                f"POST={post.status_code} DL={dl.status_code} "
                f"status.enabled={st.get('enabled')} — expected "
                f"{'BLOCKED (503 on both)' if want_blocked else 'open'}; the export "
                "releases real breached passwords and must fail closed, including "
                "the download route")
        print(f"  [{'PASS' if ok else 'FAIL'}] export_switch:{label:<18} "
              f"env={str(val):<6} POST={post.status_code} DL={dl.status_code} "
              f"enabled={st.get('enabled')}")


# (h) PROVIDER BUDGET GUARD. The guard existed but was decorative: caps were
# placeholders 20x above the real quota (1000/day vs IntelX's free 50/day) so it
# could never fire first, and the counters were in-process, so every deploy
# handed the box a fresh allowance it did not have. The durable `usage` table
# recorded every call and had no reader. Two subtleties are asserted here because
# both were got wrong on the first attempt:
#   * a FRESH ledger (i.e. after a restart) must inherit the day's durable spend;
#   * a STALE durable read must not hand out allowance already spent — anchoring
#     to max(durable, in-process) silently overruns the cap by up to one cache
#     TTL's worth of calls, which is why the delta is measured from the
#     in-process counter at fetch time instead.
def _check_provider_budget(failures):
    import importlib
    P = importlib.import_module("providers")

    def L(cap):
        return P.DurableUsageLedger(default_daily_cap=None, daily_caps={"intelx": cap},
                                    retry_cap_per_window=50, retry_window_seconds=300)

    checks = []

    # real quota, not a placeholder
    # The cap is in HTTP CALLS, not searches: a live scan on 2026-07-28 showed one
    # IntelX search costs 4 calls (1 initiate + 3 polls). Asserting 50 here — the
    # search quota — is what shipped a cap that would throttle at a quarter of the
    # real allowance. Assert the CALL budget covers 50 searches instead.
    ix_cap = P._LEDGER.caps().get("intelx")
    checks.append(("real_quota_unit", ix_cap is not None and ix_cap >= 50 * 4,
                   f"intelx cap={ix_cap} calls — one search costs up to 4 calls, so a "
                   "50-search/day free tier needs a 200-call budget; a lower value "
                   "throttles while quota remains and wrongly marks dark-web unassessed"))

    # the cap binds
    l = L(3)
    with mock.patch.object(l, "_durable_spend", return_value=0):
        seq = []
        for _ in range(5):
            a = l.allow_call("intelx")
            seq.append(a)
            if a:
                l.record_call("intelx")
    checks.append(("cap_binds", seq == [True, True, True, False, False],
                   f"cap=3 produced {seq} — the cap must stop the 4th call"))

    # survives a restart
    f = L(50)
    with mock.patch.object(f, "_durable_spend", return_value=48):
        rem0 = f.remaining("intelx")
        f.record_call("intelx"); f.record_call("intelx")
        after = f.allow_call("intelx")
    checks.append(("survives_restart", rem0 == 2 and after is False,
                   f"a fresh ledger saw remaining={rem0} then allow={after} — it must "
                   "inherit the durable count, not restart the day's allowance at zero"))

    # stale cache must not overrun
    s = L(50)
    with mock.patch.object(s, "_durable_spend", return_value=49):
        s.spend_today("intelx")        # prime the cache
        s.record_call("intelx")        # the 50th call
        overran = s.allow_call("intelx")
    checks.append(("stale_cache", overran is False,
                   "a call made after the durable snapshot was not counted — the cap "
                   "overruns by up to one cache TTL"))

    # metering must never block a scan
    b = L(50)
    with mock.patch("scanner_db.usage_for", side_effect=RuntimeError("db down")):
        okfail = b.allow_call("intelx")
    checks.append(("fails_open_on_db_error", okfail is True,
                   "a metering failure blocked a provider call — accounting must never "
                   "take the scanner down"))

    for label, ok, why in checks:
        if not ok:
            failures.append(f"provider_budget[{label}]: {why}")
        print(f"  [{'PASS' if ok else 'FAIL'}] provider_budget:{label:<24} {ok}")


# (i) LOOKALIKE POSTURE. "4 lookalikes resolve" is not actionable; what decides
# danger is whether a domain can SEND MAIL as the client. Ground truth from the
# real phishield.com self-scan (2026-08-06):
#   phisheild.com  Namecheap PrivateEmail + 5 forwarders, Cloudflare  -> HIGH
#   hishield.com   GoDaddy secureserver MX, 411-byte parking page     -> HIGH
#   phshield.com   NULL MX ("0 .") + SPF -all, Afternic for-sale      -> NOT high
#   pishield.com   no MX, 114-byte parking page                       -> LOW
# The null-MX case is the trap: a first pass treated any non-empty MX answer as
# mail-capable and labelled phshield.com a phishing risk, when RFC 7505 "0 ."
# declares the exact opposite. Asserted offline so no scan or DNS is needed.
MX_SCENARIOS = [
    ("null mx",        ["0 ."],                        0, True),
    ("real mx",        ["10 mx1.privateemail.com."],   1, False),
    ("mixed",          ["0 .", "10 mx1.example.com."], 1, False),
    ("absent",         [],                             0, False),
]
# (label, entry, expected risk)
VERDICT_SCENARIOS = [
    ("mail, no site (phisheild profile)",
     {"mail_capable": True, "serves_content": False, "similarity": 89}, "high"),
    ("mail + live site",
     {"mail_capable": True, "serves_content": True, "similarity": 89}, "high"),
    ("null mx, parked for sale (phshield profile)",
     {"mail_capable": False, "null_mx": True, "listed_for_sale": True,
      "serves_content": False, "similarity": 89}, "medium"),
    ("no mail, parked (pishield profile)",
     {"mail_capable": False, "null_mx": False, "serves_content": False,
      "similarity": 89}, "low"),
]


def _check_lookalike_posture(failures):
    import importlib
    F = importlib.import_module("checkers_threats").FraudulentDomainChecker

    # THE DOMAIN IS NEVER A LOOKALIKE OF ITSELF. Found live on
    # excellentmeat.co.za (2026-08-06): char-swap transposing two ADJACENT
    # IDENTICAL letters is a no-op — "exce(ll)ent" swaps to "excellent" — so the
    # generator emitted the scanned domain, it "resolved" (it is their real
    # domain), probed as mail-capable (their real mail server) and was published
    # as a HIGH-risk impersonator with advice to report it to its own registrar.
    # Every domain with a doubled letter was affected; phishield.com has none,
    # which is exactly why testing missed it. Domains below all contain doubles.
    c = F()
    for dom in ("excellentmeat.co.za", "coffee.com", "williams.co.za",
                "mattress.com", "aabb.com", "phishield.com"):
        name, tld = c._split_domain(dom)
        perms = c._generate_permutations(name, tld)
        hits = [p[0] for p in perms if p[0].lower().strip(".") == dom.lower().strip(".")]
        ok = not hits and len(perms) > 10      # and the generator still produces work
        if not ok:
            failures.append(
                f"lookalike_self[{dom}]: generated itself {len(hits)} time(s) "
                f"(perms={len(perms)}) — the scanned domain must never be reported as "
                "impersonating itself; it resolves, probes as mail-capable, and gets "
                "published as HIGH risk with a recommendation to report the client to "
                "their own registrar")
        print(f"  [{'PASS' if ok else 'FAIL'}] lookalike_self:{dom:<22} "
              f"perms={len(perms)} self={len(hits)}")

    # COVERAGE: a cap must never delete a whole ATTACK CLASS. The old
    # `permutations[:60]` truncated a list built technique-by-technique, so on
    # phishield.com it probed 0 of 16 tld-variants, 0 of 8 dot-insertions, 0 of 8
    # hyphen-insertions and 0 of 6 IDN homoglyphs — and missed three live
    # lookalikes (phishield.io, phi-shield.com, phish.ield.com). It also
    # reported "115 permutations tested" while testing 60.
    import collections as _collections
    _probed = []

    def _fake_resolves(self, d):
        _probed.append(d)
        return False

    with mock.patch.object(F, "_resolves", _fake_resolves):
        _out = F().check("phishield.com")
    _c = F()
    _n, _t = _c._split_domain("phishield.com")
    _perms = _c._generate_permutations(_n, _t)
    _tech = {p[0]: p[1] for p in _perms}
    _cov = _collections.Counter(_tech.get(d, "?") for d in _probed)
    _all = _collections.Counter(p[1] for p in _perms)
    _missing = sorted(t for t in _all if _cov.get(t, 0) == 0)
    ok_cov = not _missing
    if not ok_cov:
        failures.append(
            f"lookalike_coverage: technique(s) never probed at all: {_missing} — a "
            "probe cap must sample across techniques, not amputate whole attack "
            "classes (tld-variant carries .co.za / .co / .io)")
    print(f"  [{'PASS' if ok_cov else 'FAIL'}] lookalike_coverage:all_techniques "
          f"probed={len(_probed)}/{len(_perms)} unprobed_classes={len(_missing)}")

    ok_honest = _out.get("total_permutations") == len(_probed)
    if not ok_honest:
        failures.append(
            f"lookalike_coverage[reporting]: reports total_permutations="
            f"{_out.get('total_permutations')} but probed {len(_probed)} — the panel "
            "must state what was actually tested, not what was generated")
    print(f"  [{'PASS' if ok_honest else 'FAIL'}] lookalike_coverage:honest_count  "
          f"reported={_out.get('total_permutations')} probed={len(_probed)}")

    for label, raw, want_usable, want_null in MX_SCENARIOS:
        usable, null = F._usable_mx(raw)
        ok = (len(usable) == want_usable) and (null == want_null)
        if not ok:
            failures.append(
                f"lookalike_mx[{label}]: usable={len(usable)} null={null}, expected "
                f"{want_usable}/{want_null} — RFC 7505 '0 .' means the domain accepts "
                "NO mail; counting it as an MX host labels a harmless parked domain "
                "a phishing risk")
        print(f"  [{'PASS' if ok else 'FAIL'}] lookalike_mx:{label:<12} "
              f"usable={len(usable)} null_mx={null}")

    # A SIMILAR NAME IS NOT IMPERSONATION. phishield.io resolves, is
    # mail-capable, and is a completely unrelated company: "PHIShield —
    # HIPAA-Safe X12 De-Identification" (PHI = Protected Health Information).
    # The first cut told the reader to report it to its registrar. A live,
    # branded site must therefore be framed verify-first, and the page's own
    # title quoted so a human settles it in one second.
    live = {"mail_capable": True, "serves_content": True, "similarity": 85,
            "page_title": "PHIShield - HIPAA-Safe X12 De-Identification"}
    _risk, rec = F._verdict(dict(live))
    quotes_title = "PHIShield" in rec
    verify_first = rec.lower().find("verify") < rec.lower().find("report")         if "report" in rec.lower() else True
    ok_live = quotes_title and verify_first
    if not ok_live:
        failures.append(
            f"lookalike_identity: recommendation for a live branded lookalike does "
            f"not quote its title ({quotes_title}) or leads with 'report' rather "
            f"than 'verify' ({verify_first}) — that tells a client to file an abuse "
            "complaint against what may be a legitimate unrelated business")
    print(f"  [{'PASS' if ok_live else 'FAIL'}] lookalike_identity:verify_first   "
          f"quotes_title={quotes_title} verify_before_report={verify_first}")

    for label, entry, want in VERDICT_SCENARIOS:
        risk, rec = F._verdict(dict(entry))
        ok = (risk == want) and bool(rec)
        if not ok:
            failures.append(
                f"lookalike_verdict[{label}]: risk={risk!r} expected {want!r} "
                f"(recommendation present={bool(rec)}) — a mail-capable near-typo must "
                "outrank a parked one, or the panel ranks by resemblance instead of "
                "by what the domain can actually do")
        print(f"  [{'PASS' if ok else 'FAIL'}] lookalike_verdict:{label[:30]:<32} {risk}")


# (j) TABLE HEADERS MUST NOT BE ORPHANED. Reported from a real broker report:
# the Regulatory Flag Audit header row sat alone at the foot of page 5 with its
# body on page 6. ReportLab will happily split a table after row 0 unless
# repeatRows is set; with it, a split that would leave only the repeat-rows is
# refused outright, so the table moves whole to the next page AND the header
# repeats on continuation pages. No table in the report set repeatRows.
#
# This asserts the LIBRARY behaviour we depend on (filler=39 reproduces the
# split exactly on A4 with these margins) plus the fact that every header table
# in the report actually sets it — the second half is what stops a new table
# being added without it.
def _check_table_headers(failures):
    import io, re
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from pypdf import PdfReader

    SS = getSampleStyleSheet()
    ROWS = [["Flag", "BrokerInput", "AutoDetected", "Evidence"]] + \
           [[f"rowmarker{i}", "No", "No", "evidence"] for i in range(1, 8)]

    def orphans(repeat):
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
        story = [Paragraph(f"Filler {i} " * 8, SS["BodyText"]) for i in range(39)]
        t = Table(ROWS, colWidths=[45 * mm, 25 * mm, 28 * mm, 50 * mm],
                  **({"repeatRows": 1} if repeat else {}))
        t.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                               ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey)]))
        story.append(t)
        doc.build(story)
        buf.seek(0)
        pages = [p.extract_text() or "" for p in PdfReader(buf).pages]
        h = next((i for i, p in enumerate(pages) if "AutoDetected" in p), None)
        r = next((i for i, p in enumerate(pages) if "rowmarker1" in p), None)
        return h is not None and r is not None and h != r

    without, with_ = orphans(False), orphans(True)
    ok = without and not with_
    if not ok:
        failures.append(
            f"table_header[reportlab_behaviour]: orphan without repeatRows={without}, "
            f"with={with_} — the fix depends on ReportLab refusing a split that "
            "leaves only the header; if this stops reproducing, the guard below is "
            "no longer sufficient")
    print(f"  [{'PASS' if ok else 'FAIL'}] table_header:repeatRows_prevents_orphan  "
          f"without={without} with={with_}")

    # Every table styled with a bold row-0 header must set repeatRows.
    for fn in ("pdf_cards.py", "pdf_report.py"):
        src = open(os.path.join(SEC, fn), encoding="utf-8").read()
        headers = len(re.findall(
            r'"FONTNAME"\s*,\s*\(0,\s*0\)\s*,\s*\(-1,\s*0\)\s*,\s*"Helvetica-Bold"', src))
        repeats = len(re.findall(r"repeatRows\s*=\s*1", src))
        ok2 = repeats >= headers
        if not ok2:
            failures.append(
                f"table_header[{fn}]: {headers} table(s) have a bold row-0 header but "
                f"only {repeats} set repeatRows=1 — a header table without it can be "
                "split after row 0, stranding the header at a page foot")
        print(f"  [{'PASS' if ok2 else 'FAIL'}] table_header:{fn:<16} "
              f"headers={headers} repeatRows={repeats}")


# (k) A BLOCKED CHECKER MUST NOT SCORE AS A CLEAN ONE. On the 2026-08-06
# phishield.com scan a WAF answered 403 to 20 of 20 probes, and six checkers
# were recorded as affected — yet info_disclosure and tech_stack both reported
# status="completed" with a PERFECT 100/100. A block page carries none of the
# signals they read (no Server / X-Powered-By, no EOL version string, no
# retrievable path), so "nothing found" was indistinguishable from a tidy site.
#
# The subtle half is the scoring side. Dropping a blocked checker's score is NOT
# enough: the per-category fallbacks are not neutral — tech_stack and
# info_disclosure both default to score=100, i.e. a perfect result — so a
# score-less blocked checker banks the exact clean sweep being removed. Only
# http_headers defaults to a neutral 50, which is why the earlier fix there
# appeared sufficient. "unreachable" therefore has to be an EXCLUDING status.
class _Resp:
    def __init__(self, code, text="", headers=None):
        self.status_code = code
        self.text = text
        self.headers = headers or {}


def _check_blocked_not_clean(failures):
    import copy, importlib
    ct_mod = importlib.import_module("checkers_threats")
    sa = importlib.import_module("scoring_analytics")

    # --- tech_stack -------------------------------------------------------
    for label, resp, want_status, want_scored in (
        ("waf 403 block page", _Resp(403, "<html>Forbidden</html>"), "unreachable", False),
        ("healthy clean 200",  _Resp(200, "<html>hi</html>"),        "completed",   True),
        ("healthy leaky 200",  _Resp(200, "<html>x</html>",
                                     {"X-Powered-By": "PHP/5.6"}),   "completed",   True),
    ):
        with mock.patch.object(ct_mod, "HTTP") as H:
            H.get.return_value = resp
            out = ct_mod.TechStackChecker().check("example.com")
        got, scored = out.get("status"), ("score" in out)
        ok = (got == want_status) and (scored == want_scored)
        if not ok:
            failures.append(
                f"blocked_clean[tech_stack/{label}]: status={got!r} scored={scored}, "
                f"expected {want_status!r}/{want_scored} — a block page has no Server "
                "header and no EOL string, so parsing it yields a perfect score for a "
                "stack that was never seen")
        print(f"  [{'PASS' if ok else 'FAIL'}] blocked_clean:tech_stack/{label:<20} "
              f"{got} scored={scored}")

    # --- info_disclosure --------------------------------------------------
    def run_id(code):
        with mock.patch("http_client.HTTP") as H, mock.patch.object(ct_mod, "HTTP") as H2:
            H.head.return_value = _Resp(code)
            H.get.return_value = _Resp(code, "x" * 50)
            H2.get.return_value = _Resp(code, "x" * 50)
            H2.stop_probing.return_value = False
            return ct_mod.InformationDisclosureChecker().check("example.com")

    for label, code, want_status, want_scored in (
        ("every probe 403 (WAF)",   403, "unreachable", False),
        ("every probe 404 (clean)", 404, "completed",   True),
    ):
        out = run_id(code)
        got, scored = out.get("status"), ("score" in out)
        ok = (got == want_status) and (scored == want_scored)
        if not ok:
            failures.append(
                f"blocked_clean[info_disclosure/{label}]: status={got!r} "
                f"scored={scored}, expected {want_status!r}/{want_scored} — refusing "
                "every probe is not the same as finding nothing exposed")
        print(f"  [{'PASS' if ok else 'FAIL'}] blocked_clean:info_disc/{label:<22} "
              f"{got} scored={scored}")

    # --- exposed_admin / vpn_remote / payment_security --------------------
    # Same shape: each returns "nothing found" when a WAF refuses every probe.
    # exposed_admin is the worst on screen (it renders a green "Passed"), and
    # vpn_remote is the worst in words (it prints "No VPN/remote access gateway
    # detected", an assertion of absence from a probe that never landed).
    cc = importlib.import_module("checkers_core")
    cn_mod = importlib.import_module("checkers_network")

    # Faithful control-probe answer for the uniform-code mocks below: a site that
    # returns `code` to everything returns it to the site root as well.
    _root_answers = lambda code: code not in {401, 403, 406, 409, 418, 429, 451, 503}

    def _admin(code):
        with mock.patch("http_client.HTTP") as H:
            H.discover.return_value = _Resp(code)
            H.get.return_value = _Resp(code, "x" * 500)
            H.stop_probing.return_value = False
            # This mock refuses EVERY url, so the site root is refused too.
            # Leaving origin_answering as a bare MagicMock would return a truthy
            # sentinel and quietly convert this blind case into a clean one.
            H.origin_answering.side_effect = lambda d, **k: _root_answers(code)
            return cc.ExposedAdminChecker().check("example.com")

    def _simple(mod, cls, code):
        with mock.patch.object(mod, "HTTP") as H:
            H.get.return_value = _Resp(code, "nope")
            H.stop_probing.return_value = False
            H.origin_answering.side_effect = lambda d, **k: _root_answers(code)
            return getattr(mod, cls)().check("example.com")

    trio = [
        ("exposed_admin",    lambda c: _admin(c)),
        ("vpn_remote",       lambda c: _simple(cn_mod, "VPNRemoteAccessChecker", c)),
        ("payment_security", lambda c: _simple(ct_mod, "PaymentSecurityChecker", c)),
    ]
    for name, run in trio:
        blocked, clean = run(403), run(404)
        ok = (blocked.get("status") == "unreachable"
              and clean.get("status") == "completed")
        if not ok:
            failures.append(
                f"blocked_clean[{name}]: blocked={blocked.get('status')!r} "
                f"clean={clean.get('status')!r} — a blanket WAF deny must read as "
                "unreachable, while an origin answering 404 must still read as a "
                "genuine clean result")
        print(f"  [{'PASS' if ok else 'FAIL'}] blocked_clean:{name:<18} "
              f"blocked={blocked.get('status')} clean={clean.get('status')}")

    # vpn_remote must stop ASSERTING absence when it was blocked
    v_blocked = _simple(cn_mod, "VPNRemoteAccessChecker", 403)
    asserts = any("No VPN" in str(i) for i in v_blocked.get("issues", []))
    if asserts:
        failures.append(
            "blocked_clean[vpn_remote/absence]: still prints 'No VPN/remote access "
            "gateway detected' after every probe was refused — that reads to a broker "
            "as 'they have no VPN', which a blanket 403 does not support")
    print(f"  [{'PASS' if not asserts else 'FAIL'}] blocked_clean:vpn_absence_claim     "
          f"asserts={asserts}")

    # a REAL exposure must survive the guard (no suppression of true positives)
    with mock.patch("http_client.HTTP") as H:
        H.discover.side_effect = lambda url, **kw: _Resp(200) if "/admin" in url else _Resp(403)
        H.get.return_value = _Resp(200, "admin login panel " * 40)
        H.stop_probing.return_value = False
        real = cc.ExposedAdminChecker().check("example.com")
    kept = real.get("status") == "completed" and (real.get("high_count") or 0) > 0
    if not kept:
        failures.append(
            f"blocked_clean[exposed_admin/true_positive]: status={real.get('status')!r} "
            f"high_count={real.get('high_count')} — a genuine exposure found amid "
            "blocking must still be reported, or the guard hides real findings")
    print(f"  [{'PASS' if kept else 'FAIL'}] blocked_clean:true_positive_kept    "
          f"high_count={real.get('high_count')}")

    # --- round 2: website_security + dependency_manifest -------------------
    # Found by the smoke harness once it patched provider clients, not just
    # HTTP. WebsiteSecurityChecker is the sharpest of the two: EVERY default in
    # its result is optimistic (cookies secure/httponly/samesite all True,
    # mixed_content False), so a block page yields "no cookie problems, no mixed
    # content, no CMS exposure" and a top score for a site never inspected.
    cs_m = importlib.import_module("checkers_supply_chain")

    def _ws(code):
        with mock.patch.object(ct_mod, "HTTP") as H:
            H.get.return_value = _Resp(code, "<html>x</html>")
            H.stop_probing.return_value = False
            return ct_mod.WebsiteSecurityChecker().check("example.com")

    def _dm(code):
        with mock.patch("http_client.HTTP") as H:
            H.head.return_value = _Resp(code)
            H.get.return_value = _Resp(code, "x" * 50)
            H.stop_probing.return_value = False
            H.origin_answering.side_effect = lambda d, **k: _root_answers(code)
            return cs_m.DependencyManifestChecker().check("example.com")

    for label, fn in (("website_security", _ws), ("dependency_manifest", _dm)):
        blocked, clean = fn(403), fn(404 if label == "dependency_manifest" else 200)
        ok = (blocked.get("status") == "unreachable"
              and "score" not in blocked
              and clean.get("status") == "completed")
        if not ok:
            failures.append(
                f"blocked_clean[{label}]: blocked={blocked.get('status')!r} "
                f"scored={'score' in blocked} clean={clean.get('status')!r} — a "
                "checker whose defaults are all optimistic must not score a block "
                "page as a well-configured site")
        print(f"  [{'PASS' if ok else 'FAIL'}] blocked_clean:{label:<20} "
              f"blocked={blocked.get('status')} clean={clean.get('status')}")

    # --- round 3: DENIED IS NOT BLIND --------------------------------------
    # The overcorrection. Rounds 1-2 taught four path-enumeration checkers to
    # report "unreachable" when every probe came back 403. But every path they
    # request is one a hardened server SHOULD refuse (/.env, /admin,
    # /remote/login, /package.json), so "all 403" is ALSO the signature of
    # correct configuration — and the two were indistinguishable.
    #
    # Live case, excellentmeat.co.za 2026-08-06: apex 19/19 = 200, exposed_admin
    # collected 15 honest 404s, and all 8 sensitive-file probes returned 403.
    # The site was answering us the whole time. We reported info_disclosure as
    # "unreachable — refused by a WAF/CDN", which then fed refusal_blinded_checkers
    # and made the WAF card announce "active blocking observed" on a site with no
    # WAF at all. Good hardening was rendered as a coverage gap AND a phantom WAF.
    #
    # The control is the site root: a page nobody has reason to deny. This must
    # cut BOTH ways, so each checker is run three times — the middle row is the
    # regression this round fixes, and the last row is the round-1/2 behaviour
    # that must survive it.
    def _urlaware(pc, rc):
        """Fake HTTP where the site ROOT answers differently from probed paths."""
        is_root = lambda u: u.rstrip("/").count("/") == 2
        H = mock.MagicMock()
        H.head.side_effect     = lambda url, **k: _Resp(rc if is_root(url) else pc)
        H.discover.side_effect = lambda url, **k: _Resp(rc if is_root(url) else pc)
        H.get.side_effect      = lambda url, **k: (_Resp(rc, "<html>Home</html>")
                                                   if is_root(url) else _Resp(pc, "x" * 80))
        H.stop_probing.return_value = False
        H.hard_blocked.return_value = False
        H.REFUSAL_CODES = frozenset({401, 403, 406, 409, 418, 429, 451, 503})
        H.origin_answering.side_effect = lambda d, **k: rc not in H.REFUSAL_CODES
        return H

    denied_trio = [
        ("info_disclosure", ct_mod, "InformationDisclosureChecker"),
        ("exposed_admin",   cc,     "ExposedAdminChecker"),
        ("vpn_remote",      cn_mod, "VPNRemoteAccessChecker"),
        ("dep_manifest",    cs_m,   "DependencyManifestChecker"),
    ]
    for name, mod, cls in denied_trio:
        got = {}
        for row, pc, rc in (("ordinary", 404, 200),
                            ("denied",   403, 200),
                            ("walled",   403, 403)):
            H = _urlaware(pc, rc)
            with mock.patch("http_client.HTTP", H), mock.patch.object(mod, "HTTP", H, create=True):
                got[row] = getattr(mod, cls)().check("example.com").get("status")
        ok = (got["ordinary"] == "completed"      # plain clean site
              and got["denied"] == "completed"    # hardened: refusals ANSWER the question
              and got["walled"] == "unreachable")  # blind: still fails closed
        if not ok:
            failures.append(
                f"denied_not_blind[{name}]: ordinary={got['ordinary']!r} "
                f"denied={got['denied']!r} walled={got['walled']!r} — a server that "
                "refuses sensitive paths while serving its home page has ANSWERED "
                "this checker's question (nothing is publicly reachable) and must "
                "score as clean; only a root that is refused too means we were blind")
        print(f"  [{'PASS' if ok else 'FAIL'}] denied_not_blind:{name:<16} "
              f"ordinary={got['ordinary']} denied={got['denied']} walled={got['walled']}")

    # ...and the phantom WAF that the false blindness produced. With no checker
    # left blinded and an apex that never blocked, nothing may claim blocking.
    _wafc = {"detected": False, "waf_name": None}
    _cats = {"waf": _wafc,
             "info_disclosure": {"status": "completed",
                                 "probe_status_codes": {"403": 8}},
             "exposed_admin": {"status": "completed",
                               "probe_status_codes": {"200": 1, "403": 8, "404": 15}}}
    _blinded = sorted(
        n for n, c in _cats.items()
        if isinstance(c, dict) and c.get("status") == "unreachable")
    phantom = bool(_blinded)
    if phantom:
        failures.append(
            "denied_not_blind[waf_card]: a scan whose checkers all completed still "
            f"reports blinded checkers {_blinded} — the WAF card would announce "
            "'active blocking observed' on a site with no WAF")
    print(f"  [{'PASS' if not phantom else 'FAIL'}] denied_not_blind:waf_card_quiet  "
          f"blinded={_blinded}")

    # --- the WAF row must not claim ABSENCE while blocking is observed ------
    # The report said "No WAF detected" in red, charged RSI +0.04 and BI +0.015,
    # and advised buying a WAF — on the same page as "20 of 20 probes returned
    # 403, active blocking pattern". We cannot claim a WAF either (a 403 wall may
    # be a bot-manager, a CDN rule or plain auth), so the correct position is
    # neutral: no penalty, and no detected-WAF credit.
    for label, wafcat, want_penalty in (
        ("no waf, no blocking",      {"detected": False}, True),
        ("blocking observed",        {"detected": False, "blocking_observed": True}, False),
        ("vendor detected",          {"detected": True, "waf_name": "Cloudflare"}, False),
    ):
        cats = {"waf": wafcat,
                "breaches": {"status": "completed", "breach_count": 0, "issues": []},
                "credential_risk": {"risk_level": "LOW"}}
        rsi = sa.RansomwareIndex().calculate(cats, industry="technology")
        charged = any("No WAF detected" in f.get("factor", "")
                      for f in rsi.get("contributing_factors", []))
        ok = charged == want_penalty
        if not ok:
            failures.append(
                f"waf_row[{label}]: RSI 'No WAF detected' charged={charged}, expected "
                f"{want_penalty} — penalising absence while the scan reports being "
                "blocked contradicts the evidence on the same page")
        print(f"  [{'PASS' if ok else 'FAIL'}] waf_row:{label:<24} penalty={charged}")

    # --- scoring: unreachable must EXCLUDE, not fall back to a 100 default --
    ok_excl = "unreachable" in sa.RiskScorer._FAILED_STATUSES
    if not ok_excl:
        failures.append(
            "blocked_clean[scoring]: 'unreachable' is not in _FAILED_STATUSES — "
            "tech_stack and info_disclosure default to score=100, so a blocked "
            "checker without an explicit score is scored as PERFECT")
    print(f"  [{'PASS' if ok_excl else 'FAIL'}] blocked_clean:unreachable_excludes    {ok_excl}")

    base = {
        "ssl": {"status": "completed", "score": 90},
        "email_security": {"status": "completed", "score": 8},
        "breaches": {"status": "completed", "breach_count": 0, "issues": []},
        "tech_stack": {"status": "completed", "score": 100, "eol_count": 0},
        "info_disclosure": {"status": "completed", "score": 100, "exposed_paths": []},
    }

    def score(c):
        out = sa.RiskScorer().calculate(c)
        return out[0] if isinstance(out, tuple) else out

    blocked = copy.deepcopy(base)
    for k in ("tech_stack", "info_disclosure"):
        blocked[k] = {"status": "unreachable", "unreachable_reason": "WAF refused all probes"}
    clean_score, blocked_score = score(copy.deepcopy(base)), score(blocked)
    ok_diff = clean_score != blocked_score
    if not ok_diff:
        failures.append(
            f"blocked_clean[composite]: blocked scan scored {blocked_score}, identical "
            f"to a genuinely clean {clean_score} — a scan that saw nothing must not "
            "score the same as one that looked and found nothing")
    print(f"  [{'PASS' if ok_diff else 'FAIL'}] blocked_clean:composite_differs      "
          f"clean={clean_score} blocked={blocked_score}")


# (l) THE DASHBOARD MUST NOT LINK OUT OF ITS OWN BASE PATH. The scanner is
# mounted under /scanner on a shared host whose ROOT is the unrelated Command
# Centre, so a bare absolute href leaves the product entirely. "Re-run
# Assessment" carried href="/" and sent users to the Command Centre — in a file
# that already imported withBase and used it correctly one line above. A static
# check because the failure only shows on the sub-path deployment, never in a
# root-mounted dev build.
import re as _re


def _check_balance_not_metered(failures):
    """The credit indicator must not BE the biggest credit consumer.

    DeHashed publishes no free balance endpoint, so /api/dehashed/balance ran a
    real /v2/search — and the scan form calls it on every page load. With several
    testers refreshing it quietly outspent the scans themselves, and because it
    used raw requests instead of the provider seam the spend never reached the
    usage ledger (ledger ~17 vs 200+ actually billed over the same period).
    """
    import importlib, time
    os.environ["DEHASHED_API_KEY"] = os.environ.get("DEHASHED_API_KEY") or "x"
    os.environ.setdefault("SCANNER_ALLOW_SQLITE", "1")
    A = importlib.import_module("app")
    ct_m = importlib.import_module("checkers_threats")

    calls = {"n": 0}

    class _Bal:
        status_code = 200
        def json(self):
            return {"balance": 231, "entries": [], "total": 0}

    def _post(*a, **kw):
        calls["n"] += 1
        return _Bal()

    ct_m._DEHASHED_BALANCE.update({"balance": None, "at": 0.0})
    with mock.patch("requests.post", side_effect=_post), A.app.test_client() as c:
        for _ in range(10):
            c.get("/api/dehashed/balance")
    ok = calls["n"] <= 1
    if not ok:
        failures.append(
            f"balance_metering[page_loads]: 10 loads of the scan form performed "
            f"{calls['n']} live DeHashed searches — the credit indicator must serve a "
            "cached balance, not buy one per page view")
    print(f"  [{'PASS' if ok else 'FAIL'}] balance_metering:10_page_loads      "
          f"paid_searches={calls['n']}")

    # THE CACHE MUST SURVIVE A RESTART. An in-memory-only cache is not a cache
    # on a service that restarts with every deploy: 10 service starts on
    # 2026-08-06 alone, each wiping it, so the next page load bought a credit.
    import time as _t2
    ct_m.record_dehashed_balance(309, _t2.time())
    ct_m._DEHASHED_BALANCE.update({"balance": None, "at": 0.0})   # the restart
    recovered = ct_m.last_dehashed_balance().get("balance")
    ok_persist = recovered == 309
    if not ok_persist:
        failures.append(
            f"balance_metering[persistence]: after a simulated restart the balance "
            f"read back as {recovered!r}, not 309 — an in-memory cache is wiped by "
            "every deploy, so each one silently costs a credit")
    print(f"  [{'PASS' if ok_persist else 'FAIL'}] balance_metering:survives_restart  "
          f"recovered={recovered}")
    try:
        os.remove(ct_m._BALANCE_FILE)
    except OSError:
        pass

    # a balance captured from a real scan must be served for free
    ct_m._DEHASHED_BALANCE.update({"balance": None, "at": 0.0})
    ct_m.record_dehashed_balance(228, time.time())
    before = calls["n"]
    with mock.patch("requests.post", side_effect=_post), A.app.test_client() as c:
        got = (c.get("/api/dehashed/balance").get_json() or {}).get("balance")
    ok2 = (calls["n"] == before) and got == 228
    if not ok2:
        failures.append(
            f"balance_metering[from_scan]: balance={got} extra_calls="
            f"{calls['n'] - before} — a balance already returned by a real scan "
            "search must be reused, not re-purchased")
    print(f"  [{'PASS' if ok2 else 'FAIL'}] balance_metering:reuse_scan_balance "
          f"balance={got} extra_paid={calls['n'] - before}")


def _check_hibp_and_waf_evidence(failures):
    """Two more of the same defect, found by an empirical WAF smoke test.

    1. BreachChecker with no HIBP key returned status="completed",
       breach_count=0 — rendering "Known Breaches (HIBP): 0 - Passed" from a
       lookup that never ran. HIBP_API_KEY is unset on the live deployment, so
       EVERY scan carried that false clean, and the DBI banked 30/30 for it.
    2. waf.blocking_observed was keyed off the APEX tracker only. A site that
       serves 200 at the root but 403s every sensitive path never trips it —
       excellentmeat.co.za did exactly that (apex {200:18, 503:2} => blocked
       False) while info_disclosure was refused 8/8. The WAF row therefore kept
       claiming "No WAF detected" on a page that also said "refused by a
       WAF/CDN". Per-checker probe codes are the stronger evidence.
    """
    import importlib
    ct_m = importlib.import_module("checkers_threats")
    sa_m = importlib.import_module("scoring_analytics")

    out = ct_m.BreachChecker().check("example.com")          # no key
    ok = out.get("status") == "no_api_key"
    if not ok:
        failures.append(
            f"hibp[no_key]: status={out.get('status')!r} breach_count="
            f"{out.get('breach_count')} — with no API key the lookup cannot have "
            "run, so 'completed / 0 breaches' is a green pass on breach history "
            "nobody checked")
    print(f"  [{'PASS' if ok else 'FAIL'}] hibp:no_key_is_not_clean        {out.get('status')}")

    def _dbi(status):
        cats = {"breaches": {"status": status, "breach_count": 0, "issues": []},
                "dehashed": {"status": "completed", "total_entries": 0}}
        r = sa_m.DataBreachIndex().calculate(cats)
        return r["components"]["breach_count"]["points"]

    def _dbi_bi(status, bi):
        cats = {"breaches": {"status": status, "breach_count": 0, "issues": []},
                "dehashed": {"status": "completed", "total_entries": 0}}
        if bi:
            cats["breach_intel"] = bi
        r = sa_m.DataBreachIndex().calculate(cats)
        return r["components"]["breach_count"]["points"]

    full, unknown = _dbi("completed"), _dbi("no_api_key")
    ok2 = unknown < full
    if not ok2:
        failures.append(
            f"hibp[dbi]: an unassessed breach lookup scored {unknown}/30, the same "
            f"as a real clean {full}/30 — the index must not award full marks for a "
            "check that never happened")
    print(f"  [{'PASS' if ok2 else 'FAIL'}] hibp:dbi_no_full_marks          "
          f"unknown={unknown} real_clean={full}")

    # RESEARCH IS THE AUTHORITY, NOT HIBP. HIBP finds almost nothing for SA
    # domains and has no key on this deployment; the researched breach-history
    # checker is the real source. So a missing HIBP key must NOT by itself make
    # the picture unknown when the research reached a verdict — including a
    # verdict of NONE, which is a genuine, earned clean.
    researched_clean = _dbi_bi("no_api_key",
                               {"status": "completed", "verdict": "none"})
    researched_hit = _dbi_bi("no_api_key",
                             {"status": "completed", "verdict": "confirmed",
                              "incident_count": 1, "most_recent_breach": "2026-06-26"})
    ok3 = researched_clean == full and researched_hit < full
    if not ok3:
        failures.append(
            f"hibp[research_authority]: researched-clean scored {researched_clean}/30 "
            f"(expected {full}) and researched-breach {researched_hit}/30 — a missing "
            "HIBP key must not downgrade a verdict the web research actually reached")
    print(f"  [{'PASS' if ok3 else 'FAIL'}] hibp:research_is_authority      "
          f"researched_clean={researched_clean} researched_hit={researched_hit}")

def _check_base_path_links(failures):
    src_dir = os.path.join(SEC, "frontend", "src")
    # (?!/) excludes protocol-relative "//cdn.example.com" while still matching
    # the exact root href="/" — the actual bug. An earlier [^/"'] class here
    # rejected the closing quote and therefore missed href="/" entirely, so the
    # check passed while the defect was present. Verified by reintroducing it.
    pattern = _re.compile(
        r"""href=["']/(?!/)|href=\{["']/(?!/)"""
        r"""|location\.(?:href|assign|replace)\s*=\s*["']/(?!/)"""
        r"""|window\.open\(["']/(?!/)""")
    offenders = []
    for root, _dirs, files in os.walk(src_dir):
        for fn in files:
            if not fn.endswith((".ts", ".tsx")):
                continue
            fp = os.path.join(root, fn)
            for i, line in enumerate(open(fp, encoding="utf-8"), 1):
                if "withBase" in line or line.lstrip().startswith(("//", "*")):
                    continue
                if pattern.search(line):
                    offenders.append(f"{os.path.relpath(fp, src_dir)}:{i}")
    ok = not offenders
    if not ok:
        failures.append(
            "base_path[absolute_links]: " + ", ".join(offenders[:5]) +
            " — an absolute href/navigation without withBase() escapes the /scanner "
            "mount and lands on the Command Centre at the site root")
    print(f"  [{'PASS' if ok else 'FAIL'}] base_path:no_bare_absolute_links   "
          f"offenders={len(offenders)}")


class _FakeKeyResp:                 # distinct from the techstack _FakeResp above
    def __init__(self, code):
        self.status_code = code
        self.text = '{"error":{"message":"synthetic"}}'

    def json(self):
        return {"error": {"message": "synthetic"}}


def _check_key_probe(failures):
    import importlib
    ws = importlib.import_module("websearch")
    for label, listing, gen, want, want_fp in KEY_PROBE_SCENARIOS:
        with mock.patch.dict(os.environ, {"GOOGLE_API_KEY": "AQ.synthetic-probe-key"}), \
             mock.patch("httpx.get", return_value=_FakeKeyResp(listing)), \
             mock.patch("httpx.post", return_value=_FakeKeyResp(gen or 200)):
            r = ws.check_key(timeout_s=1.0)
        got, fp = r.get("status"), bool(r.get("key_fingerprint"))
        ok = (got == want) and (fp == want_fp)
        if not ok:
            failures.append(
                f"key_probe[{label}]: HTTP {listing}/{gen} -> status={got!r} "
                f"(want {want!r}), fingerprint_present={fp} (want {want_fp}) — a "
                "rejected key must be reported as 'inactive' WITH its fingerprint, "
                "otherwise the operator gets no remediation hint and cannot tell "
                "which key is failing")
        print(f"  [{'PASS' if ok else 'FAIL'}] key_probe:{label:<21} "
              f"{listing}/{gen or '-'} -> {got} fp={fp}")


def _check_breach_intel(failures):
    import importlib
    bwd = importlib.import_module("breach_web_discovery")
    import scoring_analytics as _sa

    # (a) company matching: word boundary, not substring
    toks = bwd.company_tokens("Mip")
    fp = [v for v in BREACH_FP_VICTIMS if bwd.title_is_about(v, toks)]
    ok = not fp
    if not ok:
        failures.append(f"breach_match: '{'mip'}' still matches unrelated victims {fp} "
                        "(substring match reintroduced; a leak-site hit floors the verdict "
                        "at confirmed, so this asserts breaches at the wrong company)")
    print(f"  [{'PASS' if ok else 'FAIL'}] breach_match:false_positives   rejected "
          f"{len(BREACH_FP_VICTIMS) - len(fp)}/{len(BREACH_FP_VICTIMS)}")

    miss = [t for t, c in BREACH_TRUE_MATCHES if not bwd.title_is_about(t, bwd.company_tokens(c))]
    ok = not miss
    if not ok:
        failures.append(f"breach_match: genuine matches lost {miss}")
    print(f"  [{'PASS' if ok else 'FAIL'}] breach_match:true_positives    matched "
          f"{len(BREACH_TRUE_MATCHES) - len(miss)}/{len(BREACH_TRUE_MATCHES)}")

    bad = [t for t, c in BREACH_TRUE_NEGATIVES if bwd.title_is_about(t, bwd.company_tokens(c))]
    ok = not bad
    if not ok:
        failures.append(f"breach_match: unrelated headlines matched {bad}")
    print(f"  [{'PASS' if ok else 'FAIL'}] breach_match:true_negatives    rejected "
          f"{len(BREACH_TRUE_NEGATIVES) - len(bad)}/{len(BREACH_TRUE_NEGATIVES)}")

    # (b) fail-safe: an unresearched or clean result must score nothing
    for status, verdict in BREACH_FAILSAFE:
        got = _sa.researched_breach_risk({"status": status, "verdict": verdict})
        ok = got is None
        if not ok:
            failures.append(f"breach_failsafe: status={status}/{verdict} returned {got}, "
                            "must be None — an unresearched scan must never score as clean")
        print(f"  [{'PASS' if ok else 'FAIL'}] breach_failsafe:{status + '/' + verdict:<22} -> {got}")

    # (b1) undated researched incident must NOT borrow a scraped article date.
    # Live on the 2026-07-28 mip.co.za scan: the researched incident came back
    # undated, the code fell back to the news-RSS dates, and a 2020 article aged a
    # breach disclosed the previous month to "75.2 months" — which also fell
    # outside every recency band and silently dropped the RSI factor.
    from datetime import datetime as _dt, timezone as _tz
    _old = _dt(2020, 4, 21, tzinfo=_tz.utc)
    _undated_incident = [{"title": "x", "incident_date": "", "disclosure_date": ""}]
    got_dates = bwd._incident_dates(_undated_incident)
    ok = got_dates == []
    if not ok:
        failures.append(f"breach_undated: undated incident produced dates {got_dates}")
    print(f"  [{'PASS' if ok else 'FAIL'}] breach_undated:incident_dates    -> {got_dates or 'undated (correct)'}")
    # and the undated path must score as "date unestablished", not as an old breach
    r_undated = _sa.researched_breach_risk(
        {"status": "completed", "verdict": "confirmed", "researched": True,
         "months_since_most_recent": None})
    ok = bool(r_undated) and abs(r_undated[0] - 50.0) < 0.01
    if not ok:
        failures.append(f"breach_undated: undated confirmed scored {r_undated}, want 50.0")
    print(f"  [{'PASS' if ok else 'FAIL'}] breach_undated:risk_band         -> {r_undated}")

    # (b2) mid-scan key failure: a degraded verdict must not drive the score
    for label, extra, should_score in BREACH_DEGRADED:
        bi = {"status": "completed", "verdict": "confirmed",
              "months_since_most_recent": 1, **extra}
        got = _sa.researched_breach_risk(bi)
        ok = (got is not None) == should_score
        if not ok:
            failures.append(f"breach_degraded: {label} scored={got is not None}, "
                            f"expected {should_score} — a headline-only verdict dates "
                            "from the earliest ARTICLE, not the incident")
        print(f"  [{'PASS' if ok else 'FAIL'}] breach_degraded:{label:<22} scores={got is not None}")

    # (c) recency ladder, both channels
    for months, verdict, want_risk, want_rsi in BREACH_LADDER:
        bi = {"status": "completed", "verdict": verdict, "incident_count": 1,
              "months_since_most_recent": months}
        got = _sa.researched_breach_risk(bi)
        got_risk = round(got[0], 1) if got else None
        rsi = _sa.RansomwareIndex().calculate(
            {"breaches": {"status": "completed", "breach_count": 0, "issues": []},
             "credential_risk": {"risk_level": "LOW"}, "breach_intel": bi},
            industry="technology")
        f = [x for x in rsi.get("contributing_factors", []) if "repeat-victimisation" in x["factor"]]
        got_rsi = round(f[0]["impact"], 3) if f else 0.0
        ok = (got_risk == round(want_risk, 1)) and (got_rsi == round(want_rsi, 3))
        if not ok:
            failures.append(f"breach_ladder: {months}mo/{verdict} risk={got_risk} "
                            f"(want {want_risk}) rsi={got_rsi} (want {want_rsi})")
        print(f"  [{'PASS' if ok else 'FAIL'}] breach_ladder:{str(months) + 'mo/' + verdict:<18} "
              f"risk={got_risk} rsi_impact={got_rsi}")


def main():
    failures = []
    _check_breach_intel(failures)
    _check_key_probe(failures)
    _check_datastore_readiness(failures)
    _check_export_switch(failures)
    _check_credential_failclosed(failures)
    _check_provider_budget(failures)
    _check_lookalike_posture(failures)
    _check_table_headers(failures)
    _check_blocked_not_clean(failures)
    _check_base_path_links(failures)
    _check_balance_not_metered(failures)
    _check_hibp_and_waf_evidence(failures)
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
          f"{len(SUBDOMAIN_CT_SCENARIOS)} subdomain-ct + "
          f"{5 + len(BREACH_FAILSAFE) + len(BREACH_DEGRADED) + len(BREACH_LADDER)} breach-intel + "
          f"{len(KEY_PROBE_SCENARIOS)} key-probe + "
          f"{len(DATASTORE_SCENARIOS)} datastore-readiness + "
          f"{len(EXPORT_SWITCH_SCENARIOS)} export-switch + "
          f"{len(NON_CONCLUSIVE) * 2 + 11} credential-failclosed + "
          f"5 provider-budget + "
          f"{len(MX_SCENARIOS) + len(VERDICT_SCENARIOS) + 9} lookalike-posture + "
          f"3 table-header + "
          f"15 blocked-not-clean + 1 base-path + 2 balance-metering "
          "ground-truth scenarios")


if __name__ == "__main__":
    main()
