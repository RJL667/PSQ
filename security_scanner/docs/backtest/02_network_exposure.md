# Network & Exposure — Card Back-Test Findings

Method: credit-free Card Verification Protocol. Ground truth via Shodan **InternetDB** (free, keyless), `dig`, `ip-api.com` (free), Team Cymru DNS-ASN (free). Cached scans used: `test_fixtures/phishield_live.json` (full-API scan, real single-origin host), `test_fixtures/phishield_R10M_finance_2026-05-15.json` (InternetDB-only path), `test_fixtures/takealot_baseline.json` (Cloudflare-fronted, full-API). No live scans run.

---

## Open Ports / High-Risk Protocols (DNS & Open Ports card)
- **Source/provider:** `DNSInfrastructureChecker._scan_ports` (raw socket connect, 15 ports incl. 21/22/23/3306/3389) -> `dns_infrastructure.open_ports`; aggregated across all IPs by `scanner.py::_aggregate_ip_results`.
- **Ground-truth:** InternetDB confirms phishield primary `213.133.105.171` ports `[21,22,25,80,110,143,443,465,587,993,995,3306,5432]` — the scan's detected ports (21,22,80,110,143,443,993,995,3306) are a correct subset. For takealot, port 21/FTP `vsFTPd 3.0.5` is genuinely open on subdomain IP `34.76.113.116` (Google LLC; InternetDB `ports:[21]`), NOT on the Cloudflare apex.
- **Code trace:** `checkers_network.py:536-575` (_scan_ports) -> merge `scanner.py:323-332` -> render `templates/results.html:1337-1390` and `pdf_report.py:769-808` (`cat_dns`). Key keys: `open_ports[].port/risk/banner/detected_version`.
- **Verdict:** GAP (attribution)
- **Severity:** medium
- **Finding:** The DNS & Open Ports card renders the *merged* `open_ports` list (deduped by port across every discovered IP) on a single card whose top-level `ip`/`reverse_dns` is the primary (Cloudflare) IP. On CDN-fronted targets this conflates ports from multiple back-end IPs onto one apparent host — e.g. takealot's FTP (on a Google Cloud box) appears alongside the Cloudflare apex with no per-port IP attribution. Correct per-IP data exists in `per_ip` but the card never shows which IP each port belongs to. (On single-origin hosts like phishield the merge is accurate.)
- **Solution(s):** (1) In `cat_dns`/HTML, add an "IP" column to the risky-port detail rows sourced from `per_ip[ip].dns_infrastructure.open_ports` instead of the flat merged list (free, render-only). (2) Minimal: append the owning IP to each port chip label. (3) Suppress/relabel the card title to "Open Ports (all discovered IPs)" so the apex-IP header is not read as the host for every port.

---

## Database / Service Exposure (High-Risk Protocol card)
- **Source/provider:** `HighRiskProtocolChecker` (socket probe of 17 DB/admin ports: 139/445/161/27017/6379/9200/5432/1433/5984/7001/8888/11211/2375/2376/9092/4848/8069) -> `high_risk_protocols.exposed_services`.
- **Ground-truth:** phishield exposes 5432/PostgreSQL — InternetDB confirms `5432` open on `213.133.105.171` (tag `database`). takealot: `exposed_services: []` — InternetDB shows no DB ports on its Cloudflare/Google IPs. Both correct.
- **Code trace:** `checkers_network.py:786-839` -> render `templates/results.html:1395-1424`, `pdf_report.py:849-930`. `SERVICE_INTEL` enrichment (CVSS/EPSS/KEV) is hardcoded but matches authoritative refs (445 EternalBlue CISA KEV, 27017 no-auth, etc.).
- **Verdict:** PASS (with one cross-checker gap)
- **Severity:** low
- **Finding:** Detection + intel are accurate and correctly attributed (PostgreSQL on phishield is real and serious). Gap: port 5432 is scanned ONLY by `high_risk_protocols`, yet `dns_infrastructure.PORT_INTEL` carries a dead 5432 entry it never scans, and `dns_infrastructure.ALL_PORTS` lacks 5432/27017/6379/etc. The two port checkers use disjoint port sets with no overlap reconciliation, so a DB port shows on the DB card but never on the "Open Ports" card.
- **Solution(s):** (1) Accept the split (DB card is the canonical place) but delete the dead 5432 `PORT_INTEL` entry in `dns_infrastructure` to avoid confusion (code-hygiene, free). (2) Optionally surface `high_risk_protocols.exposed_services` ports as chips in the Open Ports card for a unified view.

---

## VPN & Remote Access / RDP
- **Source/provider:** `VPNRemoteAccessChecker` (apex 3389 socket + 8 VPN login-page fingerprints) -> `vpn_remote`; RDP reconciled across ALL IPs in `scanner.py` Phase 4a from per-IP `dns_infrastructure` 3389 hits.
- **Ground-truth:** phishield `rdp_exposed:false` — InternetDB shows no 3389 on its IPs (correct). 3389 IS in `dns_infrastructure.ALL_PORTS`, so the Phase-4a reconciliation has real data to read. RDP fix verified holding.
- **Code trace:** RDP fix `scanner.py:625-643` (sets `rdp_exposed=True` + `rdp_exposed_ips` from any per-IP 3389); checker `checkers_network.py:310-354`; render `results.html:1443-1458`, `pdf_report.py:932-976`.
- **Verdict:** BUG (VPN false-positive) — RDP path PASS
- **Severity:** medium
- **Finding:** RDP reconciliation fix is correct (resolves the apex-only false-negative). BUT the VPN signature match is weak: `Microsoft RDS Web` fires if the substring "remote desktop" or "rdweb" appears in the first 3000 chars of a GET to `/RDWeb/`, with no HTTP-status or login-form check. takealot_baseline shows `vpn_detected:true, vpn_name:"Microsoft RDS Web"` — a probable false positive (Cloudflare SPA soft-404 / "remote desktop" product category), rendered as a reassuring green "VPN detected" badge.
- **Solution(s):** (1) Require `r.status_code==200` AND a stronger token (e.g. `"RDWeb"` + `"workspace"`/form action) before asserting detection (free, checker edit). (2) Down-weight detections on CDN-fronted apexes (we already know the WAF/CDN provider). (3) Render an "unverified" qualifier when only a single soft keyword matched.

---

## Origin IP Discovery (Cloudflare-bypass)
- **Source/provider:** `origin_discovery.discover_origin_ips` — SecurityTrails historical A-records + Shodan cert `/host/count` (free) / `/host/search` (paid); each candidate auto-verified by TLS cert CN/SAN match before being scanned.
- **Ground-truth:** phishield_live: `verified:["213.133.105.171"]`, `unverified:["91.109.10.226","208.87.149.250"]`, `shodan_cert_hosts:0`. The verified IP's cert genuinely covers the domain (it is the live origin; InternetDB confirms it hosts the site). Cert-match gating is the standard, sound technique. Fix verified holding.
- **Code trace:** `origin_discovery.py:149-238` (`_verify_origin` TLS SNI cert match, `CERT_NONE` + manual CN/SAN check); wired `scanner.py:553-569`; render `results.html:1460-1491`, `pdf_report.py:977-1020` (`origin_discovery_block`). Both renderers gate on `status=='completed'` so the card is correctly hidden on no-key/skipped scans (e.g. takealot baseline has no `origin_discovery` key).
- **Verdict:** PASS
- **Severity:** n/a
- **Finding:** Discovery, cert-verification, verified-vs-candidate separation, and the "scan only verified" safety posture are all correct and well-attributed. Candidate IPs are surfaced but never port-scanned (respects under-the-radar posture). The `shodan_cert_hosts` gap hint is wired correctly. No bug found.
- **Solution(s):** Optional enhancement only: add the free crt.sh SAN-pivot as a third candidate source (already used by SubdomainChecker) so origin discovery degrades less when no SecurityTrails key is present — currently candidate generation is entirely key-gated.

---

## CVE / Known Vulnerabilities (Shodan / external_ips card)
- **Source/provider:** `ShodanVulnChecker` (InternetDB free, or Shodan full API if key) per IP, enriched with NVD CVSS + CISA KEV + FIRST EPSS + Metasploit/ExploitDB maturity + OSV.dev CPE->CVE; aggregated by `ExternalIPAggregator.aggregate` -> `external_ips`.
- **Ground-truth:** phishield's 19 CVEs are real, current OpenSSH issues (CVE-2024-6387 regreSSHion CVSS 10.0 / EPSS 0.64; CVE-2023-48795 Terrapin; CVE-2025-26465/26466) matching the `openssh:9.2p1` CPE InternetDB reports on `2a01:4f8:d0a:27c5::2`. CVSS/EPSS/KEV flags validate against NVD/FIRST. Counts consistent (19 = 7C/4H/8M). Attribution caveat: the host is a SHARED Hetzner box (`dedi5586.your-server.de`, also serving globalgrinders.com) — CVEs are real but not solely phishield's asset.
- **Code trace:** `checkers_threats.py:407-938`; aggregator `scoring_analytics.py:16-220`; render `results.html:1493-1670`, `pdf_report.py` (`cat_external_ips` + line 4369). Keys: `external_ips.ip_addresses[].shodan.{open_ports,cves,risk_score,...}`, `aggregate_vulns`.
- **Verdict:** BUG (two issues, both InternetDB-path / edge)
- **Severity:** medium
- **Finding:** (1) **ASN/Country mini-stats are fabricated on the free path.** `scoring_analytics.py:193-194` falls back `unique_asns = len(asns) or 1` / `unique_countries or 1`. InternetDB returns no ASN/org/geo, so the InternetDB-only fixture (R10M, 18 IPs across Hetzner-DE + AWS-ZA + Microsoft) renders **"1 ASN / 1 Country" and every org "Unknown"** — false data in an underwriting report. (2) **Latent >10-CVE undercount:** `checkers_threats.py:807-808` bumps `medium_count` for raw CVEs 11–20 without adding them to `cves`; `ExternalIPAggregator` recounts from the (≤10) `cves` list, so the per-IP card can drop CVEs 11+. Mitigated in practice by OSV.dev back-fill (phishield's 19 all rendered), so currently low-impact.
- **Solution(s):** (1) Drop the `or 1` fallbacks and either (a) hide ASN/Country/org stats when `data_source=='internetdb'`, or (b) enrich free via `ip-api.com` (45 req/min, no key — verified returns `AS16509 Amazon af-south-1 / South Africa` for 13.244.225.213) or Team Cymru DNS-ASN (keyless). Cost: free; ~1 cached call per unique IP. (2) Cap parity: enrich up to 20 CVEs or stop inflating `medium_count` for un-enriched CVEs.

---

## Cluster summary
cards=5, BUG=2 GAP=1 PASS=2 NEEDS-LIVE=0; headline = **the recent RDP and Origin-IP-Discovery fixes both held and verified clean; the live issues now are presentation/attribution — merged open-ports lose per-IP attribution on CDN-fronted targets, and the CVE card fabricates "1 ASN / 1 Country" + "Unknown" org on the free InternetDB path (fixable free via ip-api.com / Team Cymru).** Secondary: weak `Microsoft RDS Web` VPN fingerprint false-positives on Cloudflare SPAs (takealot).
