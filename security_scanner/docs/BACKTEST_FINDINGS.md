# Phishield Scanner — Card Back-Test Findings

> **STATUS UPDATE (2026-06-11): historical snapshot — the bugs below are FIXED.**
> All 17 bugs (and the targeted gaps) were fixed in Waves 1–4 and re-verified
> with zero regressions on 2026-06-03 — see **`RETEST_FINDINGS.md`** for the
> per-finding confirmation. Spot re-verified in code on 2026-06-11: #1 SSL
> (sslyze-6.x port, `checkers_core.py:71`), #2 DNSBL return-code validation
> (`checkers_network.py:1013`), #3 Exposed-Admin 200-only gate
> (`checkers_core.py:857`), #4 `_overall_score` wiring (`scanner.py:1114`),
> #5 F5 signature tightened, #6 CMS readme.txt validation, #7 wildcard-DNS
> guard, #8 password-bearing record count, #9 Mandrill/Zoho SPF classes,
> #10 severity tracks underlying breach, #11 ASN render guarded, #12
> `unique_emails` lower-cased, #15 DKIM `v=DKIM1` guard, #18 AAAA rendered,
> #22 ghost renderers deleted. #16 (dual remediation cards) fixed 2026-06-11.
> Still open by design: #17 S-1 auto-discovery (v1.2 roadmap), #20 IDN
> homoglyphs, parts of #13/#21 — tracked in `OUTSTANDING.md`.
> **Do not treat the findings below as the current state of the code.**

# Card Back-Test — Executive Summary

**Date:** 2026-06-02 (overnight autonomous run)
**Method:** Card Verification Protocol, credit-free — 7 parallel research agents, each auditing a card cluster against cached real scan data (phishield.com, takealot.com) plus free ground-truth (openssl, curl, dig, crt.sh, Shodan InternetDB). No paid APIs, no live scans, no source code edited.
**Coverage:** 34 cards across 7 clusters. **Result: 17 bugs, 7 gaps, 10 pass.**

---

## The headline: most bugs share five root causes

The individual findings are listed below, but the value is in the **patterns** — fixing the root cause clears several cards at once, and most fixes are free.

### Theme 1 — WAF/CDN responses scored as findings (the single biggest issue)
A Cloudflare/F5 edge returns **403 (blanket deny)** to anything sensitive and **200 (catch-all)** to anything else. Three checkers read those generic edge responses as positive findings:
- **Exposed Admin** treats a 403 on `/.env`, `/.git`, `wp-config.php` as a *critical exposure* — the logic is **inverted**: a 403 means the path is protected. Well-defended orgs are penalised hardest (backwards for underwriting).
- **CMS Plugin Surface** reads the 200 catch-all as plugin "presence" — flags takealot (not even WordPress) as WordPress with 25 plugins.
- **Subdomains** brute-forces against wildcard DNS (`*.takealot.com` resolves) and fabricates "risky" subdomains.

**The fix template already exists in-repo:** the S-3 dependency-manifest probe (`checkers_supply_chain.py` `_probe`, 200-only + body-sanity) is the correct WAF-robust pattern. Adopt it across Exposed Admin, CMS Plugins, and Subdomains. Free.

### Theme 2 — a generic/standard response read as a positive signal
- **DNSBL** counts *any* A-record answer as a blacklisting; Spamhaus's "open resolver / query blocked" reply (`127.255.255.254`) and URIBL's refusal (`127.0.0.1`) are misread → **every** scan returns `blacklisted:True`. Validate the documented return-code ranges. Free.
- **DKIM** counts any resolving `selector._domainkey` as a hit without checking `v=DKIM1` → a wildcard `*._domainkey` reports 41/41 selectors "found". Require `v=DKIM1`/`p=`. Free.
- **WAF (F5 BIG-IP)** fingerprints off `x-frame-options`, a ubiquitous standard header → false F5 detection + phantom WAF credit. Tighten the signature. Free.
- **VPN / RDS Web** flags a Cloudflare SPA as a Microsoft RDS gateway off a weak substring. Free.

### Theme 3 — a boolean rendered as a count (the bug fixed this session, not propagated)
The "13 with passwords" overstatement fixed in the Credential Exposure Correlation card this session **lives on in its siblings**:
- **Credential Risk Assessment** states "passwords for 4 emails across 13 records" when only **2 records / 1 mailbox** carry a password — and this one feeds the RSI score (HIGH → +0.15).
- **Dehashed** counts `Rudolph@` and `rudolph@` as two mailboxes (`unique_emails` not lower-cased) → inflated counts.
Both are the same free fix already proven this session: count password-bearing records; normalise case.

### Theme 4 — scoring decoupled from posture (wiring)
- **Financial Impact:** `vulnerability` is **pinned at 0.5 in production** because `cat_results["_overall_score"]` is never set before the financial calculator runs — so `p_breach`, incident probabilities, expected loss and every Monte-Carlo return-period tail are **decoupled from the actual risk score**. (This is the `_overall_score not propagated` WARN visible in the smoke test.) The regen/verifier paths inject the score, which masked it. One-line fix. **High priority — it undermines the headline financial numbers.**
- **CVE card** fabricates "1 ASN / 1 Country / org Unknown" on the free InternetDB path (which carries no geo/ASN). Free fix: ip-api.com (45/min, no key) or Team Cymru DNS-ASN.

### Theme 5 — ghosts, dead code, and stale tables
DNS records (AAAA/TXT/DNSSEC) computed but never rendered while a DNSSEC remediation still fires; two dead-ghost PDF renderers (`cat_ransomware_risk`, `cat_data_breach_index`); two divergent remediation cards rendered consecutively (R2.01M vs R2.70M); S-1 contributes nothing autonomously; `vendor_breaches.json` carries permanently-expired rows; hardcoded EOL table (use endoflife.date).

---

## Master findings table (severity-ranked)

| # | Card | Verdict | Severity | One-line finding | Fix cost |
|---|---|---|---|---|---|
| 1 | SSL/TLS | BUG | **critical** | sslyze 6.x API mismatch swallowed by `except: pass` → every cert graded "Invalid" (−40) on 100% of scans | Free |
| 2 | IP/Domain Reputation (DNSBL) | BUG | **critical** | any A-record = "listed"; Spamhaus open-resolver reply misread → every scan `blacklisted:True` | Free |
| 3 | Exposed Admin & Paths | BUG | **critical** | 403 (protected) counted as critical exposure — inverted; penalises well-defended orgs | Free |
| 4 | Financial Impact | BUG | **high** | `_overall_score` never set in prod → `vulnerability` pinned 0.5 → p_breach + all MC tails decoupled from posture | Free (1 line) |
| 5 | WAF | BUG | high | F5 signature keys off `x-frame-options` → false F5 + phantom WAF credit | Free |
| 6 | CMS Plugin Surface | BUG | high | CDN 200 catch-all → non-WordPress site reported WordPress + 25 plugins | Free |
| 7 | Subdomains | BUG | high | no wildcard-DNS guard fabricates subs; crt.sh shows 77 real vs 16 captured; PDF still claims "via CT" | Free |
| 8 | Credential Risk Assessment | BUG | medium | boolean `has_passwords` rendered as count ("4 emails / 13 records") — feeds RSI | Free |
| 9 | Email-Vendor Surface (S-4) | BUG | medium | Mandrill/Zoho SPF mis-classified "unknown" → suppresses a real HIGH Mailchimp breach match downstream | Free |
| 10 | Third-Party Cross-Correlation | BUG | medium | severity hard-set CRITICAL on any vendor overlap regardless of underlying breach severity; stale docstring | Free |
| 11 | CVE / Known Vulns | BUG | medium | fabricated "1 ASN / 1 Country / Unknown org" on free path | Free (ip-api) |
| 12 | Dehashed | BUG | medium | `unique_emails` case-sensitive → double-counts mailboxes | Free (1 line) |
| 13 | Open Ports / Protocols | GAP | medium | per-IP attribution lost on CDN targets (real FTP shown under Cloudflare apex) | Free (render) |
| 14 | VPN & Remote Access | BUG | medium | weak substring flags Cloudflare SPA as Microsoft RDS Web | Free |
| 15 | Email Security (DKIM) | BUG | medium | wildcard `*._domainkey` → 41/41 selectors "found" without `v=DKIM1` | Free |
| 16 | Remediation Roadmap | BUG | medium | two divergent remediation cards (R2.01M vs R2.70M) render consecutively; unbounded rsi_reduction sum | Free |
| 17 | Supply-Chain S-1 | GAP | medium | inert (broker-declared only; auto-discovery deferred); 2 expired `vendor_breaches.json` rows | Free |
| 18 | DNS Intelligence | GAP | low | AAAA/TXT/DNSSEC computed but never rendered; DNSSEC remediation still fires | Free |
| 19 | Technology Stack & EOL | GAP | low | hardcoded stale EOL table | Free (endoflife.date) |
| 20 | Fraudulent Domains (Typosquat) | GAP | low | ASCII-only homoglyphs miss IDN/Unicode confusables (dominant real vector) | Free |
| 21 | IntelX Dark-Web | BUG | low | non-reproducible count (asks 40, shows 60); infostealer text dumps all fall in `leak_count` → `darkweb_count` ~always 0 | Free |
| 22 | PDF dead-ghost renderers | BUG | low | `cat_ransomware_risk` / `cat_data_breach_index` read stale shapes; never wired | Free (delete) |

**PASS (verified accurate):** HTTP Security Headers, VirusTotal, HIBP Brand Breach, Hudson Rock, Third-Party JavaScript (S-2), Exposed Dependency Manifests (S-3), RDP/Remote (recently-fixed — held), Origin IP Discovery (recently-fixed — held), RSI (reconciles), DBI (reconciles).

---

## Recommended remediation order (all fixes free unless noted)

**Wave 1 — correctness bugs that distort every report (do first):**
1. SSL sslyze 6.x API fix (#1) — un-breaks cert grading on 100% of scans.
2. `_overall_score` wiring (#4) — re-couples the entire financial model to posture.
3. DNSBL return-code validation (#2) — stops universal false "blacklisted".
4. Exposed Admin 403-inversion (#3) — stop penalising defended orgs.

**Wave 2 — the WAF/CDN response-handling family (shared template):**
5. Adopt the S-3 `_probe` pattern (200-only + body-sanity + wildcard-DNS guard) across Exposed Admin (#3), CMS Plugins (#6), Subdomains (#7); switch Subdomains' primary source to crt.sh.

**Wave 3 — count/attribution accuracy:**
6. Boolean-as-count + case-normalisation (Credential Risk #8, Dehashed #12); S-4 vendor patterns (#9, unlocks the Mailchimp breach match); cross-correlation severity propagation (#10); CVE ASN/geo via ip-api (#11); per-IP port attribution (#13); WAF/RDS/DKIM signature tightening (#5, #14, #15).

**Wave 4 — ghosts & hygiene:**
7. Render or remove DNS-records/DNSSEC (#18); reconcile the two remediation cards (#16); delete dead PDF renderers (#22); prune expired vendor rows + plan S-1 auto-discovery (#17); endoflife.date EOL (#19); IDN typosquat (#20); IntelX count/darkweb classification (#21).

**Architecture / budget notes:** every fix above is free and respects the low-footprint posture — three use free keyless services already trusted by the design (crt.sh, Shodan InternetDB, ip-api.com / endoflife.date at 45/min no-key). None require live credit spend, aggressive probing, or new paid tiers. Calibration-class questions (factor magnitudes) were explicitly **deferred to FIN-9**; everything above is correctness, not calibration.

---

*Per-cluster detail follows.*


---

# Core Web Security — Card Back-Test Findings

Back-tested against two cached REAL scans: `test_fixtures/phishield_live.json` and
`charming-ishizaka-3b0bf1/.../test_fixtures/regen_outputs/takealot_live2.json`.
Free ground-truth: `openssl s_client`, `curl -sI`, `nslookup` (dig unavailable on Win),
plus live `sslyze` 6.3.1 dataclass introspection. No paid/metered APIs used.

## SSL / TLS
- **Source/provider:** `SSLChecker` (sslyze 6.3.1) → `categories.ssl`. Renderers: HTML `templates/results.html:1044-1080`, PDF `pdf_report.py:cat_ssl` (503-570).
- **Ground-truth:** `openssl s_client` shows BOTH certs are **valid and in-date** — takealot `*.takealot.com` (GoDaddy G2, notAfter Dec 2026), phishield `phishield.com` (DigiCert Encryption Everywhere DV, notAfter Oct 2026). CAA absent on both (legitimate −5). phishield HSTS absent on apex (legitimate −10).
- **Code trace:** `checkers_core.py:55-103` `_check_with_sslyze` populates `result["certificate"]` ONLY inside a `try/except Exception: pass` (102-103). Line 87 reads `dep.leaf_certificate_subject_matches_hostname` and lines 97/99 read `dep.verified_certificate_chain` — **neither attribute exists in sslyze 6.x** (verified via `dataclasses.fields(CertificateDeploymentAnalysisResult)`: hostname-match field is gone; `verified_certificate_chain` moved into `path_validation_results[i]`). So the access raises `AttributeError`, is swallowed, and `certificate` stays `{}`. Grade calc `_calculate_grade:265` then sees `cert.get("valid")` falsy → `−40 + "Invalid or unverifiable SSL certificate"`. Confirmed in BOTH fixtures: `data_source:"sslyze"` yet `certificate:{}`, `cert_chain_valid:null`, `key_size:null`.
- **Verdict:** BUG
- **Severity:** critical
- **Finding:** A stale sslyze-5.x API call breaks cert parsing on the installed sslyze 6.3.1 for EVERY scan. Result: every domain is falsely graded "Invalid certificate" (−40), so phishield shows D/45 (should be ~A/85) and takealot C/55 (should be ~A+/95). Cert Subject/Issuer/Expiry rows render blank/"—" in both HTML (guarded by `{% if ssl.certificate %}`) and PDF, and the C/D narrative wrongly blames "legacy protocols / weak ciphers" when TLS 1.0/1.1 are actually disabled. Scoring blast radius: inflates `ssl_risk=inv(score)` ×weight 0.09 (`scoring_analytics.py:615,747`); fires the "Weak SSL grade D" +0.05 probability factor (1087-1090); triggers phantom "Upgrade SSL/TLS R0–R3,600" remediation (3341-3342) and a 0.05 probability_reduction (3070). Mis-grades risk score AND premium on 100% of scans.
- **Solution(s):** (1) Port the cert block to the sslyze 6.x API: replace `leaf_certificate_subject_matches_hostname` with a hostname check against the leaf SANs, and read chain validity from `dep.path_validation_results` (`any(r.verified_certificate_chain for r in ...)`). Cost: free, ~1hr. (2) Defensive guard: if `data_source=="sslyze"` but `certificate=={}`, fall through to `_check_with_stdlib` (which already parses cert validity correctly) instead of grading as invalid — prevents silent-swallow false-positives on any future API drift. (3) Add a CI assertion in the smoke verifier that a known-good host (e.g. the scanner's own domain) never returns `certificate=={}` with `data_source=="sslyze"`.

## HTTP Security Headers
- **Source/provider:** `HTTPHeaderChecker` (`checkers_core.py:627-753`, `requests.get` with `allow_redirects=True`) → `categories.http_headers`. Renderers: HTML `results.html:1083-1108`, PDF `cat_http_headers`.
- **Ground-truth:** `curl -sIL`: takealot www returns CSP `frame-ancestors 'self'`, HSTS `max-age=2592000`, XFO `ALLOW-FROM origin`, no XCTO/Referrer/Permissions — matches fixture exactly. phishield www returns XFO `SAMEORIGIN`, Referrer `unsafe-url`, **XCTO `nosniff` present**, but fixture says XCTO missing.
- **Code trace:** Header presence/weights `checkers_core.py:723-730`; CSP quality `_analyze_csp:648-711`; score `750`. HTML iterates `hh.headers` and renders CSP quality block — accurate, no ghost.
- **Verdict:** PASS (with one drift + one minor gap)
- **Severity:** low
- **Finding:** Card logic and rendering are correct; takealot reproduces 1:1. Two issues: (a) DRIFT — phishield fixture shows `X-Content-Type-Options` missing but the live site now serves `nosniff`; the fixture predates a server config change (re-capture needed, not a code bug). (b) GAP — the checker awards full weight for header *presence* regardless of validity; takealot's `X-Frame-Options: ALLOW-FROM origin` is a deprecated/invalid value no modern browser honours, yet it scores full 15 pts and renders a green check.
- **Solution(s):** (1) For the drift, re-run a fresh capture of phishield before shipping; no code change. (2) Optional low-cost hardening: validate XFO values (`DENY`/`SAMEORIGIN` only; flag `ALLOW-FROM` as ineffective) and Referrer-Policy values (flag `unsafe-url` as leaky) — mirrors the existing CSP-quality sub-analysis, keeps presence-credit but adds a quality note. Free, ~1hr, reporting-only (no new weight, no double-count).

## WAF Detection
- **Source/provider:** `WAFChecker` (`checkers_core.py:760-841`) → `categories.waf`. Renderers: HTML `results.html:1132-1146` + stat tile `441`, PDF `cat_waf:731-766`.
- **Ground-truth:** `curl -sIL`: phishield = `Server: Apache` (WordPress), only `X-Frame-Options: SAMEORIGIN`, **no** `x-wa-info` or any F5 marker. takealot = `Server: cloudflare`, `cf-ray`, `__cf_bm` cookie (= genuine Cloudflare), only `X-Frame-Options: ALLOW-FROM origin`, **no** F5 marker.
- **Code trace:** `WAF_SIGNATURES["F5 BIG-IP ASM"]["headers"] = ["x-wa-info", "x-frame-options"]` (`checkers_core.py:787-791`). Matcher fires on ANY single header (819-821). `X-Frame-Options` is a ubiquitous standard security header → false match. Fixtures confirm: phishield `waf_name:"F5 BIG-IP ASM"` (no WAF exists); takealot `all_detected:["Cloudflare","F5 BIG-IP ASM"]` (Cloudflare real, F5 phantom).
- **Verdict:** BUG
- **Severity:** high
- **Finding:** Using `x-frame-options` as an F5 fingerprint produces a false "F5 BIG-IP ASM" WAF detection on essentially any site that sets XFO (most of them). phishield (no WAF at all) is reported as WAF-protected. This grants a phantom risk-score credit: `scoring_analytics.py:789-794` subtracts up to **50 points** from the risk score when `waf.detected` is true, and suppresses the "No WAF detected" remediation (3349), the +0.05 "No WAF" probability factor (1082-1084), and the RSI/BI −0.05 reductions (3064). Net effect: under-states risk and premium for any WAF-less site that merely sets a clickjacking header. The PDF/HTML also print reassuring "protected by F5 BIG-IP ASM" narrative that is simply untrue.
- **Solution(s):** (1) Remove `"x-frame-options"` (and the generic `"ts"` cookie) from the F5 signature; keep only the specific `x-wa-info` / `x-waf` / F5-specific cookies (`f5avr`, `bigipserver*`). Free, 5min, eliminates the false positive. (2) Add a confidence tier: require a vendor-specific header/cookie/body token (not a generic security header) before setting `detected=True`; treat ambiguous single-signal matches as "possible, unconfirmed" and do NOT bank the 50-pt credit on them. (3) Re-back-test phishield/takealot after the fix to confirm phishield→"No WAF" and takealot→`["Cloudflare"]` only.

## DNS Intelligence (SecurityTrails) + DNS Infrastructure
- **Source/provider:** SecurityTrails data → `categories.securitytrails`; DNS records/DNSSEC → `categories.dns_infrastructure`. Renderers: HTML SecurityTrails card `results.html:2320-2352`, PDF `cat_securitytrails:1850-1887`; DNS-records/DNSSEC rendering — see finding.
- **Ground-truth:** `nslookup` matches fixtures exactly. phishield A `213.133.105.171`, NS `ns1.your-server.de / ns3.second-ns.de / ns.second-ns.com`, MX `za-smtp-inbound-1/2.mimecast.co.za`. takealot A `104.16.71/72.64`, NS `lia/gordon.ns.cloudflare.com`, MX Google. DNSSEC: no `DNSKEY` on either → `dnssec_enabled:false` is correct. `associated_count:0` on both (plausible — empty pivot).
- **Code trace:** SecurityTrails card renders A/MX/NS + associated domains accurately; score is fixed `100` → `st_risk=inv(100)=0` at weight 0.01 (`scoring_analytics.py:678-683`) = correctly reporting-only, no double-count. BUT `dns_infrastructure.dns_records` (A/AAAA/MX/NS/**TXT**) and `dns_infrastructure.dnssec_enabled` are computed and stored yet **never rendered** — searched HTML for `dns_records|dnssec|AAAA|TXT records` = 0 matches; PDF `cat_dns:769-808` shows only ports/server/reverse-DNS/zone-transfer.
- **Verdict:** GAP (SecurityTrails card itself = PASS)
- **Severity:** medium
- **Finding:** The SecurityTrails card is accurate and honestly labelled "Info" (no fake grade). However `dns_infrastructure.dnssec_enabled` and the richer `dns_records` (notably AAAA and TXT — which carry SPF/verification tokens) are GHOSTS: computed by the checker, used to drive a hidden DNSSEC remediation (`scoring_analytics.py:3376-3377`), but shown on no card. An underwriter sees a DNSSEC remediation line with no corresponding "DNSSEC: disabled" status anywhere, and never sees the AAAA/TXT records the scanner already collected.
- **Solution(s):** (1) Add a "DNSSEC" row to the DNS & Open Ports card (HTML `results.html:~1319` and PDF `cat_dns` rows) sourced from `dns.dnssec_enabled` — free, ~15min, closes the remediation/status mismatch. (2) Optionally surface AAAA + TXT in the SecurityTrails/DNS card (TXT already partly duplicated by email checks, so render reporting-only to avoid clutter — no scoring change). (3) No scoring change needed; both are already reporting-only.

## Cluster summary
cards=4, BUG=2 GAP=1 PASS=1 NEEDS-LIVE=0; headline = **SSL cert parsing is broken against the installed sslyze 6.3.1** (stale 5.x attribute names swallowed by a bare `except: pass`), so EVERY scan falsely grades the certificate "Invalid" (−40 pts), mis-grading SSL (phishield D vs ~A, takealot C vs ~A+) and inflating risk score, premium, and phantom remediations on 100% of reports. Second-most-important: the WAF F5 signature keys off the ubiquitous `X-Frame-Options` header, falsely reporting "F5 BIG-IP ASM" and banking a phantom 50-point WAF credit on any WAF-less site that sets a clickjacking header.


---

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


---

# Email & Reputation — Card Back-Test Findings

Repo: `dazzling-germain-0b0427/security_scanner`. Method: cached JSON (phishield_live.json, takealot_live2.json) + free DNS via dnspython + code trace. No credits spent.

---

## Email Security (SPF / DMARC / DKIM / MX)
- **Source/provider:** `EmailSecurityChecker` in `checkers_core.py:318` — live DNS (TXT/MX), no API.
- **Ground-truth (free dnspython):**
  - phishield SPF = `v=spf1 redirect=_sn4qmlzpy.sdmarc.net` → checker `valid=True, has_redirect=True, dns_lookups=11, exceeds_lookup_limit=True`. CORRECT.
  - phishield DMARC = `p=reject; pct=100; rua=…` → `policy=reject, pct=100`. CORRECT.
  - phishield MX = mimecast.co.za x2; DKIM real key only at `k2._domainkey`. Cached shows `selectors_found:['k2']`. CORRECT.
  - takealot DKIM cached shows **all 41 selectors "found"**. Live query proves `nonexistent-xyz-123._domainkey.takealot.com` and `zzqqww._domainkey.takealot.com` BOTH resolve to a generic `heritage=external-dns…` TXT (a wildcard `*._domainkey` record), NOT DKIM keys. Only `google._domainkey` is a real `v=DKIM1` key.
- **Code trace:** `_check_dkim` (`checkers_core.py:452`) treats ANY successful `resolve(selector._domainkey.domain, TXT)` as a hit — never validates the TXT starts with `v=DKIM1` or contains `p=`. Rendered: `templates/results.html:1224` and `pdf_report.py:584` join `selectors_found`.
- **Verdict:** BUG (DKIM false-positive on wildcard `_domainkey`) + minor GAP (SPF qualifier).
- **Severity:** medium
- **Finding:** DKIM detection over-reports on any domain with a wildcard `*._domainkey` TXT (e.g. takealot reports 41/41 selectors "Found" when only 1 is real), giving a false "DKIM fully configured" impression. Separately, `_check_spf` (line 369) sets `dangerous` only for `+all`; it never distinguishes `~all` (softfail) from `-all` (hardfail) — a softfail SPF is scored identically to a strict one (GAP).
- **Solution(s):** (1) In `_probe`, require the returned TXT to start with `v=DKIM1` OR contain `p=` before counting a selector — drops wildcard noise, zero cost. (2) Parse the SPF all-qualifier (`-all`/`~all`/`?all`) and add a small penalty for non-`-all`; reporting-only, no new weight.

## IP / Domain Reputation (DNSBL)
- **Source/provider:** `DNSBLChecker` in `checkers_network.py:892` — DNS lookups against Spamhaus zen/dbl, spamcop, sorbs, barracuda, uceprotect, uribl.
- **Ground-truth (free dnspython):** `takealot.com.dbl.spamhaus.org` AND control `zzq-random-xyz123.com.dbl.spamhaus.org` BOTH return `127.255.255.254`; TXT = `"Error: open resolver; …"`. `phishield.com.dbl` → same. `…zen.spamhaus.org` TXT = `"Error: open resolver"`. `multi.uribl.com` → `127.0.0.1` (= query refused). These are Spamhaus/URIBL **error/blocked return codes**, NOT listings. spamcop/sorbs/barracuda/uceprotect all NXDOMAIN (correct).
- **Code trace:** `checkers_network.py:925/933` — `dns.resolver.resolve(…, "A")` succeeding → appended to listings, with NO inspection of the returned `127.x.x.x` value. Scored: `scoring_analytics.py:635-637` `dnsbl_risk = min(100, listed*50)`, weight `0.06` (line 482); also fires remediation row (line 3362) + financial probability uplift (line 3079). Rendered red at `templates/results.html:1710/1717`, `pdf_report.py:1076`.
- **Verdict:** BUG (systematic false-positive; always-fires inversion class)
- **Severity:** critical
- **Finding:** BOTH cached scans (phishield AND takealot — a clean top-1113 retailer) show `blacklisted:True` with `domain_listings:['dbl.spamhaus.org']`. The scan host's public resolver is rate-limited/blocked by Spamhaus, which returns `127.255.255.252/254`; the checker treats any A-answer as a listing. Every scan false-flags a DBL listing, inflating dnsbl_risk by `50*0.06 = 3` risk points, triggering a bogus "prior compromise/spam" remediation and premium-relevant probability uplift on clean domains.
- **Solution(s):** (1) Filter return codes: only count `zen` answers in `127.0.0.2–127.0.0.11` and `dbl` answers in `127.0.1.2–127.0.1.99`; treat `127.255.255.x` as "query blocked → checker unavailable", not a listing (free, decisive fix). (2) Run Spamhaus from a dedicated/authenticated resolver (DQS key, free tier) instead of a shared public resolver so error codes stop appearing. (3) Until fixed, suppress DBL/zen from scoring (set those zones reporting-only) to stop premium contamination.

## VirusTotal Reputation
- **Source/provider:** `VirusTotalChecker` in `checkers_threats.py:1370` — VT API v3 domains endpoint (free tier 4/min, 500/day); `no_api_key` fallback.
- **Ground-truth (cached, credit-free):** phishield `status:completed, malicious:0, suspicious:0, reputation:0, score:100, pop_rank:197905`; takealot `…score:100, pop_rank:1113`. Consistent with two clean, legitimate domains. No live VT lookup needed.
- **Code trace:** parses `last_analysis_stats`, `total_votes`, `categories`, `popularity_ranks`; `score = 100 - min(100, mal*10 + sus*5)` (line 1474). Scoring guards `no_api_key/auth_failed/rate_limited` → risk 0 (`scoring_analytics.py:672-683`, weight 0.05). Rendered with no-key fallback at `templates/results.html:2012/2029`, `pdf_report.py:1790`.
- **Verdict:** PASS
- **Severity:** n/a
- **Finding:** Card is accurate, correctly gated, and degrades cleanly without a key. Minor note: `reputation` (VT community score, can be negative) is captured but not used in `score` and not shown as a penalty; a strongly-negative community reputation would not lower the card. Low-priority enhancement, not a bug.
- **Solution(s):** (Optional) factor `reputation < -X` into the issues/score as a soft signal; reporting-only, no new weight.

## Fraudulent Domains (Typosquat / Lookalike)
- **Source/provider:** `FraudulentDomainChecker` in `checkers_threats.py:2050` — generates permutations, DNS-resolves them; opt-in (`include_fraudulent_domains`, default False).
- **Ground-truth:** Card is ABSENT from both cached scans (`'fraudulent_domains' in categories` = False) because the flag defaults off (`scanner.py:438`, `app.py:844`). Permutation logic verified by reading code only (no aggressive domain registration/queries).
- **Code trace:** 8 techniques (omission, swap, dup, homoglyph, keyboard, TLD, dot, hyphen); `_split_domain` (line 2082) handles `.co.za`/`.org.za` etc.; caps to 60 checked, 20 displayed. Scored `scoring_analytics.py:686` weight 0.04; rendered `templates/results.html:2058` (+ enabled/disabled fallback at 2094) and `pdf_report.py:2109`. When disabled the renderer shows the correct "enable to run" panel — no ghost.
- **Verdict:** GAP (coverage, not a bug)
- **Severity:** low
- **Finding:** No always-fires inversion (the disabled-state fallback is correct). But permutation coverage misses high-value classes for SA brand-abuse: (a) homoglyph map is ASCII-only — no Unicode/IDN confusables (e.g. Cyrillic `а`, `ο`) which are the dominant real-world lookalike vector; (b) no insertion/bitsquatting/transposition-of-words; (c) `dns_lookups`-style nested checks absent. Also resolution-only flagging misses registered-but-parked lookalikes that don't resolve.
- **Solution(s):** (1) Add IDN/Unicode confusable expansion (use the `confusable_homoglyphs` table, offline, free) — biggest accuracy win for phishing detection. (2) Optionally flag NS/registration via free RDAP for non-resolving permutations to catch parked squats. (3) Keep opt-in (cost/time), but document that disabling it leaves the brand-abuse kill-chain phase uncovered.

---

## Cluster summary
cards=4, BUG=2 GAP=1 PASS=1 (Email card carries both a BUG and a minor GAP; counted under BUG). NEEDS-LIVE=0.
**Headline:** DNSBL checker (`checkers_network.py:925/933`) counts Spamhaus/URIBL `127.255.255.x` "open-resolver / query-blocked" return codes as real blacklist listings — BOTH phishield and a clean top-1113 retailer (takealot) are flagged `blacklisted:True` on every scan, inflating dnsbl_risk (weight 0.06), triggering a false "prior compromise" remediation and a premium-relevant probability uplift. Fix by validating return-code ranges (free). Secondary: DKIM over-reports on wildcard `*._domainkey` records (takealot shows 41/41 selectors "found", only 1 real).


---

# Credential & Dark-Web — Card Back-Test Findings

Cohort: phishield.com cached scan (`test_fixtures/phishield_live.json`, scan 2026-06-01).
Credit-free: all reasoning from cached JSON + code trace. No live provider calls.
Scope: HIBP brand-breach, Dehashed, Credential Risk Assessment, Hudson Rock, IntelX.
Note: the "Credential Exposure Correlation" card was fixed earlier this session (`password_records=2`, renders "(2 with passwords)" correctly) — excluded from deep re-test but used as the reconciliation anchor below; it is the only one of the five that gets the password count right.

---

## 1. Brand Breach Record (HIBP)
- **Source/provider:** Have I Been Pwned free brand-breach endpoint (`BreachChecker.check`).
- **Ground-truth:** phishield `breaches` = `{breach_count: 0, breaches: [], data_classes: []}`. Correct: phishield is a B2B domain, not a consumer breached-service in HIBP's named catalogue. The card scope note explicitly defers email-level exposure to Credential Risk Assessment.
- **Code trace:** `checkers_threats.py:182-224` (free endpoint, 404→count 0). HTML `templates/results.html:1679-1706`; PDF `pdf_report.py:1026-1073`. Score wiring `scoring_analytics.py:619-620` (`breach_count*15`, cap 100), WEIGHTS `breaches=0.07`.
- **Verdict:** PASS
- **Severity:** n/a
- **Finding:** Renders correctly as "Clean — see Credential Risk", scope is well-disclaimed (no overstated "no exposure" claim), no double-count with Dehashed (separate weight, separate question). The free endpoint returns 404/empty for B2B domains by design.
- **Solution(s):** None needed. (Optional: the card says "Set HIBP_API_KEY to upgrade to paid domain-lookup" — fine; do not auto-enable, it is metered.)

---

## 2. Dehashed Credential Leaks
- **Source/provider:** Dehashed v2 search (`DehashedChecker.check`), paid/metered.
- **Ground-truth:** 13 records, 6 sources, **2 plaintext** (both ALIEN TXTBASE, `rudolph@`), 0 hashed, `corporate_count=9` (per-record), 4 `unique_emails`, `staff_accounts_total=4`. Score 68 (penalty `2*5 + 11*2 = 32`).
- **Code trace:** `checkers_threats.py:1175-1363`. HTML `templates/results.html:1790-1827`; PDF `pdf_report.py:1505-1566`. Score wiring `scoring_analytics.py:667-669`.
- **Verdict:** BUG (two, both low/medium)
- **Severity:** medium
- **Finding:**
  (a) **`unique_emails` case-sensitivity double-count.** `emails_seen` is a case-sensitive set (`checkers_threats.py:1255-1260`), so `Rudolph@phishield.com` and `rudolph@phishield.com` count as 2 distinct mailboxes → `unique_emails=4` when there are only **3** real mailboxes (louise, nkululeko, rudolph). This inflates the "Unique emails" row on the Dehashed card AND propagates into the Credential Risk factor (card 3) and the RSI composite. The masked staff list shows the same address twice (`Ru***h@` and `ru***h@`).
  (b) **Two-meaning "corporate" count.** Dehashed card shows `corporate_count=9` ("9 corporate") which is per-record, while the remediation/exec cards use `staff_accounts_total=4` (unique). Same underlying data, two different numbers on different pages — reader confusion, not a math error.
  Minor adjacent: a record with BOTH plaintext and hash (`has_hash:true, has_password:true`) is counted only as plaintext (`elif` at line 1275), so the per-row "[HASH EXPOSED]" flag can coexist with `hashed_count=0`. Cosmetic.
- **Solution(s):** (1) FREE — lowercase the email before adding to `emails_seen` (and dedupe the masked staff list case-insensitively) at `checkers_threats.py:1255-1260` / `:1314`; fixes (a) and the duplicated masked address in one line. (2) Label disambiguation — rename the Dehashed-card row to "Corporate records (9)" vs exec "Staff mailboxes (4)", or render both as unique. (3) No scoring change needed; `total_entries*2` is unaffected by email dedupe.

---

## 3. Credential Risk Assessment (CredentialRiskClassifier)
- **Source/provider:** Composite — Dehashed + HIBP enrichment + Hudson Rock + IntelX (`CredentialRiskClassifier.classify`).
- **Ground-truth:** `risk_level=HIGH, risk_score=55`. Score reconstructs exactly: 100 − 30 (passwords) − 15 (recent breaches) = 55; IntelX 60-leak adds a factor line only (no deduction, correct — `darkweb=0`). Recency factor names SocRadar.io + ALIEN TXTBASE as "2023+".
- **Code trace:** `checkers_threats.py:1789-1934`; HIBP enrichment `:1741-1782`; `KNOWN_BREACH_DATES` `:1796-1807`. HTML `templates/results.html:1970-2009`; PDF `pdf_report.py:1717-1787`. Feeds RSI at `scoring_analytics.py:1018-1032` (HIGH → +0.15 RSI base).
- **Verdict:** BUG
- **Severity:** medium
- **Finding:**
  (a) **Boolean-as-count overstatement (same bug-class as the just-fixed correlation card).** Factor text (`:1870`) reads *"Plaintext or hashed passwords exposed for 4 email(s) across 13 breach record(s)"* — but `has_passwords` is a single boolean OR over all records; only **2 records / 1 unique mailbox** actually carry a password. The card asserts passwords for "4 emails across 13 records" when reality is 2 records, 1 email. This is the exact pattern the correlation fix corrected (it now says "2 with passwords") but the Credential Risk card was NOT updated to match.
  (b) **Recency anchoring of combo lists is heuristic.** `KNOWN_BREACH_DATES["alien txtbase"]="2024-12-01"` (`:1797`) anchors a continuously-recompiled stuffing/combo compilation to a single "fresh" date, so it is counted as a 2023+ "recent breach" driving the HIGH level (−15). ALIEN TXTBASE is re-circulated infostealer/combo data, not a point-in-time corporate breach — recency attribution is soft. (The sibling correlation card sets `combo_only:false` and still treats it as recent.)
- **Solution(s):** (1) FREE — change the factor to count password-bearing records, mirroring the correlation fix: use `dehashed.credential_breakdown.plaintext_count + hashed_count` (=2) and the password-bearing unique-email count, e.g. "passwords exposed for 1 mailbox across 2 of 13 records". (2) FREE — flag combo/stuffing sources (ALIEN TXTBASE, Naz.API, Collection #1, RockYou) as "re-circulated, date approximate" in the recency factor so HIGH is not driven purely by a guessed combo-list date; or down-weight combo-list recency vs named-breach recency. (3) Architecture: keep classifier scored via RSI (already correct, no standalone weight) — do not add to WEIGHTS.

---

## 4. Hudson Rock Infostealer Detection
- **Source/provider:** Hudson Rock Cavalier free OSINT API (`HudsonRockChecker.check`).
- **Ground-truth:** `compromised_employees=0, users=0, third_party_exposures=1, total=0, score=95`. Score math correct (100 − 1×5). Card header shows "1 third-party"; one issue line. Infection-date anchors all null (no employee/user hits) — consistent.
- **Code trace:** `checkers_threats.py:1591-1692`. HTML `templates/results.html:1909-1932`; PDF `pdf_report.py:1569-1637`. NOT in WEIGHTS — scored indirectly via `credential_risk.risk_level` → RSI (`scoring_analytics.py:1018-1032`). Design note `scoring_analytics.py:505-515` confirms reporting-via-composite is intentional (no double-count).
- **Verdict:** PASS (one low-severity gap)
- **Severity:** low
- **Finding:** Card is accurate and correctly attributed. Gap: the **third-party exposure does not influence the score at all.** Hudson Rock only reaches the score through `credential_risk`, and the classifier (`:1820-1835`) keys exclusively on `compromised_employees`/`compromised_users` — `third_party_exposures` is read by nobody for scoring. So phishield's 1 third-party infostealer hit is surfaced but contributes 0 to RSI / overall. Defensible (third-party is supply-chain, handled elsewhere) but it is a silent reporting-only signal.
- **Solution(s):** (1) FREE — leave as-is (third-party credential risk is genuinely covered by the S-1/S-5/third_party_correlation supply-chain channel; adding it to credential_risk would double-count). (2) If desired, surface a tiny MEDIUM nudge in `credential_risk` only when third_party>0 AND no other credential signal exists (avoids the current "1 third-party, LOW overall" blind spot) — but verify no double-count with vendor_breach first.

---

## 5. IntelX Dark-Web Monitoring
- **Source/provider:** Intelligence X free tier (`IntelXChecker.check`). Free tier = 50/day, reset midnight UTC.
- **Ground-truth:** `total_results=60, leak_count=60, paste_count=0, darkweb_count=0`. All 60 records are media "Text File" → all classified as `leak`. `recent_results` capped at 10 (dates 2026-04-16 back to 2025-06, all pre-scan — recency sane). Score 100 (no darkweb, pastes ≤5). The 60 here are infostealer-log filenames (`.rar/...Microsoft Edge_Default.txt`, ZA IP-tagged) — consistent with infostealer dumps, correctly described in the PDF narrative.
- **Code trace:** `checkers_threats.py:1941-2043`. HTML `templates/results.html:1934-1968`; PDF `pdf_report.py:1640-1714`. NOT in WEIGHTS; reaches score via `credential_risk` IntelX factor (informational unless `darkweb_count>0`).
- **Verdict:** BUG (low)
- **Severity:** low
- **Finding:** **Request/result count mismatch.** The live request asks `maxresults: 40` (`:1970`) but the cached result has `total_results=60`. The free `/intelligent/search` does not strictly honour the 40 cap here, so the displayed "60 results" reflects whatever the API returned — a fresh re-scan could return a different number for the same domain, making the headline count non-reproducible. Secondary: every record falls into `leak_count` because the media-type map (`:2004-2010`) only recognises `media in (1,2)=paste` and `media==13=darkweb`; infostealer text dumps (the dominant IntelX content) all land in the catch-all `leak` bucket. That is acceptable (they ARE leak entries) but means `darkweb_count` will almost always be 0 even for genuine criminal-forum infostealer logs — the "Dark web mentions" row understates.
- **Solution(s):** (1) FREE — align the displayed count with the request cap (set `maxresults` to the intended display cap, or label the total as "≥N / first page") so the headline is reproducible. (2) FREE — recognise infostealer-log filename patterns (`.rar/...Default.txt`, IP-tagged archives) as dark-web-grade rather than generic "leak", OR rename the "Dark web mentions" row to "Forum/market mentions" and keep infostealer dumps under "Leak DB entries" with a note that these are stealer logs (the PDF narrative already explains this well; the HTML kv-table does not). (3) Sustainable-replacement for IntelX 50/day is a known open item — out of scope here.

---

## Cluster summary
cards=5, BUG=3 GAP=0 PASS=2 NEEDS-LIVE=0; headline = **Credential Risk Assessment repeats the just-fixed boolean-as-count bug** — its factor claims "passwords exposed for 4 email(s) across 13 breach record(s)" when only 2 records / 1 mailbox carry a password (and the `unique_emails=4` itself is inflated by a case-sensitivity double-count of `Rudolph@`/`rudolph@`, real count 3). Both are FREE one-line fixes; the email-dedupe fix also cures the duplicated masked staff address. Hudson Rock + IntelX are correctly architected as reporting-only-via-RSI (no double-count), but HR third-party and IntelX infostealer-log classification are silent/understated (low severity). HIBP brand-breach is clean and correctly scoped.


---

# Attack Surface & Tech — Card Back-Test Findings

Fixtures used: `test_fixtures/phishield_live.json` (F5 BIG-IP ASM WAF),
`.../charming-ishizaka-3b0bf1/.../takealot_live2.json` (Cloudflare).
Ground truth: crt.sh (`%25.takealot.com` → **77** real subdomains), `nslookup`,
non-intrusive `curl -I` against takealot.

> **Cluster headline (read first):** A single root cause — **WAF/CDN HTTP 403
> blanket-deny + 200 catch-all responses are treated as positive findings** —
> corrupts 3 of the 5 cards (Exposed Admin, CMS Plugin Surface, and via
> wildcard DNS the Subdomains card) on BOTH fixtures. The phantom findings max
> out `admin_risk` and `sub_risk` in the score, so **better-defended orgs (WAF
> present) are penalised harder** — an underwriting inversion.

## Subdomains (CT logs / crt.sh)
- **Source/provider:** `SubdomainChecker` — crt.sh CT logs (Source 1) + DNS brute-force of 48 prefixes (Source 2).
- **Ground-truth:** crt.sh returns **77** real subdomains for takealot.com (incl. high-value `admin.`, `jira.`, `remotessl.`, `cpt-hq-fortiauth.`, `urbackup.hq.`, `security-elasticsearch-*`, `sellercapital.`). The takealot fixture captured **ct_count=0** (crt.sh empty/slow during scan) and fell back to **16 brute-forced** names. `nslookup thisdoesnotexist-zzz99.takealot.com` **resolves** → `*.takealot.com` is a **wildcard**. So brute "hits" like `jenkins./grafana./kibana./backup./crm./webmail./ftp.` are wildcard phantoms (none appear in crt.sh's authoritative list); 9 of them are flagged "risky".
- **Code trace:** `checkers_network.py:143-160` (crt.sh) + `:162-180` (brute, no wildcard guard) → `:251` risky filter → score `:258/265`. Render `templates/results.html:1752-1788`; `pdf_report.py:1149-1190`. Score `scoring_analytics.py:655-656` `sub_risk=min(100, risky*15)`. `ct_count` set at `:158` *before* the 150-cap at `:183` (can exceed `total_count`).
- **Verdict:** BUG (+ GAP on CT completeness)
- **Severity:** high
- **Finding:** No wildcard-DNS detection → brute-force fabricates "risky" subdomains on any wildcard apex; for takealot that yields 9 phantom risky subs that max `sub_risk` to 100. Separately, when crt.sh is empty/slow the card silently under-discovers (16 vs 77 real) yet the PDF still narrates "discovered via Certificate Transparency logs." `ct_count` can exceed `total_count` after the cap.
- **Solution(s):** (1) Add a wildcard probe — resolve one random label; if it resolves, drop brute-force results that share that IP set (free, ~1 extra DNS query). (2) Make crt.sh resilient: retry once + fall back to a second free CT source (certspotter free tier) and mark `ct_source_ok=false` so the PDF stops claiming CT when it was brute-only. (3) Set `ct_count` after the cap (or label it "CT entries pre-cap").

## Exposed Admin & Sensitive Paths
- **Source/provider:** `ExposedAdminChecker` — HEAD/GET probes of 38 admin/sensitive paths.
- **Ground-truth:** phishield fixture: **all 12** critical paths (`.env`, `.git/HEAD`, `wp-config.php`, `backup.sql`…) return **identical HTTP 403** behind **F5 BIG-IP ASM**. takealot: 4 critical paths all **403** behind **Cloudflare**. Live `curl -I https://www.takealot.com/.env` = **403**, but a random control path = **200** → the 403s are WAF managed-rule blanket-denies, not real exposures.
- **Code trace:** `checkers_core.py:1016` — `r.status_code == 200 or (risk=="critical" and r.status_code in [401,403])` counts 403 as a critical finding. Render `results.html:1730-1748`; `pdf_report.py:1116-1145` ("…including N critical exposure(s)"). Score `scoring_analytics.py:626-628` `admin_risk=min(100, crit*50+high*20)` → both fixtures hit **100**.
- **Verdict:** BUG (inversion)
- **Severity:** critical
- **Finding:** A WAF returning 403 to `/.env` means the file is **protected**, yet the checker reports it as a "critical exposure" and the PDF says "N critical exposure(s)". With WAF active, every critical path 403s → `critical_count` 12 (phishield) / 4 (takealot), `admin_risk` maxes to 100. WAF-protected orgs are scored as worst-case.
- **Solution(s):** (1) Treat 403/401 as "present-but-protected" (info, not critical) — only HTTP **200** with a non-WAF body counts as exposure. (2) WAF-aware suppression: if `waf.detected`, require a 200 + content-type/size sanity check before flagging. (3) Detect blanket-deny: if ≥N critical paths all return the same status from the same WAF, collapse to one "WAF blocks sensitive paths (good)" note.

## Technology Stack & EOL
- **Source/provider:** `TechStackChecker` — `Server`/`X-Powered-By` headers + hardcoded `EOL_SIGNATURES` table + CMS/JS-lib regex on body.
- **Ground-truth:** phishield: `Server: Apache` only, no EOL → correct PASS. takealot: `Server: cloudflare`, `X-Powered-By: Awesome` (Cloudflare's joke header) shown verbatim as "disclosed technology". `EOL_SIGNATURES` is **stale vs endoflife.date**: no PHP 8.0 (EOL Nov-2023) / 8.1 (EOL Nov-2025, live today 2026-06-02), no Node 18 (EOL Apr-2025)/20, no nginx ≥1.20, no Apache 2.4 branch.
- **Code trace:** `checkers_threats.py:14-49` (table) `:80-103` (header+EOL match) `:166` `eol_count`. Render `results.html:2242-2266` (`ts_tl='tl-crimson' if eol else 'tl-green'` — **no amber**, and X-Powered-By/jQuery/AngularJS penalties never move the light). Score `scoring_analytics.py:640` + REMEDIATION `:3360` keyed on `eol_count`.
- **Verdict:** GAP (+ minor BUG)
- **Severity:** medium
- **Finding:** EOL table is hand-maintained and already behind current endoflife dates (misses PHP 8.x, Node 18/20, modern nginx/Apache) so it will under-detect on real SA stacks; `X-Powered-By: Awesome` is surfaced as if meaningful; traffic light is binary (red/green) despite info-leak/old-jQuery penalties.
- **Solution(s):** (1) Replace the hardcoded table with the free **endoflife.date** JSON API (cached daily) keyed by detected product+major — kills staleness for ~0 cost. (2) Filter known-decoy headers (`X-Powered-By: Awesome`, PHP/ASP echo from CDNs) before display. (3) Add an amber light when `score < 100` but no EOL (info-leak / old-JS).

## CMS Plugin Surface (WordPress)
- **Source/provider:** `CMSPluginSBOMChecker` — `_is_wordpress` discriminator then probes 25 popular plugin dirs for `readme.txt` Stable-tag.
- **Ground-truth:** takealot is **not WordPress** (custom React/Node SPA) yet fixture shows `is_wordpress=True`, `plugin_count=25` (all `status_code 403`, 0 versioned). Live: `curl -I /wp-content/` and `/wp-login.php` → **200** (CDN catch-all), random path → **200**. So `_is_wordpress` trips on the 200 catch-all and every plugin dir "exists". phishield: 25/25 plugins, all 403 behind F5 — also implausible (no single site runs all 25 of these).
- **Code trace:** `checkers_supply_chain.py:871-886` `_is_wordpress` (accepts 200/301/302/401/403) → `:888-908` `_probe_plugin` (accepts 200/301/302/401/403) → `:941-962` score. Render `results.html:2268-2298`; `pdf_report.py:2407`. Score `scoring_analytics.py:735-736` `cms_risk=inv(score)`, weight 0.03, REMEDIATION `:3387`.
- **Verdict:** BUG (false positive)
- **Severity:** high
- **Finding:** Accepting 403 (and any non-404) as "plugin present" + a 200/403 catch-all defeating the WP discriminator makes the card report a full 25-plugin WordPress SBOM for sites that aren't WordPress (takealot) or behind a WAF (phishield). `cms_risk` then contributes phantom risk via the 0.03 weight.
- **Solution(s):** (1) Require **HTTP 200** AND a successfully-parsed `readme.txt` Stable-tag (or a plugin asset) — a bare 403 dir is not evidence of a plugin. (2) Harden `_is_wordpress`: confirm a real WP fingerprint (`wp-json` API 200 with JSON, or `wp-content` 200 serving a real asset), and bail if a random control path also 200s (catch-all). (3) Cap/flag "all 25 probed plugins matched" as a WAF/catch-all artefact, not a finding.

## Exposed Dependency Manifests (S-3)
- **Source/provider:** `DependencyManifestChecker` — HEAD+GET 15 manifest/lockfile paths, parse deps, OSV.dev CVE cross-ref.
- **Ground-truth:** Both fixtures: `exposed_manifests=[]`, 0 deps, 0 CVEs — correctly clean. This checker is the **only one of the five that handles WAF correctly**: `_probe` (`:188-201`) requires HTTP **200**, rejects HTML/`<!doctype`/"not found"/"404" bodies, and demands ≥10 bytes — so a WAF 403 is correctly ignored. Card hidden when `status != completed`/no manifests, so no empty-card noise.
- **Code trace:** `checkers_supply_chain.py:136-520`; OSV enrich `:348-413`; render `results.html:2142-2197`; `pdf_report.py:2206`. Score `scoring_analytics.py:723-724` `dm_risk=inv(score)`, weight 0.04, REMEDIATION `:3381`.
- **Verdict:** PASS
- **Severity:** n/a
- **Finding:** Logic is sound and WAF-robust; the 200-only + body-sanity gate in `_probe` is exactly the pattern the Admin and CMS checkers are missing. Minor: only exact-pinned versions are OSV-queried (SemVer ranges skipped by design — documented, acceptable).
- **Solution(s):** Use `_probe`'s 200-only + body-sanity gate as the template to retrofit `ExposedAdminChecker` and `CMSPluginSBOMChecker`.

## Cluster summary
cards=5, BUG=3 GAP=1 PASS=1 NEEDS-LIVE=0; headline = **WAF/CDN 403 blanket-deny and 200 catch-all responses are scored as positive findings**, fabricating "12 critical exposures" + a full 25-plugin WordPress SBOM + 9 wildcard-DNS "risky subdomains" on WAF/CDN-fronted orgs — maxing `admin_risk` and `sub_risk` and **penalising well-defended targets**. `DependencyManifestChecker._probe` already does it right (200-only + body sanity) and should be the fix template.


---

# Supply-Chain & Correlation — Card Back-Test Findings

Cached data used: `test_fixtures/phishield_live.json` (HTTP 403 on homepage → S-2/S-4/S-5
all empty/no_data) and `worktrees/charming-ishizaka-3b0bf1/.../regen_outputs/takealot_live2.json`
(rich SPF + Hudson Rock data — primary back-test target). S-1 absent from both fixtures
(broker-declared-only, no siblings supplied). Free verification: `curl` takealot homepage,
`dig TXT` takealot SPF chain, Python classifier replay. No paid calls spent.

## Supply-Chain / Related Domains (S-1)
- **Source/provider:** `RelatedDomainsChecker.check()` — broker-declared sibling domains only (v1.0); LITE re-scan (SSL + DNS + info-disclosure) of each declared domain.
- **Ground-truth:** Neither fixture contains a `related_domains` key — both scans ran without a declared sibling list, so the checker returns `status="skipped"` and the HTML/PDF cards correctly do not render (gated on `status=='completed' and declared_count>0`, results.html:2105). Matches the documented v1.0 scope (broker-declared only; v1.1 auto-discovery deferred).
- **Code trace:** `checkers_supply_chain.py:34-133` (gated on `related_domains` arg) → invoked `scanner.py:513-523` only `if related_domains:` → `templates/results.html:2104-2140` / `pdf_report.py:cat_related_domains` 2150. WEIGHTS 0.04 (line 499), uplift +0.04 on `critical_count>0` (line 2071), REMEDIATION row (line 3379). All wired once.
- **Verdict:** GAP
- **Severity:** medium
- **Finding:** Card is correctly built and wired, but is **inert without broker input** — on an autonomous scan (the stated operating model: "scanner runs without a human in the loop") S-1 contributes nothing. The whole supply-chain-discovery value prop vs KYND/Coalition depends on auto-discovery that is still deferred. Cannot validate render path against live data (NEEDS-LIVE with a declared sibling list).
- **Solution(s):** (1) Ship S-1 v1.1 auto-discovery using the free methods already scoped in memory (crt.sh cert-SAN scrape + WHOIS registrant match + favicon hash) feeding a candidate list, then autonomously confirm via TLS cert-match (per the autonomous-verification memo) before LITE-scanning — no broker gate. (2) Until then, surface an explicit "0 siblings declared — supply-chain depth not assessed" note so the absence is visible to the underwriter rather than silent.

## Third-Party JavaScript (S-2)
- **Source/provider:** `ThirdPartyJSChecker.check()` — homepage `<script src>` parse; SRI-presence, known-compromised-CDN match (polyfill.io/bootcss), third-party host volume.
- **Ground-truth:** takealot fixture: `total_scripts=9, third_party_count=0, score=100`. **Verified accurate** by `curl` — takealot is a Next.js app serving all 9 scripts from first-party relative `/_next/static/...` paths (incl. a first-party `polyfills-*.js` chunk that is correctly NOT confused with `polyfill.io`). phishield fixture: `status="error", HTTP 403` (bot-blocked) → card hidden (gated on `status=='completed'`).
- **Code trace:** `checkers_supply_chain.py:523-674`; `_host_of` (553) returns `primary` for relative/`/`-rooted src (correct first-party classification); renderer `results.html:1150-1191` / `pdf_report.py:2279`. WEIGHTS 0.03 (501), uplift +0.06 on `compromised_host_count>0` (2065), REMEDIATION on compromised-host OR >50% missing-SRI (3383). One channel each — no double-count.
- **Verdict:** PASS
- **Finding:** Logic and rendering are correct; the takealot 0/9 result is true ground truth, not a parser miss. One robustness limitation: a 403 (phishield) silently hides the card, so a bot-protected insured shows no S-2 assessment at all — same "silent absence" pattern as S-1.
- **Solution(s):** (1) On `status=="error"` render a muted "homepage blocked (HTTP 403) — third-party JS not assessable" stub so the gap is visible. (2) Optional free upgrade: retry with a browser User-Agent (the curl test got HTTP 200 from takealot with a Mozilla UA) to cut false 403s.

## Email-Vendor Surface / SPF (S-4)
- **Source/provider:** `EmailVendorSurfaceChecker.check()` — recursive SPF `include:` walk → `VENDOR_PATTERNS` suffix-match → vendor list + DMARC policy.
- **Ground-truth:** takealot live SPF (`dig` confirmed): `include:_spf.google.com, mail.zendesk.com, spf.mandrillapp.com, transmail.net, _spf.123formbuilder.com`. Card reports `vendor_count=2 (google_workspace, zendesk), unknown_count=5, dmarc=quarantine`. Two **mainstream vendors are misclassified as "unknown"**: `spf.mandrillapp.com` = **Mandrill (Mailchimp transactional)** and `transmail.net` = **Zoho TransMail/ZeptoMail**. Replayed `_classify()` → both return `''`.
- **Code trace:** `checkers_supply_chain.py:677-832`; `VENDOR_PATTERNS` 681-715 has `mailchimp` keyed only on `servers.mcsv.net`/`_spf.mailchimp.com` (NOT `mandrillapp.com`) and `zoho` keyed on `zoho.com`/`zohomail.com` (NOT `transmail.net`). Renderer `results.html:1264-1300` / `pdf_report.py:2342`. WEIGHTS 0.02 (502), REMEDIATION on weak-DMARC (3385).
- **Verdict:** BUG
- **Severity:** medium
- **Finding:** Pattern gap drops two real, common email vendors into the unscored "unknown" bucket. Beyond under-counting the vendor surface, the Mandrill miss is **load-bearing**: Mandrill→`mailchimp` key has two HIGH-severity breaches in the DB, so the miss propagates into S-5 and the cross-correlation (see below).
- **Solution(s):** (1) Free 1-line fix: add `mandrillapp.com` to the `mailchimp` pattern list and `transmail.net`/`zeptomail.com` to `zoho` (or a new `zoho_transactional` key) in `VENDOR_PATTERNS`. (2) Consider adding `123formbuilder.com` as informational. Back-test impact: takealot would then show 3-4 classified vendors and trigger the Mailchimp breach match.

## Vendor Breach Correlation (S-5)
- **Source/provider:** `VendorBreachChecker.check()` — re-walks SPF, classifies vendors, joins against `vendor_breaches.json` (14 rows) with 5-yr lookback + linear age-decay penalty.
- **Ground-truth:** takealot: 1 match — `zendesk` 2022-10-28, **medium**, `vendor_internal_logs`, penalty 2.25, score 98. Match is correct given the (limited) classified vendor set. DB audit: all 14 vendor keys map cleanly to `VENDOR_PATTERNS` (no dead keys). **But the join is starved upstream**: because Mandrill isn't classified (S-4 bug), the two HIGH-severity `mailchimp` breaches (2023-01, 2022-08) are never tested against takealot, understating its true vendor-breach exposure. Also found **2 permanently-expired DB rows** (`sendgrid` 2018, age 2975d; `constant_contact` 2021-05-25, age 1833d) that exceed `LOOKBACK_DAYS=1825` and can never match; `marketo` (1805d) expires in ~3 weeks.
- **Code trace:** `checkers_supply_chain.py:966-1093`; lookback gate 1046, decay 1050. `vendor_breaches.json` 14 rows. Renderer `results.html:2199-2233` / `pdf_report.py:2666`. WEIGHTS 0.04 (504), uplift +0.04/+0.02 on critical/high match (2075-2083), REMEDIATION (3389). Wired once.
- **Verdict:** GAP
- **Severity:** medium
- **Finding:** Checker logic is sound and correctly age-decays, but two issues degrade it: (a) inherited S-4 classification gap suppresses a real HIGH-severity Mailchimp match on takealot; (b) DB carries dead, never-matching rows (sendgrid/constant_contact) — quiet drift, no editorial expiry process.
- **Solution(s):** (1) Fix the S-4 patterns (above) — primary lever. (2) Add a maintenance assertion (a tiny test in `tooling/`) that fails when any `vendor_breaches.json` row is older than `LOOKBACK_DAYS`, forcing editorial refresh; or add a fresher MOVEit/Snowflake-class 2023-24 row to keep the DB current. (3) Free, no scoring change.

## Third-Party Cross-Correlation (HR × S-4 × S-5)
- **Source/provider:** `scanner.py:build` inline block (924-1051) — joins Hudson Rock `third_party_exposures` × S-4 SPF vendor set × S-5 matched breaches. Reporting-only by design.
- **Ground-truth:** takealot: `hr_third_party=59, spf_vendors=2, suspected=[zendesk], severity="critical", score=0`. Join logic verified correct (intersection of SPF-vendor set ∩ breach-matched vendors). Key-read confirmed: builder reads `hr.get("third_party_exposures")` (line 938) which matches the HR card key (`third_party_exposures=59`) — no key mismatch. phishield: single-signal `medium` (HR=1, no SPF) — also correct.
- **Code trace:** `scanner.py:924-1051`; severity set at 990 (`critical` for ANY suspected vendor). Renderer `results.html:1829-1869` / `pdf_report.py:cat_third_party_correlation` 2572. **Confirmed genuinely NOT in WEIGHTS / RSI / FIC-uplift / REMEDIATION** — excluded at all four scoring surfaces (scoring_analytics.py:505, 742, 1092, 2084, 3391). No double-count.
- **Verdict:** BUG
- **Severity:** medium
- **Finding:** Two issues. (a) **Severity over-escalation**: severity is hard-set to `critical` whenever any overlap exists, *regardless of the underlying breach severity*. takealot's only overlap is zendesk's **medium** breach (disclosure: "no customer ticket data exfiltrated"), yet the card renders CRITICAL / "treat as already compromised / rotate TODAY." For a UW deliverable this over-states a benign-class incident. (b) **Stale docstring**: scanner.py:921 claims the output "drives RSI... FIC vuln uplift" — the code does NOT (correctly reporting-only); the comment contradicts the implementation and could mislead a future maintainer into "fixing" it by wiring it in (which would double-count).
- **Solution(s):** (1) Make correlation severity a function of the max underlying breach severity (critical→critical, high→high, medium→medium/high) rather than presence-only; keep it reporting-only. (2) Fix the scanner.py:921 comment to match the four other accurate "reporting-only" notes. (3) Note: fixing the S-4 Mandrill gap would correctly upgrade takealot to a genuinely high/critical overlap (Mailchimp HIGH) — making the escalation defensible on the merits rather than on a medium-only signal.

## Cluster summary
cards=5, BUG=2 GAP=2 PASS=1 NEEDS-LIVE=0; headline = one S-4 pattern gap (Mandrill→mailchimp / transmail→zoho misclassified as "unknown") cascades through S-5 and the cross-correlation, suppressing a real HIGH-severity Mailchimp breach on takealot while the correlation simultaneously over-escalates a medium zendesk signal to CRITICAL. Scoring wiring itself is clean: each S-1/2/4/5 contributes exactly once, the supply-chain vulnerability uplift is applied once, and the cross-correlation is genuinely excluded from WEIGHTS/RSI/FIC/REMEDIATION (no double-count).


---

# Insurance Analytics & Financial — Card Back-Test Findings

Method: credit-free recompute from cached `test_fixtures/phishield_live.json`
(phishield.com, Financial Services, overall_risk_score=381) and
`charming-ishizaka-3b0bf1/.../takealot_live2.json` (overall_risk_score=245).
By-hand formula reconciliation + code trace `scoring_analytics.py` →
`templates/results.html` / `pdf_report.py`. No live scans.

---

## (1) RSI — Ransomware Susceptibility Index
- **Source/provider:** `RansomwareIndex.calculate()` scoring_analytics.py:993; reads `categories` (vpn_remote, high_risk_protocols, credential_risk, shodan_vulns, info_disclosure, email_security, waf, ssl, supply-chain S-*). Output `insurance.rsi`.
- **Ground-truth:** base 0.05 + factors [cred HIGH 0.15, 1 db port 0.10, 4 high-EPSS 0.12, 11 crit/high CVE 0.08, SSL D 0.05, CMS 25 plugins 0.02] = **0.57** (== fixture `base_score`). Diminishing (>0.5): 0.5+0.5(1−e^(−2·0.07)) = 0.5653. ×1.15 (FS industry) ×1.12 (micro size) = **0.728** == fixture `rsi_score`. **Reconciles exactly.** Label "High" correct (0.50–0.75). Caps verified: db ports min(0.20), KEV min(0.20), EPSS min(0.12), supply-chain SUPPLY_CHAIN_CAP 0.22, rsi min(1.0).
- **Code trace:** calc scoring_analytics.py:1280 → PDF `cat_rsi` pdf_report.py:2732 (reads `risk_label`/`base_score`/`industry_multiplier`/`size_multiplier`/`contributing_factors` — all correct) → HTML results.html RSI block.
- **Verdict:** PASS
- **Severity:** n/a
- **Finding:** RSI math, caps, diminishing-returns, multipliers and live renderer all reconcile. Two DEAD-GHOST functions `cat_ransomware_risk` (pdf_report.py:2839) read stale key `rsi_label` + nonexistent `categories.ransomware_risk` shape — never called, but would mis-render if wired. (See DBI note.)
- **Solution(s):** No fix needed for the live card. Optionally delete the unused `cat_ransomware_risk` ghost to prevent future mis-wiring. Industry/size multiplier magnitudes → defer to FIN-9.

## (2) DBI — Data Breach Index
- **Source/provider:** `DataBreachIndex.calculate()` scoring_analytics.py:3218; reads `breaches` + `dehashed`. Output `insurance.dbi`.
- **Ground-truth:** 5 components: breach_count 0→30, recency "No breaches"→20, data_severity "No data"→15, credential_leaks 13 (≤100 band)→10, trend "Improving"→15. Sum = **90** == fixture `dbi_score`; label "Excellent" (≥80) correct. Components dict points/max all reconcile.
- **Code trace:** calc scoring_analytics.py:3309 → PDF `cat_dbi` pdf_report.py:2780 (reads `dbi_score`/`label`/`components` correctly) → HTML DBI block.
- **Verdict:** BUG (ghost renderer only) / card itself PASS
- **Severity:** low
- **Finding:** Live DBI card reconciles perfectly. The unused `cat_data_breach_index` (pdf_report.py:2858) reads a flat legacy shape (`dbi_label`, `breach_count`, `most_recent_breach`, `has_sensitive_data`, `credential_leaks`) that the real dict never produces (it nests these in `components`, and uses `label`). It is never called (grep confirms only `cat_dbi` is wired at pdf_report.py:6354) → harmless dead code, but a latent mis-render trap.
- **Solution(s):** Delete dead `cat_data_breach_index` + `cat_ransomware_risk` ghosts, or add a one-line "UNUSED — see cat_dbi/cat_rsi" comment. Free.

## (3) Financial Impact Analysis (annual loss + Monte Carlo)
- **Source/provider:** `FinancialImpactCalculator._calculate_zar()` scoring_analytics.py:1987; ZAR path (annual_revenue_zar>0). Output `insurance.financial_impact`.
- **Ground-truth:** `total.most_likely` = `estimated_annual_loss.most_likely` = Σ incident `expected_loss` = **3,538,971** (all three reconcile; scenarios_4cat sum 3,538,970 = trivial −1 rounding). p_breach = vulnerability×TEF×0.3 = 0.5×1.45×0.3 = **0.2175** == fixture. MC P50=5,186,391, mean=5,897,366, ordered P5<P25<P50<P75<P95<P99. Deductible 7.84%→7.8% at RSI 0.728, R392,000 on R5M cover — reconciles.
- **Code trace:** scanner.py:1155 `fin_calc.calculate(...)` → `_calculate_zar` → HTML ZAR branch results.html:619-745; PDF `cat_financial_impact` pdf_report.py:2876.
- **Verdict:** BUG (wiring)
- **Severity:** high
- **Finding:** **`vulnerability` is pinned at 0.5 in production.** `_calculate_zar` computes `vulnerability=(100−_overall_score/10)/100` reading `categories.get("_overall_score", 500)` (line 2029), but **scanner.py never writes `cat_results["_overall_score"]`** before calling `fin_calc.calculate()` (Phase 6, lines 1142-1162) — so it always defaults to 500 → vulnerability 0.5 regardless of the actual scan. Proven: phishield overall=381 should give 0.619 (p_breach 0.269) but fixture shows 0.5/0.2175; takealot overall=245 should give 0.755 (p_breach 0.283) but shows 0.5/0.1875. Confirmed by live test: injecting `_overall_score=245` yields vulnerability 0.755. `regen_outputs_from_cache.py:98` and `verify_supply_chain_financial_wiring.py:186` DO inject it → the test harness masks the production bug. Net effect: p_breach, all six incident probabilities, expected losses and MC tails are decoupled from posture — a clean site and a critical site price identically on the breach axis.
- **Solution(s):** (a) One-line fix in scanner.py Phase 6: `cat_results["_overall_score"] = risk_score` immediately after line 1080, before the insurance block — mirrors the regen/verifier path. Free. (b) Add a guard/assert in `_calculate_zar` (or the smoke verifier) that flags when `_overall_score` is absent so this can't silently regress. Magnitude/curve of the vulnerability→p_breach mapping → defer to FIN-9 (the p(breach) refinement session), but the wiring itself is a correctness bug to fix now.

## (4) Loss Exposure / Return Periods (1-in-100 / 200 / 250)
- **Source/provider:** `_mc_percentiles` + `_gpd_tail_quantile` scoring_analytics.py:1545/1478; `return_periods` + `loss_exposure.scenarios` dicts. GPD Peaks-Over-Threshold tail fit above P95.
- **Ground-truth:** P99=14,690,559 (1-in-100) < P99.5=15,875,688 (1-in-200) < P99.6=16,238,125 (1-in-250) — **strictly ordered**, and all > P50 5.19M. Percentile→return-period labels correct: P99→1-in-100 (exceed 0.01), P99.5→1-in-200 (0.005), P99.6→1-in-250 (0.004). `loss_exposure.scenarios` mode 3.18M / median 5.19M / 3 return rows all match `return_periods` and `monte_carlo.total`. GPD fit: `p99_fit_applied=false` here (raw≈fitted within 1%), p99_5_raw 15.80M vs fitted 15.88M consistent.
- **Code trace:** dict scoring_analytics.py:2993/3001 → HTML loss_exposure table results.html:695-709 (schema-driven loop, P99 row amber, P99.5/.6 red) + MC kv-table results.html:897-899 → PDF `loss_exposure_scenarios_block` pdf_report.py:3005.
- **Verdict:** PASS
- **Severity:** n/a
- **Finding:** Return-period ordering, percentile-to-label mapping, currency formatting (R, no trailing .00, thousands separators) and reconciliation across `return_periods`/`loss_exposure`/`monte_carlo` all correct in both renderers. Note: these inherit the (3) vulnerability=0.5 understatement, so absolute magnitudes are biased low — but the card's own wiring/ordering is sound.
- **Solution(s):** None for ordering/render. Magnitudes correct themselves once (3) is fixed; tail-widening calibration → defer to FIN-9.

## (5) Peer Benchmarking
- **Source/provider:** `compute_peer_rating()` peer_benchmarking.py:267; SQLite `benchmark_scans` pool, percentile rank of inverted risk score → 1.0-10.0. Output `insurance.peer_benchmarking`.
- **Ground-truth:** Fixture status `insufficient_data`, n_peers=0 (pool empty pre-launch) — correct fallback. `own_risk_score=381`, `own_critical_findings=22`, `revenue_band="micro"`. Rating formula `1.0 + 9.0·(pct/100)` and `_percentile_of` (tie-safe average of below / at-or-below) are correct by inspection; cannot exercise the `status="ok"` branch without a populated pool.
- **Code trace:** peer_benchmarking.py:327 → PDF `peer_benchmark_card` pdf_report.py:3237 (omits section entirely when status!="ok" → no broken placeholder in client PDF) → HTML shows the evidence note.
- **Verdict:** NEEDS-LIVE (+ minor GAP)
- **Severity:** low
- **Finding:** Logic sound; cannot validate the populated path offline (pool=0). One real inconsistency: peer uses `scan_context.annual_revenue_zar` (0 → band "micro"), while Financial Impact defaults missing revenue to R10M (scanner.py:1152). For the SAME scan, peer says "micro (<R10M)" while FIC models R10M — the revenue basis is not unified across the two cards.
- **Solution(s):** (a) Unify the revenue default: apply the same R10M fallback (or carry a single resolved `annual_revenue_zar`) to peer-band selection so the two cards agree. Free. (b) Re-verify the `status="ok"` branch once the benchmark pool reaches N≥5 (SCN-028 rollout). Rating-curve calibration → defer to FIN-9 if raised.

## (6) Remediation Roadmap (before/after savings)
- **Source/provider:** TWO models — `RemediationSimulator.calculate()` scoring_analytics.py:3415 (`insurance.remediation`, RSI-reduction based) AND `FinancialImpactCalculator._build_mitigations()` scoring_analytics.py:3087 (`financial_impact.risk_mitigations`, incident-driven).
- **Ground-truth:** RemediationSimulator: 14 steps, Σ rsi_reduction = **0.59** (unbounded sum), simulated_rsi = max(0, 0.728−0.59) = **0.138**, sim/cur loss ratio 0.19, savings **R2,007,688** (sum reconciles). `_build_mitigations`: savings **R2,700,586**, capped at 85% of current loss, summary critical/high/medium reconciles. Both internally consistent — but they disagree by ~R0.69M for the same scan.
- **Code trace:** RemediationSimulator → PDF `cat_remediation` pdf_report.py:2806 (line 6370) + HTML results.html:986. `_build_mitigations` → PDF `cat_risk_mitigations` pdf_report.py:3627 (line 6369) + HTML results.html:913. **Both render consecutively** in the PDF (lines 6369-6370) and both in HTML.
- **Verdict:** BUG (reconciliation / unbounded cap)
- **Severity:** medium
- **Finding:** (a) Two adjacent "before/after savings" cards show different totals (R2.01M vs R2.70M) and different methodologies for one scan — a broker-visible inconsistency. (b) RemediationSimulator's `rsi_improvement` is a raw arithmetic sum of 14 independent `rsi_reduction` values (0.59) subtracted from RSI, then scaled linearly into financial savings — RSI's forward model uses diminishing returns + caps, so additive subtraction overstates achievable improvement (here implies an 81% loss cut). `_build_mitigations` caps at 85%; RemediationSimulator has no analogous cap on cumulative RSI reduction.
- **Solution(s):** (a) Pick ONE remediation model as broker-facing (the incident-driven `risk_mitigations` is the more defensible, IBM-anchored one) and demote/remove the duplicate card, or explicitly relabel them as "potential RSI-point reduction" vs "expected-loss reduction" so they're not read as competing savings. (b) Cap cumulative `rsi_improvement` (e.g. clamp simulated_rsi to a floor like the 0.05 inherent baseline, or re-run RSI through `_diminishing` on the reduced base) so savings can't exceed a realistic ceiling. Exact reduction magnitudes → defer to FIN-9.

---

## Cluster summary
cards=6, BUG=3 (incl 2 dead-ghost renderers folded into RSI/DBI), GAP=0, PASS=2, NEEDS-LIVE=1, DEFER-FIN9=0 (calibration flagged within cards).
headline = **Financial Impact `vulnerability` is pinned at 0.5 in production** — `scanner.py` Phase 6 never injects `cat_results["_overall_score"]` before the FIC call, so p_breach, incident probabilities, expected loss and MC return-period tails are decoupled from the actual scan posture; the test/regen harnesses inject it and mask the bug. One-line fix (`cat_results["_overall_score"] = risk_score` after scanner.py:1080). RSI, DBI, return-period ordering and deductible math all reconcile exactly; secondary issues are duplicate/divergent remediation cards and unbounded RSI-reduction summing.
