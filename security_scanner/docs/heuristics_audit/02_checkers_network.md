# checkers_network.py — Heuristics Audit

White-box Step-6 heuristics sweep of `checkers_network.py` (6 classes:
`SubdomainChecker`, `VPNRemoteAccessChecker`, `DNSInfrastructureChecker`,
`HighRiskProtocolChecker`, `SecurityPolicyChecker`, `DNSBLChecker`).
RESEARCH ONLY — no code changed. Failure-mode screen per
`docs/card_verification_protocol.md` Step 6.

**Scope note.** Shodan/InternetDB and origin-discovery checkers do NOT live in
this module (they are in `checkers_threats.py` / `origin_discovery.py`) — out of
scope here. Waves 1-5 fixes confirmed present and clean in this file:
DNSBL return-code validation (`_is_genuine_listing`), RDS/VPN `require_200` +
genuine-marker tokens, subdomain wildcard guard + crt.sh `%25` primary with
`ct_source_ok`. The remaining audit targets the *unhardened* heuristics:
per-port score deltas, the high-risk port taxonomy, the brute wordlist, caps,
timeouts, and the curated CVE/EOL-flavoured intel tables.

**Calibration boundary.** Per-checker `score`/`risk_score`/`*N` deltas that feed
`scoring_analytics.RiskScorer` are calibration-gated and flagged for FIN-9 — I do
NOT propose numeric replacements for them. Where a heuristic is a *correctness
gate* (substring match, status-code rule, fallback, curated list) I propose a
free robust fix (bucket 1/2).

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| `BRUTE_PREFIXES` (48 prefixes) | Subdomain L14-22 | DNS-brute candidate list supplementing crt.sh | No fabrication (each is a real resolve); generic/error N/A (positive resolve required). Coverage curated, not exhaustive | justified | Document: supplemental only (crt.sh is primary); reasonable infra-name list. Optional: note last-reviewed date so it doesn't silently rot |
| `RISKY_KEYWORDS` (25 substrings, `any(k in s)`) | Subdomain L24-29, L296 | Flags subdomains whose name contains a risky token | **Loose substring** — `k in s` over full FQDN matches the apex too (`api.takealot.com` flagged by `api`; `olddomain.com` → `old`; a brand literally containing `db`/`test`). False positives on benign hosts. Substring not label-boundary | fragile | Bucket-2: match on dotted **labels** (`set(host.split("."))`), not raw substring; and exclude the apex/`www`. Stops phantom "risky subdomain" counts feeding `sub_risk` |
| `TAKEOVER_SIGNATURES` (28 services, CNAME→fingerprint) | Subdomain L32-62 | CNAME-target pattern → dangling-service body fingerprint | Curated table can go **stale** (services rename/retire fingerprint pages); ~12 entries have `fingerprint=None` → dangling decided on NXDOMAIN only (sound). Pattern is `in cname_target` substring (acceptable for vendor domains) | fragile | Bucket-2: add a `last_verified` date + a periodic fingerprint-drift test (mirror the vendor-DB drift test from Wave 5). None-fingerprint entries are conservative — keep |
| Takeover via HTTP GET body `fingerprint in r.text` (`verify=False`) | Subdomain L106-124 | Confirms dangling by matching vendor 404 string in body | Generic-response risk is LOW (requires specific vendor string), but `verify=False` + `allow_redirects=True` could match a redirected catch-all page that echoes the string. Sound enough | justified | Document: relies on vendor-specific strings, not a generic 200/403; matches S-3 `_probe` spirit |
| Takeover `score -= 15` per vuln (`max(0, …)`) | Subdomain L293 | Subtracts 15 from local 0-100 score per takeover | **Calibration magic-number** feeding the card score | calibration-gated | FLAG for FIN-9 — do not intuit. (Note: this local `score` is largely informational; `subdomains` weight in scorer is driven by `risky_subdomains` count, not this score) |
| Risky-subdomain `score = max(40, 100 - n*5)` | Subdomain L303 | Per-risky-sub score delta with 40 floor | Calibration magic-numbers (5, 40 floor) | calibration-gated | FLAG for FIN-9 |
| Large-surface threshold `len > 50` → `score = min(score, 60)` | Subdomain L305-310 | "Large attack surface" if >50 subdomains | Threshold 50 + cap 60 are arbitrary; benign for big orgs (takealot easily >50) → could over-penalise large legit estates | calibration-gated | FLAG for FIN-9 (threshold + cap). Document that absolute count, not normalised, may bias against large orgs |
| Cap `subdomains[:150]` | Subdomain L227 | Caps stored subdomain list at 150 | No fabrication; bounds memory/time. Could truncate very large estates (>150) silently | justified | Document rationale (perf bound; aligns with takeover cap). Optional: record `truncated=True` when hit |
| `resolved_ips` cap `[:80]` | Subdomain L235 | Resolves only first 80 subs to IPs | `unique_ips_found` then under-counts on big estates (boolean-ish undercount, not fabrication) | fragile | Bucket-2: note in output that IP-resolution is sampled at 80 so `unique_ips_found` isn't read as a complete count |
| Takeover probe cap `[:150]` + `as_completed(timeout=90)`, `max_workers=10`, per-future `result(timeout=5)` | Subdomain L277-279 | Coverage budget for takeover probing | Well-documented (L253-275 audit note). Timeout-driven partial coverage means some subs unchecked → **under-detection, not fabrication** (safe-direction) | justified | Document already strong. Keep; note that misses are false-negatives (acceptable for non-intrusive posture) |
| `_wildcard_ips`: 2 random labels, `secrets.token_hex(8)` | Subdomain L73-83 | Wildcard-DNS guard (Wave-3 fix) | Correctly prevents fabrication of phantom brute hits. 2 samples is low but adequate (random 16-hex collision ~nil) | justified | Clean (Wave 3). Document: 2-sample is sufficient given entropy |
| `ThreadPoolExecutor(max_workers=20)` (brute + resolve) | Subdomain L210,234; DNS L624; HRP L878 | Concurrency for socket probes | Not a signal; perf only. 20 parallel TCP connects is mildly aggressive but bounded | justified | Document: respects non-intrusive posture (passive TCP connect, no payload flood) |
| `VPN_SIGNATURES` paths + `body_keywords` (8 vendors) | VPN L320-361 | Probes known VPN login paths, matches body tokens | RDS entry hardened (`require_200` + genuine markers, Wave 2). Others match on **specific vendor tokens** (`anyconnect`,`fortigate`) — low generic-response risk, but no `require_200` on the other 7 → a soft-404/redirect page echoing e.g. "citrix" could false-positive | fragile | Bucket-2: extend `require_200` (or S-3 `_probe` 200+body-sanity) to all 8 signatures, not just RDS. Vendor tokens are specific enough that risk is modest, but apply the gate uniformly |
| OpenVPN signature path `"/"` + tokens `openvpn access server` | VPN L353-355 | Detects OpenVPN-AS on root path | Root-path probe + generic token; `openvpn access server` is specific so low risk, but probing `/` means any homepage mentioning the product matches | fragile | Bucket-2: same `require_200` + ensure token appears in a login-form context, not marketing copy |
| RDP check: `connect_ex((domain,3389)) == 0`, `settimeout(3)` | VPN L375-382 | Flags RDP exposed if 3389 open | `connect_ex==0` is a true open-port signal (sound). Connects to `domain` (apex A) not per-resolved IP — single-IP attribution; behind CDN this is the edge IP not origin (false-negative, safe). Timeout 3s arbitrary but fine | justified | Document: open-port is genuine; note apex-only attribution (origin RDP behind CDN won't show — safe-direction miss) |
| `vpn_risk = 40 if rdp else (20 if not vpn_detected else 0)` | scoring L660 | Maps VPN result to risk; **"no VPN detected" → +20** | **Possible inversion/over-penalty**: absence of a *detected* gateway is treated as a 20-pt risk, but many orgs use ZTNA/cloud VPN (no on-prem login page) — penalises modern, well-defended orgs. Boolean (`vpn_detected`) drives score, which is correct, but the "unknown = risk" mapping is questionable | calibration-gated | FLAG for FIN-9 (the 40/20/0). Also flag the *semantics*: "no on-prem VPN page" ≠ "insecure remote access" — consider neutral, not +20 |
| `HIGH_RISK_PORTS` {21,23,3306,3389,5900}; `MEDIUM` {22,25,110,143}; `INFO` {80,443,993,995,8080,8443} | DNS L420-422 | Port → risk-tier taxonomy | Taxonomy curated. 5432(Postgres) & 1433(MSSQL) absent here but covered in HRP `CRITICAL_SERVICES` (no double-count: different checker). 22(SSH) as medium is defensible. No fabrication | justified | Document: tiering matches insurer convention (cleartext/DB/remote-admin = high). Cross-ref HRP so 5432/1433 aren't expected here |
| Port score deltas: high `+40`, medium `+15`, zone-transfer `+50`, `min(score,150)` | DNS L711,716,721,728 | Per-open-port risk accumulation | Calibration magic-numbers (40/15/50/150 cap) | calibration-gated | FLAG for FIN-9 |
| `PORT_INTEL` curated table (CVEs, CVSS, EPSS, KEV per port) | DNS L426-504 | Enriches port findings with exploit/CVSS/EPSS/KEV strings | **Stale-table risk**: hardcoded CVSS/EPSS/"CISA KEV" labels and CVE lists go out of date; EPSS especially is time-varying. Used as narrative enrichment, not score input (score is from tier, not these) → display-only staleness, not a scoring defect | fragile | Bucket-2: add a generated-on date + caveat that CVSS/EPSS are point-in-time; or source EPSS live. Not load-bearing for score, so low urgency |
| `BANNER_PROBES` (9 ports, raw bytes) + `_extract_version` regexes | DNS L582-592, L649-681 | Grabs service banner, regex-extracts version | Banner is real evidence (sound). Regexes are best-effort; a missed parse → empty version (no fabrication). `HEAD /` probe is non-intrusive | justified | Document: passive banner read, fail-open to empty (no fabricated version). Clean |
| Banner cap `[:200]`, `recv(1024)`, `settimeout(2)` | DNS L612,643-644 | Bounds banner capture | Pure bounds; no signal | justified | Document |
| Zone transfer: `ns_servers[:4]`, `lifetime=5`, `record_count>0`→vulnerable | DNS L552-563 | AXFR against ≤4 NS; any records = critical | `from_xfr` succeeding with `nodes>0` is genuine disclosure (sound, not generic-response). `[:4]` may skip later NS (under-test, safe) | justified | Document: refused/timeout correctly swallowed; success is true-positive. Note `[:4]` cap is a coverage choice (false-neg safe) |
| `_check_dnssec`: `bool(resolve(domain,"DNSKEY"))` | DNS L529-536 | DNSKEY presence ⇒ DNSSEC enabled | Presence of DNSKEY is a real signal; absence → False (no fabrication). Doesn't validate DS chain (documented) | justified | Clean. Document: apex DNSKEY only, not full chain-of-trust (stated in code) |
| Port-scan `settimeout(3)`, `as_completed(timeout=30)` | DNS L605,626; HRP L863,880 | TCP-connect timeouts | Bounds; non-signal. 3s connect is standard | justified | Document |
| `CRITICAL_SERVICES` (16 DB/admin ports) | HRP L736-754 | DB/service exposure port set | Curated; each is a genuine high-risk service. `connect_ex==0` = real open port (sound, no generic-response) | justified | Document: passive connect, port-open is ground truth. Reasonable DB/admin coverage |
| `SERVICE_INTEL` curated CVE/EPSS/KEV table (16 entries) | HRP L756-842 | Narrative enrichment per critical service | **Stale-table risk** same as `PORT_INTEL` (hardcoded CVSS/EPSS/KEV strings). Display-only; `critical_count` (not these) drives `hrisk` score | fragile | Bucket-2: date-stamp + point-in-time caveat for CVSS/EPSS; not score-load-bearing |
| `critical_count` → `hrisk = min(100, n*35)` | scoring L639-640 | Each exposed DB/service ⇒ +35 risk | **Count is genuine** (real open ports). 35 multiplier + 100 cap are calibration | calibration-gated | FLAG for FIN-9 (the 35) |
| `dnsbl_risk = min(100, listed*50)` | scoring L645 | Each blacklist listing ⇒ +50 | Count uses validated `_is_genuine_listing` (Wave-1 clean) → no false-positive inflation. 50 multiplier is calibration | calibration-gated | FLAG for FIN-9 (the 50). Listing count itself is sound |
| `_is_genuine_listing` return-code ranges (127.0.0.2-255; 127.0.1.2-99; reject 127.255.255.x & 127.0.0.1) | DNSBL L963-1005 | Validates DNSBL reply codes per spec | **Wave-1 fix — directly addresses the generic/error-response failure mode.** Correctly rejects open-resolver/refused codes. Per-list nuance folded into generic ranges (slight over-generalisation across 5 lists but conservative) | justified | Clean. Optional doc: SORBS/UCEPROTECT/Barracuda use 127.0.0.x so the generic range is correct for them; Spamhaus zen multi-code handled |
| `IP_DNSBLS` (5 lists) / `DOMAIN_DNSBLS` (2 lists) + `lifetime=5` | DNSBL L951-961 | Curated DNSBL providers | Curated; lists can deprecate (UCEPROTECT/SORBS reliability varies; SORBS shut down 2024 — **potential stale entry**) | fragile | Bucket-2: verify `dnsbl.sorbs.net` still resolves (SORBS ceased operation mid-2024); drop dead lists so a NXDOMAIN'd provider can't skew availability. Quick free check |
| security.txt: `status==200 and "Contact:" in r.text` | SecPolicy L920-925 | Detects VDP via security.txt | Requires 200 **and** literal `Contact:` — robust (S-3-style); a soft-404/SPA won't false-positive. `has_pgp` substring on `Encryption:`/PGP header is fine | justified | Clean. Good pattern — 200+content-sanity. Document as reference-correct |
| robots.txt `disallows_count = text.count("disallow:")` | SecPolicy L937-939 | Counts Disallow lines | Counts on any 200 body without sanity-check — a soft-404 HTML page containing the word would mis-count; but `disallows_count` is **informational only** (not scored) | fragile | Bucket-2: gate on `content-type: text/plain` or a `User-agent:` line present before counting, to avoid counting an HTML catch-all. Low urgency (unscored) |
| `vpn_detected` body slice `r.text[:3000].lower()` | VPN L399 | Limits body scanned for tokens | Bound; could miss tokens past 3000 chars (under-detection, safe) | justified | Document |

## Summary
total=33 justified=15 fragile=11 arbitrary=0 calibration-gated=7; top 3 concerns.

**Top 3 concerns**

1. **`RISKY_KEYWORDS` loose-substring match (fragile, free fix).** `any(k in s)`
   over the full FQDN flags benign hosts — `api.`, `db`-containing brands, the
   apex/`www` itself — inflating `risky_subdomains`, which *directly* drives
   `sub_risk` (`*15`) in the scorer. This is the back-test's "loose substring"
   failure mode and the only fragile item that feeds a real score. **Fix:**
   label-boundary match (`set(host.split("."))`) + exclude apex/www.

2. **VPN signatures lack a uniform `require_200`/body-sanity gate (fragile).**
   Only the RDS signature was hardened in Wave 2; the other 7 vendors still
   match a vendor token in any response (incl. soft-404/redirect/marketing
   copy). **Fix:** apply the S-3 `_probe` 200-only + body-sanity pattern to all
   8 signatures. Related: the `vpn_risk` "no VPN page detected = +20" mapping
   risks **inverting** against ZTNA/cloud-VPN orgs — flag the *semantics* to
   FIN-9, not just the number.

3. **Stale curated tables (fragile).** `PORT_INTEL`/`SERVICE_INTEL` hardcode
   point-in-time CVSS/EPSS/"CISA KEV" strings (display-only, low urgency), and
   `dnsbl.sorbs.net` may be a **dead list** (SORBS ceased operation mid-2024) —
   verify and drop. `TAKEOVER_SIGNATURES` should carry a `last_verified` date +
   drift test (mirror Wave-5 vendor-DB drift test). None are score-load-bearing
   except via listing-count, which is itself validated.

**Calibration-gated (FIN-9, not intuited):** takeover `-15`/sub `100-n*5`+40
floor / large-surface `>50`→`60` (Subdomain local score); port `+40/+15`,
zone-xfer `+50`, `min(,150)` (DNS); `hrisk n*35`; `dnsbl listed*50`; `vpn_risk
40/20/0`. The underlying **counts** behind every flagged delta are sound
(real open ports, validated listings) — only the multipliers/thresholds need
calibration.
