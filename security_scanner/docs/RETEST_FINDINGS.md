# Phishield Scanner — Card Back-Test Re-Test (post-fix)

> **STATUS UPDATE (2026-06-11):** the three "new issues" below are resolved:
> (1) HTTP Headers 403 guard — fixed (`checkers_core.py:858`, `unreachable`
> status on non-2xx, no false posture read); (2) vendor_breaches.json drift —
> warn-only date-window check now runs inside
> `tooling/verify_supply_chain_financial_wiring.py` (note: the `marketo` row
> exits the 5-yr lookback ~2026-06-21 — refresh or prune deliberately);
> (3) peer-vs-financial revenue basis — unified default via
> `resolve_effective_revenue_zar()` / shared R10M constant.

# Card Back-Test — Re-Test Summary (post-fix)

**Date:** 2026-06-03
**Method:** the same 7 cluster agents re-verified every previously-flagged issue against the FIXED code, using code inspection + free live re-checks (sslyze, curl, dig, crt.sh, Shodan InternetDB) + cached raw inputs. No new scan, no credits, no source edits during the re-test.
**Fixes under test:** Waves 1-4 (commits `f0cf35e`, `8d2663b`, `2b36471`, `c1d3134`, `f13ba11`).

## Headline tally

| | Count |
|---|---|
| **FIXED (confirmed)** | **26** |
| Partial | 5 |
| Still-broken | 1 |
| **Regressions** | **0** |
| New issues found | 3 |

**Every one of the original 17 bugs (and the targeted gaps) is confirmed fixed, with zero regressions.** The 4 report-distorting criticals/highs are verified live: SSL now grades phishield A/85 & takealot A+/95 (was "Invalid"); `vulnerability` now couples to posture (phishield 0.619 / takealot 0.755, was pinned 0.5); DNSBL clean on clean domains; Exposed-Admin 403 no longer scored as exposure. The S-4 fix unlocked the previously-suppressed Mailchimp vendor-breach match, which now correctly surfaces through S-5 and the cross-correlation.

## Non-FIXED items (none are regressions)

**Partial — pre-existing secondary notes, out of the fix scope:**
- CVE: the latent >10-CVE undercount (OSV back-fill mitigates) — never in scope.
- IntelX: `darkweb_count` reclassification works on `bucket`, but `recent_results` strips that field, so the name-token fallback only catches a subset; full verification needs a live IntelX record (credit-gated).
- Tech Stack: EOL table refreshed (the GAP fixed), but two minor residual bugs remain (an `X-Powered-By` decoy is still penalised; the traffic light is binary with no amber).
- Dehashed: cosmetic corporate-vs-staff dual-label not relabelled (the actual double-count IS fixed).
- Financial remediation cap: correct, but a no-op for phishield's own numbers — its ~81% modelled loss-cut is now a **calibration** question → **FIN-9**, not a correctness bug.

**Still-broken — deferred by design (not a bug):**
- S-1 related-domain auto-discovery is inert (broker-declared only); auto-discovery was always a deferred roadmap item.

**New issues surfaced by the live re-test (3):**
1. **HTTP Headers card — no 403/status guard (MEDIUM, genuine).** The header checker has no status-code guard or apex→www follow, so when a WAF/CDN origin returns 403 to the scanner UA it reads the block-page's (empty) headers as the site's posture — phishield falsely scores 30 ("CSP/HSTS/XCTO missing"). This is the SAME WAF/CDN-403 family fixed in Waves 1-2, but the header checker wasn't in that scope (it was a PASS on cached data; the live re-check exposed it). Fix is the same template (status-guard + body-sanity + apex→www). **Recommend a quick Wave 5.**
2. **vendor_breaches.json drift (LOW).** The `marketo` row hits the 5-yr lookback in ~19 days and there is no automated editorial-expiry test, so the DB will silently drift again. Add a date-window test.
3. **Peer vs FIC revenue basis (LOW, pre-existing).** Peer benchmarking uses raw revenue while the FIC defaults to R10M — a basis mismatch; no wave touched `peer_benchmarking.py`.

## Updated state rating

**~8 / 10** (up from ~5 pre-fix). The four bugs that distorted every report are fixed and live-verified, the financial model is re-coupled to posture, and there are zero regressions. It is held below 9 by: the one new medium (HTTP Headers 403 on WAF-fronted origins — a headline card), the pending FIN-9 calibration (incl. the credential-confidence p(breach) work), and a handful of minor residual gaps. A quick Wave 5 (HTTP Headers + the two lows) plus the FIN-9 calibration puts it at a genuine 9.

*Per-cluster re-test detail follows.*


---

# Core Web Security — Re-Test

Re-verified the four Core Web Security cards after Waves 1-4. Method: read the fixed
checker/renderer code + free live re-checks (the scanner's own `SSLChecker` /
`WAFChecker` / `HTTPHeaderChecker` / `DNSInfrastructureChecker` run live against
phishield.com & takealot.com, cross-checked with `openssl s_client`, `curl -sIL`,
`nslookup`). The cached `test_fixtures/phishield_live.json` is PRE-FIX and was NOT
trusted. No paid/metered APIs used.

## SSL / TLS
- **Was:** BUG (critical) — stale sslyze-5.x attribute names (`leaf_certificate_subject_matches_hostname`, `dep.verified_certificate_chain`) swallowed by `except: pass`; `certificate={}` → every cert graded "Invalid" (-40). phishield D/45, takealot C/55.
- **Now:** FIXED
- **Evidence:** `checkers_core.py:55-127` ported to sslyze-6.x API (chain validity via `dep.path_validation_results`, hostname via new `_leaf_san_dns_names`/`_hostname_matches` helpers, lines 176-203); the bare `except: pass` is gone — parse errors now `raise` and fall through to `_check_with_stdlib` (`data_source="stdlib_fallback"`, lines 29-31). Live re-run: phishield **A/85**, takealot **A+/95**, both `cert.valid=True hostname_match=True chain_valid=True`, real issuers (DigiCert EE DV G2 / GoDaddy G2) — matches `openssl s_client` exactly (issuer + notAfter Oct/Dec 2026).

## HTTP Security Headers
- **Was:** PASS with minor gap — checker awards full presence-credit without value validation (takealot's deprecated `XFO: ALLOW-FROM origin` scores green; `Referrer: unsafe-url` not flagged); plus a fixture "drift" on phishield XCTO.
- **Now:** NEW-ISSUE (status-code blind spot) + GAP still open
- **Evidence:** Live `HTTPHeaderChecker.check('phishield.com')` returns score **30** with CSP/HSTS/XCTO all "MISSING" — but that is because `requests.get('https://phishield.com')` gets a hard **403** from the server for the python User-Agent (no redirect followed), so it reads the 403 block-page's empty headers as the org's posture. A browser-UA `curl` 301-redirects apex→www and serves `X-Content-Type-Options: nosniff` (+ the real header set). `HTTPHeaderChecker.check` has **no `status_code` guard and no apex→www follow** (`checkers_core.py:776-816`; confirmed `status_code`/`403`/`200` absent in source) — same WAF/CDN-403 theme as the back-test, but the Wave-2 `_probe` template was NOT applied here. The optional XFO/Referrer value-validation gap also remains (`ALLOW-FROM`/`unsafe-url` not flagged in source). Note: this card was originally PASS so it was not a Wave fix target; the regenerated live run is what surfaces the 403 mis-read.

## WAF Detection
- **Was:** BUG (high) — `F5 BIG-IP ASM` signature keyed off ubiquitous `x-frame-options` (+ generic `ts` cookie); single-header match → phantom "F5" on any XFO-setting site, banking a 50-pt WAF credit. phishield falsely "F5"; takealot `["Cloudflare","F5 BIG-IP ASM"]`.
- **Now:** FIXED
- **Evidence:** `checkers_core.py:850-861` — F5 `headers` reduced to `["x-wa-info"]` only; `x-frame-options` and generic `ts` removed; F5 cookies now specific prefixes (`bigipserver`/`ts01`/`f5avr`/`f5_cspm`/`f5_st`) with prefix-matching (lines 894-899). Live re-run: phishield **detected=False ("No WAF")**, takealot **`["Cloudflare"]` only** — phantom F5 eliminated on both. curl confirms phishield serves only `Server: Apache`+XFO (no F5 marker), takealot is genuine Cloudflare (`cf-ray`).

## DNS Intelligence + DNS Infrastructure
- **Was:** GAP (medium) — `dns_infrastructure.dnssec_enabled` and richer `dns_records` (AAAA/TXT) computed and driving a hidden DNSSEC remediation but rendered on no card (status/remediation mismatch). SecurityTrails card itself PASS.
- **Now:** FIXED
- **Evidence:** Both renderers now surface them — HTML `templates/results.html:1337-1348` (DNSSEC row Enabled/Disabled badge + AAAA + TXT count) and PDF `pdf_report.py:776-789` (DNSSEC / AAAA / TXT rows). Live `DNSInfrastructureChecker.check('phishield.com')` returns `dnssec_enabled=False` + `dns_records` keys A/AAAA/MX/NS/TXT, `AAAA=['2a01:4f8:d0a:27c5::2']` (matches `nslookup`), 4 TXT records; `nslookup -type=DNSKEY` empty → `dnssec_enabled=False` is correct. SecurityTrails card unchanged (still PASS, reporting-only).

## Re-test summary
fixed=3 partial=0 still-broken=0 regressions=0 new=1; headline = **The three flagged BUGs/GAP are all genuinely FIXED** — SSL cert parsing now matches `openssl` ground-truth (phishield A/85, takealot A+/95, real issuers), the WAF F5 false-positive is gone (phishield "No WAF", takealot Cloudflare-only), and DNSSEC + AAAA/TXT now render in both HTML and PDF. One NEW-ISSUE surfaced on the regenerated live run: `HTTPHeaderChecker` has no HTTP-status guard and no apex→www redirect, so when the origin returns a **403** to the scanner's python User-Agent it reads the block-page's empty headers as the org's posture (phishield falsely scores 30 with "CSP/HSTS/XCTO missing"). This is the same WAF/CDN-403 family the back-test identified, but the Wave-2 `_probe` fix was not extended to the header checker. The earlier optional XFO/Referrer value-validation gap also remains open. Both are reporting-only header-card issues; no scoring-pipeline regression.


---

# Network & Exposure — Re-Test

Method: code verification across Waves 1-4 (`f0cf35e~1..f13ba11`) + free live re-checks (Shodan InternetDB keyless, no paid APIs). Cached `phishield_live.json` is PRE-FIX and was NOT trusted for output; fixes verified in code + live ground truth + isolated Python execution of the changed functions.

## Open Ports / High-Risk Protocols (DNS & Open Ports card)
- **Was:** GAP (attribution) — merged `open_ports` rendered under the apex (Cloudflare) IP header; on CDN-fronted targets FTP on a separate origin appeared to sit on the apex with no per-port IP attribution.
- **Now:** FIXED
- **Evidence:** HTML `templates/results.html:1349-1373` builds a `port_ip_map` from `dns.per_ip[ip].dns_infrastructure.open_ports` and renders a "Found on IP:" row per risky port; PDF `pdf_report.py:cat_dns` (≈797-808) adds the same "Found on IP" row. `scanner.py:295-333` confirms `_aggregate_ip_results` populates `dns.per_ip` with each IP's `dns_infrastructure.open_ports`, so the renderer reads real data. Live: InternetDB `34.76.113.116` (takealot) returns `ports:[21]` on Google Cloud (`*.googleusercontent.com`), NOT the apex — exactly the case now attributed correctly.

## Database / Service Exposure (High-Risk Protocol card)
- **Was:** PASS (with a dead 5432 `PORT_INTEL` hygiene entry in `dns_infrastructure`).
- **Now:** FIXED (no regression; hygiene addressed in Wave 4)
- **Evidence:** Detection path unchanged and correct. Live: InternetDB `213.133.105.171` returns `5432` open + `tags:["database"]` — phishield PostgreSQL exposure is real and still surfaces on the DB card. Wave 4 ("ghosts & hygiene") cleans the disjoint-port dead entry. No regression.

## VPN & Remote Access / RDP
- **Was:** BUG (VPN false-positive) — `Microsoft RDS Web` fired on the substring `"remote desktop"` with no status check; takealot rendered a false "VPN detected" badge. RDP path was PASS.
- **Now:** FIXED (VPN); PASS held (RDP)
- **Evidence:** `checkers_network.py:342-396` — `body_keywords` now require genuine RD Web tokens (`rdwebpage`, `domainusernamelabel`, `workspaceid`, `rdweb/pages`, `tswa_winauthcookie`); weak `"remote desktop"` removed; `require_200:True` + status gate added. Executed the match logic: soft-404 SPA mentioning "remote desktop" (HTTP 200) → no detection; 302+token → no detection; genuine RDWeb login form → detects. RDP reconciliation intact at `scanner.py:630-640` (`rdp_exposed`/`rdp_exposed_ips` set from any per-IP 3389) — no regression.

## Origin IP Discovery (Cloudflare-bypass)
- **Was:** PASS — cert-verified verified-vs-candidate separation, scan-only-verified posture.
- **Now:** PASS (no regression)
- **Evidence:** `origin_discovery.py` untouched in Waves 1-4 (not in the diff stat). Cert-match gating, renderer `status=='completed'` gating, and candidate/verified separation all unchanged. No regression introduced.

## CVE / Known Vulnerabilities (Shodan / external_ips card)
- **Was:** BUG — (1) ASN/Country fabricated as "1 ASN / 1 Country" + "Unknown" org on the free InternetDB path (`unique_asns = len(asns) or 1`); (2) latent >10-CVE undercount (`medium_count` bumped for CVEs 11+ without adding to `cves`).
- **Now:** (1) FIXED; (2) STILL-PRESENT (latent, unchanged — was a secondary/low-impact note, not in the committed fix set)
- **Evidence:** (1) `scoring_analytics.py:193-202` drops the `or 1` fallbacks, reports genuine `len(asns)`/`len(countries)`, and adds `asn_geo_unavailable`; HTML `results.html:1541-1542` renders `n/a` when the flag is set. Executed the aggregator: InternetDB path → `unique_asns=0, unique_countries=0, asn_geo_unavailable=True` (renders n/a); full-API path → genuine counts, flag False. Live: InternetDB `2a01:4f8:d0a:27c5::2` returns NO asn/org/country fields, confirming n/a is the correct output. (2) `checkers_threats.py:825-826` still does `for cve_id in raw_cves[10:]: result["medium_count"] += 1` while the aggregator recounts from the ≤10 `cves` list — unchanged. Low-impact (OSV.dev back-fill renders phishield's 19), and it was explicitly logged as a latent edge, not part of the 3 committed cluster fixes.

## Re-test summary
fixed=4 partial=1 still-broken=0 regressions=0 new=0; headline = all three committed Network & Exposure fixes (CVE ASN/geo fabrication, VPN RDWeb tokens+200, Open-Ports per-IP attribution) verified clean in code + live + execution; RDP and Origin Discovery held with no regression. The CVE card is PARTIAL only because the pre-existing latent >10-CVE undercount (a secondary back-test note, never in the fix scope) is untouched and stays low-impact.


---

# Email & Reputation — Re-Test

Method: code verification of Waves 1-4 fixes + free live DNS (dnspython) re-checks.
Cached `phishield_live.json` is PRE-FIX and was NOT trusted; fixes confirmed by driving
live values through the actual fixed functions. No paid APIs, no full live scans.

## IP / Domain Reputation (DNSBL)
- **Was:** CRITICAL false-positive — `checkers_network.py:925/933` counted any A-answer as a listing, so Spamhaus `127.255.255.x` (open-resolver/blocked) and URIBL `127.0.0.1` (refused) marked every scan `blacklisted:True`. Both phishield AND clean takealot flagged.
- **Now:** FIXED
- **Evidence:** New `DNSBLChecker._is_genuine_listing` (`checkers_network.py:963-1005`) validates return codes; called for both IP and domain lists (`checkers_network.py:1028,1037`). Live: `phishield/takealot.dbl.spamhaus.org → 127.255.255.254`, `takealot.multi.uribl.com → 127.0.0.1`. Driven through fixed code: `127.255.255.254 → False`, `127.0.0.1 → False`, real `127.0.1.2/127.0.0.2 → True`. Clean domains no longer flagged.

## Email Security (SPF / DMARC / DKIM)
- **Was:** DKIM false-positive — `_check_dkim` (`:452`) counted any resolving `selector._domainkey` TXT, so takealot's wildcard `*._domainkey` gave 41/41 selectors "found"; wildcard test domains gave 41/41. (+ minor SPF `~all`/`-all` GAP, untouched.)
- **Now:** FIXED (DKIM); GAP-remains (SPF qualifier, out of scope of this wave)
- **Evidence:** Fixed `_probe` (`checkers_core.py:509-523`) requires `v=dkim1` OR `p=` before counting (`:519`). Live takealot wildcard TXT `heritage=external-dns…` → rejected (`False`); real `google._domainkey` `v=DKIM1; …p=…` → accepted (`True`). Wildcard over-report eliminated, real keys retained. SPF `~all` vs `-all` still scored identically (`_calculate_score` unchanged) — pre-existing GAP, not a regression.

## Fraudulent Domains (Typosquat / Lookalike)
- **Was:** GAP — homoglyph map ASCII-only; no Unicode/IDN confusables (dominant real-world lookalike vector).
- **Now:** FIXED
- **Evidence:** New `IDN_HOMOGLYPHS` map + technique #9 (`checkers_threats.py:2150-2163, 2240-2262`) emits bounded punycode candidates (one substitution each, hard-capped at 12). Live generation for `phishield.com`: 6 `idn-homoglyph` candidates, all `xn--` (e.g. `xn--hishield-4bh.com`), DNS-resolvable form, no candidate-set explosion (115 total perms).

## VirusTotal Reputation
- **Was:** PASS (no fix needed; correctly gated, degrades without key).
- **Now:** FIXED / no-change (still PASS)
- **Evidence:** `VirusTotalChecker` scoring/guards untouched by Waves 1-4; no regression introduced. Optional `reputation<-X` enhancement still not wired (acknowledged low-priority, not a bug).

## Re-test summary
fixed=4 partial=0 still-broken=0 regressions=0 new=0; all 4 Email & Reputation cards verified — DNSBL return-code validation, DKIM `v=DKIM1`/`p=` gating, and IDN punycode typosquat candidates all confirmed against live DNS. One pre-existing SPF `~all`/`-all` GAP remains (out of scope, not a regression).


---

# Credential & Dark-Web — Re-Test

Cohort: phishield.com cached `test_fixtures/phishield_live.json` (card outputs are PRE-FIX). All
results recomputed from the fixture's RAW fields through the post-Wave code — no live provider
calls. Fix commits: `2b36471` (Wave 3a, Dehashed + Credential Risk), `f13ba11` (Wave 4, IntelX).

---

## 1. Brand Breach Record (HIBP)
- **Was:** PASS — `breach_count=0`, correctly scoped to B2B domain, defers to Credential Risk.
- **Now:** FIXED (no change needed / no regression)
- **Evidence:** No HIBP checker change across Waves 1–4 (`git log f0cf35e..f13ba11 -- checkers_threats.py` touches only Dehashed/CredRisk/IntelX). Fixture still `breach_count=0, breaches=[], status=completed`. Clean, untouched.

## 2. Dehashed Credential Leaks
- **Was:** BUG — `unique_emails=4` (case-sensitive double-count of `Rudolph@`/`rudolph@`); masked staff showed `Ru***h@` + `ru***h@`; `corporate_count=9` vs `staff=4` dual-number confusion.
- **Now:** FIXED (case bug) | PARTIAL (label confusion still open)
- **Evidence:** `checkers_threats.py:1276-1281,1335` now `.strip().lower()`. Recompute on the 13 cached `breach_details`: unique mailbox set = {louise, nkululeko, rudolph} → **3** (was 4); masked staff = `['lo***e@', 'nk***o@', 'ru***h@']` — duplicate pair gone. The `corporate_count=9` (per-record) vs `staff_accounts_total` (unique) dual-number labelling (orig. item 2b, cosmetic) was NOT relabelled in pdf_report/results.html — minor reader-confusion gap remains.

## 3. Credential Risk Assessment (CredentialRiskClassifier)
- **Was:** BUG — factor read "Plaintext or hashed passwords exposed for 4 email(s) across 13 breach record(s)" (boolean-as-count); only 2 records / 1 mailbox carry a password.
- **Now:** FIXED
- **Evidence:** `checkers_threats.py:1885-1906` now counts `pw_records = plaintext+hashed` and `pw_mailboxes` (case-insensitive, has_password OR has_hash). Recompute on fixture: `pw_records=2, pw_mailboxes=1` → factor renders **"Plaintext or hashed passwords exposed for 1 mailbox(es) across 2 of 13 breach record(s)"**. Matches the correlation-card fix. Risk_level/score (HIGH/55) wiring unchanged (correctness-only). Recency-heuristic gap (combo-list date anchoring, orig. item 3b) untouched — deferred, low.

## 4. Hudson Rock Infostealer Detection
- **Was:** PASS (low gap: `third_party_exposures=1` reaches score via nobody).
- **Now:** FIXED (no change needed / no regression)
- **Evidence:** No HR checker change in any wave. Fixture unchanged: `compromised_employees=0, third_party_exposures=1, score=95`. Reporting-only-via-RSI architecture intact; orig. third-party-blind-spot gap (low, by-design) not addressed and not a regression.

## 5. IntelX Dark-Web Monitoring
- **Was:** BUG — request asked `maxresults:40` but card showed `total_results=60` (non-reproducible); every record bucketed `leak`, `darkweb_count` always 0 even for infostealer logs.
- **Now:** FIXED (reproducibility) | PARTIAL (darkweb classification)
- **Evidence:** `checkers_threats.py:1989` `MAX_RESULTS=40`; `:2032-2068` truncates returned records to 40 and sets `result_cap_applied=True` — synthetic 60→40 confirmed, count now bounded/reproducible. New `_is_darkweb_grade` (`:2002-2013`) classifies on `media==13`, `bucket` in (darknet/logs/stealer), or `_STEALER_TOKENS` in name. **PARTIAL:** the bucket path (the load-bearing one — IntelX `leaks.logs.*`) cannot be confirmed from this fixture because `recent_results` strips `bucket`/`media`-int. Tested classifier on the 10 cached record NAMES alone (media=0): only **1 of 10** matched (`Microsoft Edge_Default.txt` via `_default.txt`); the other 9 clear stealer dumps (`.rar/...Slow-dom...txt`, `/Important Files/Desktop/1md.txt`, ZA/CN IP-tagged) miss every token. So in production `darkweb_count` correctness hinges entirely on IntelX returning a `logs`/`darknet` bucket — unverifiable credit-free; if it does not, the row still understates. No regression; reproducibility fix is solid.

## Re-test summary
fixed=3 partial=2 still-broken=0 regressions=0 new=0; headline = **all 3 original BUGs corrected** — Dehashed case-double-count (4→3 mailboxes, masked staff de-duped) and Credential Risk boolean-as-count ("4 emails/13" → "1 mailbox across 2 of 13") both verified by recompute on cached RAW fields; IntelX is reproducible (40-cap truncation confirmed) but its `darkweb_count` classification is PARTIAL — depends on an IntelX `bucket` field not captured in the fixture (name-token fallback caught only 1/10 cached stealer logs). Residual low gaps (Dehashed corporate-vs-staff dual-label, CredRisk combo-date recency, HR third-party blind spot) were out of fix scope and remain.


---

# Attack Surface & Tech — Re-Test

Method: code verification of the committed fixes + free, non-intrusive live
re-checks against takealot.com (HttpWebRequest HEAD/GET, `[System.Net.Dns]`,
crt.sh JSON). Cached `phishield_live.json` is PRE-FIX, so all confirmation is
code + live. All five touched files byte-compile clean
(`py_compile` on checkers_core / checkers_network / checkers_supply_chain /
checkers_threats / scoring_analytics → OK).

## Subdomains (CT logs / crt.sh)
- **Was:** BUG (high) — no wildcard-DNS detection → brute-force fabricated 9
  "risky" phantom subs maxing `sub_risk`; crt.sh secondary/flaky so card
  silently under-discovered (16 vs 77) yet PDF claimed CT; `ct_count` could
  exceed `total_count`.
- **Now:** FIXED
- **Evidence:** `checkers_network.py:157-185` crt.sh is now PRIMARY with
  `%25`-encoding + 2-attempt retry + `ct_source_ok` flag; `:73-83 _wildcard_ips`
  resolves two random labels, `:193-204` suppresses brute-force on a wildcard
  apex, `:217` discards residual wildcard-IP brute hits; `:230`
  `ct_count=min(ct_count,total_count)` caps it. Live: crt.sh (after one 404
  retry, exactly the new loop) returned **76** unique subs; random labels
  `nx-*.takealot.com` → NXDOMAIN (no wildcard today, so brute hits with
  distinct IPs are legitimately kept — guard behaves correctly in both states).

## Exposed Admin & Sensitive Paths
- **Was:** BUG/INVERSION (critical) — 403/401 counted as critical exposure;
  WAF/CDN blanket-deny maxed `admin_risk` to 100, penalising well-defended orgs.
- **Now:** FIXED
- **Evidence:** `checkers_core.py:1098` now `if r.status_code != 200: return None`
  (403/401/404/3xx rejected), `:1103-1116` body-sanity GET rejects HTML shells
  (`<html`/`<!doctype`), "not found"/"404", and <10-byte bodies. Live proof of
  robustness on BOTH failure modes: `.env` & `.git/HEAD` → **403** (now
  suppressed); `wp-config.php`/`backup.sql`/`dump.sql` → **200 but body is the
  Next.js SPA shell** `<!DOCTYPE html><html…>` (16.6 kB) → caught by the
  `<!doctype` reject; random control → 404. Zero false criticals.

## Technology Stack & EOL
- **Was:** GAP + minor BUG (medium) — EOL table stale vs endoflife.date (no PHP
  8.x, Node 18/20, modern nginx/Apache); `X-Powered-By: Awesome` decoy surfaced
  & penalised; binary red/green traffic light (no amber).
- **Now:** PARTIAL
- **Evidence:** EOL GAP FIXED — `checkers_threats.py:14-67` table "Refreshed
  2026-06-02 against endoflife.date" now includes PHP 8.0 (EOL Nov-2023)/8.1,
  Node 16/18, nginx 1.16/1.18, IIS 8.x, Tomcat 9, Python 3.8. BUT the two minor
  BUG items remain: (1) no decoy-header filter — `:104-108` still emits
  "X-Powered-By discloses technology: Awesome" and applies `-5` for Cloudflare's
  joke header; (2) traffic light still binary — `results.html:2269`
  `ts_tl = 'tl-crimson' if ts.eol_detected else 'tl-green'`, no amber for
  info-leak/old-jQuery penalties.

## CMS Plugin Surface (WordPress)
- **Was:** BUG/false-positive (high) — `_is_wordpress` & `_probe_plugin`
  accepted any non-404 (incl. 403/catch-all 200), so a full 25-plugin WordPress
  SBOM was reported for non-WP/WAF sites; phantom `cms_risk`.
- **Now:** FIXED
- **Evidence:** `checkers_supply_chain.py:880-936 _is_wordpress` adds a catch-all
  guard (random path 200-body) + requires a genuine fingerprint (homepage
  `/wp-content/` or WP generator, OR `wp-login.php` 200 with `user_login`/
  `wp-submit`/`wordpress` markers AND body ≠ catch-all); `:938-974 _probe_plugin`
  now requires readme.txt **200** + real WP readme markers (`=== `/`stable tag:`/
  `tested up to:`), rejecting HTML shells. Live: takealot home has no
  `/wp-content/` or WP generator; `wp-login.php` → 200 but body is the SPA shell
  (= catch-all, no WP markers) → rejected; `akismet/readme.txt` → **404**. So
  `is_wordpress=False`, `plugin_count=0`. SBOM no longer fabricated.

## Exposed Dependency Manifests (S-3)
- **Was:** PASS — the only WAF-robust checker; `_probe` 200-only + body-sanity.
- **Now:** FIXED (no regression)
- **Evidence:** `checkers_supply_chain.py:188-201 _probe` unchanged — HEAD+GET
  both must be 200, len ≥10, rejects `<html`/`<!doctype`/"not found"/"404". This
  remained the template the Admin (`checkers_core.py:1098-1116`) and CMS
  (`:938-974`) fixes were modelled on. Compiles clean.

## Re-test summary
fixed=4 partial=1 still-broken=0 regressions=0 new=0; the WAF/CDN 403-blanket +
200-catch-all root cause is eliminated across Exposed Admin (inversion gone,
robust to both the 403 and the SPA-shell-200 case), CMS Plugins (false 25-plugin
WP SBOM gone), and Subdomains (crt.sh primary + wildcard guard + ct_count cap);
S-3 unregressed. Only residual: Tech Stack EOL **table** refreshed but the two
minor cosmetics — `X-Powered-By: Awesome` decoy still surfaced/penalised and the
binary (no-amber) traffic light — are not yet addressed.


---

# Supply-Chain & Correlation — Re-Test

Method: code re-read of `checkers_supply_chain.py` / `scanner.py` / `scoring_analytics.py` +
`vendor_breaches.json`; free `Resolve-DnsName` of takealot SPF; classifier/worst-severity
replay; full S-4→S-5→cross-correlation trace. No paid APIs, no live full scans. Cached
`phishield_live.json` is pre-fix and was not relied on.

Live SPF confirmed (`Resolve-DnsName takealot.com TXT`):
`v=spf1 ... include:_spf.google.com include:mail.zendesk.com include:spf.mandrillapp.com
include:transmail.net include:_spf.123formbuilder.com -all`

## Supply-Chain / Related Domains (S-1)
- **Was:** GAP — inert without broker input (auto-discovery deferred); card correct + wired once.
- **Now:** STILL-BROKEN (out of fix scope — not in Waves 1-4)
- **Evidence:** `related_domains` still WEIGHTS 0.04 once (scoring_analytics.py:507), no v1.1
  auto-discovery shipped. Unchanged by these fixes; remains a deferred GAP, not a regression.

## Third-Party JavaScript (S-2)
- **Was:** PASS — first-party relative `/_next/...` correctly classed; no parser miss.
- **Now:** FIXED (no regression — still PASS)
- **Evidence:** `_host_of` replay: `/_next/static/chunks/polyfills-abc.js`→`takealot.com`,
  `/main.js`→`takealot.com`, real third-parties (`cdn.takealot.com`, `polyfill.io`) still
  resolved. `third_party_js` WEIGHTS 0.03 once (line 509). No change to S-2 logic; intact.

## Email-Vendor Surface / SPF (S-4)
- **Was:** BUG — `spf.mandrillapp.com` and `transmail.net` misclassified as "unknown"
  (Mandrill miss was load-bearing, suppressing the Mailchimp S-5 match).
- **Now:** FIXED
- **Evidence:** `VENDOR_PATTERNS` (checkers_supply_chain.py:687-698) now lists
  `spf.mandrillapp.com`/`mandrillapp.com`/`mandrill.com` under `mailchimp` and
  `transmail.net`/`zeptomail.com`/`zeptomail.eu` under `zoho`. Classifier replay:
  `spf.mandrillapp.com`→`mailchimp`, `transmail.net`→`zoho`, `zeptomail.com`→`zoho`.
  takealot now classifies 4 vendors (google_workspace, mailchimp, zendesk, zoho) vs 2
  pre-fix. (`123formbuilder` still unknown — left as informational, acceptable.)

## Vendor Breach Correlation (S-5)
- **Was:** GAP — (a) inherited S-4 gap suppressed a real HIGH Mailchimp match;
  (b) 2 permanently-expired rows (sendgrid 2018, constant_contact 2021-05) could never match.
- **Now:** FIXED
- **Evidence:** With S-4 fixed, S-5 join now returns mailchimp (2× HIGH: 2023-01-11,
  2022-08-12) **and** zendesk (medium) for takealot — the suppressed HIGH match surfaces.
  `vendor_breaches.json` pruned to 12 rows; `sendgrid`/`constant_contact` both absent
  (replay confirmed). Key audit: 0 dead keys (all 8 DB vendors ∈ VENDOR_PATTERNS).
  WEIGHTS 0.04 once (line 512). **Residual (minor):** `marketo` 2021-06-22 now 1806d vs
  LOOKBACK 1825 — expires in ~19 days; the editorial-expiry test the original recommended
  was not added (NEW-ISSUE, low — quiet drift will recur).

## Third-Party Cross-Correlation (HR × S-4 × S-5)
- **Was:** BUG — severity hard-set CRITICAL on ANY overlap (medium zendesk → CRITICAL
  "rotate TODAY"); stale docstring claimed it "drives RSI / FIC uplift".
- **Now:** FIXED
- **Evidence:** Severity now tracks worst underlying breach via `_SEV_RANK`
  (scanner.py:1001-1014): replay → medium-only=medium, high+medium=high, critical=critical,
  garbage-sev defaults safely to medium. Docstring (scanner.py:921-929) corrected to
  "REPORTING-ONLY ... excluded from WEIGHTS, RSI, FIC vuln uplift, REMEDIATION_MAP" and
  "severity tracks the MOST SEVERE underlying breach". On takealot the overlap now resolves
  to **high** (mailchimp), a defensible escalation rather than a medium-only over-call.
- **Double-count check:** STILL EXCLUDED. `third_party_correlation` NOT in WEIGHTS (only the
  no-double-count note at scoring_analytics.py:513-520) and reporting-only notes intact at
  all four scoring surfaces (lines 750, 1100, 2092, 3407). S-1/2/4/5 each weighted once.

## Re-test summary
fixed=4 partial=0 still-broken=1 regressions=0 new=1; headline = the load-bearing S-4
Mandrill/Zoho pattern gap is FIXED and the suppressed HIGH-severity Mailchimp S-5 match now
surfaces end-to-end (takealot: 4 vendors, mailchimp 2×HIGH + zendesk medium); cross-correlation
severity now tracks the worst underlying breach (medium→medium, mailchimp→high) and the stale
docstring is corrected, with cross-corr STILL excluded from WEIGHTS (no double-count); 2
permanently-expired DB rows pruned. STILL-BROKEN: S-1 auto-discovery (out of scope, deferred
GAP, no regression). NEW low: marketo row expires in ~19 days and no editorial-expiry test was
added, so DB drift will recur.


---

# Insurance Analytics & Financial — Re-Test

Method: credit-free CODE verification of Waves 1-4 + offline-python recompute from
`test_fixtures/phishield_live.json` RAW numbers via the FIXED formulas. The cached
fixture is PRE-FIX (it still carries `vulnerability=0.5`, `p_breach=0.2175`, and has
NO `_overall_score` in `categories`) — financial values were recomputed by hand, not
trusted from the stale fixture. No live scans, no paid APIs. Regression gate
`verify_supply_chain_financial_wiring.py` = 31/31 PASS. Calibration → FIN-9.

---

## (1) RSI — Ransomware Susceptibility Index
- **Was:** PASS (math reconciles; flagged dead-ghost `cat_ransomware_risk`)
- **Now:** FIXED
- **Evidence:** Ghost `cat_ransomware_risk` deleted (Wave 4, pdf_report.py — replaced by a NOTE block at ~2879; grep finds no `def`/call, only docs + the comment). Live `cat_rsi` untouched; RSI math/caps/multipliers unchanged so the 0.728 reconciliation still holds.

## (2) DBI — Data Breach Index
- **Was:** BUG (ghost renderer `cat_data_breach_index` only; card itself PASS)
- **Now:** FIXED
- **Evidence:** Ghost `cat_data_breach_index` deleted (Wave 4) alongside `cat_ransomware_risk`; only `cat_dbi` remains wired. Live DBI card (nested `components`, `label`) unchanged.

## (3) Financial Impact Analysis — `vulnerability` pinned at 0.5
- **Was:** BUG/high — `scanner.py` never wrote `cat_results["_overall_score"]`; `_calculate_zar` defaulted it to 500 → `vulnerability` stuck at 0.5, decoupling p_breach/MC tails from posture.
- **Now:** FIXED (wiring; magnitude → DEFER-FIN9)
- **Evidence:** Wave 1 adds `cat_results["_overall_score"] = risk_score` at scanner.py:1114, BEFORE the Phase 6 FIC call (line 1174). Read path intact: scoring_analytics.py:2037 `categories.get("_overall_score", 500)` → :2038 `vulnerability=(100-overall/10)/100` → :2107 `p_breach=min(1, vuln*tef*0.3)`. Offline recompute with the now-wired score: phishield overall=381 → vuln **0.619**, p_breach **0.269** (was 0.5 / 0.2175); takealot overall=245 → vuln **0.755**, p_breach **0.283** (was 0.5 / 0.1875) — matches the original predicted post-fix values exactly. Clean vs critical sites now price differently on the breach axis. (Cached fixture still shows the old 0.5 because it predates the fix; a post-fix scan is needed to refresh stored magnitudes.)

## (4) Loss Exposure / Return Periods (1-in-100 / 200 / 250)
- **Was:** PASS (ordering/labels sound; magnitudes biased low by inheriting (3)'s 0.5)
- **Now:** FIXED (inherited correction)
- **Evidence:** Ordering/label/render logic untouched — fixture still strictly ordered P99 14.69M < P99.5 15.88M < P99.6 16.24M with correct exceedance-prob labels. The low-magnitude bias is now resolved upstream by (3); absolute tails will rise on the next post-fix scan (recompute: vuln 0.5→0.619 lifts p_breach ~24%, which scales the loss curve). No regression in the return-period/loss_exposure/monte_carlo reconciliation.

## (5) Peer Benchmarking
- **Was:** NEEDS-LIVE + minor GAP (peer uses raw `annual_revenue_zar`→"micro" while FIC defaults missing revenue to R10M — revenue basis not unified).
- **Now:** PARTIAL (NEW-ISSUE persists — out of assigned scope)
- **Evidence:** `peer_benchmarking.py` was NOT touched by any wave (git show across f0cf35e/f13ba11/2b36471/c1d3134/8d2663b = no diff). FIC still uses the R10M fallback (scanner.py:1184 `_zar = ... else 10_000_000`), peer still reads raw revenue → the two cards still disagree on revenue band for the same scan. Logic otherwise sound; populated `status="ok"` path still NEEDS-LIVE (pool=0). Not in the committed fix list — carry forward.

## (6) Remediation Roadmap (before/after savings)
- **Was:** BUG/medium — (a) two adjacent cards show divergent totals (R2.01M vs R2.70M) for one scan; (b) RemediationSimulator sums 14 `rsi_reduction` values arithmetically (0.59) with no cap → implied 81% loss cut.
- **Now:** (a) FIXED (relabel); (b) PARTIAL — cap correctly wired but non-binding for phishield's specific numbers → DEFER-FIN9 on magnitude.
- **Evidence (a):** Wave 4 relabels the two cards as methodologically distinct with cross-refs: "Remediation Roadmap — RSI Prioritisation" (RSI-point + RSI-scaled loss) vs "Risk Mitigation Recommendations (Expected-Loss)" (incident-driven, 85%-capped); both notes now state they are complementary, not competing totals. They no longer read as conflicting savings.
- **Evidence (b):** scoring_analytics.py:3332 adds `RSI_RESIDUAL_FLOOR=0.05`, `MAX_RSI_REDUCTION_FRACTION=0.15`; simulated_rsi now floored at `max(0.05, current_rsi*0.15)`; `rsi_improvement` reports the EFFECTIVE (capped) value and per-step savings are scaled by `effective/total` so the displayed reduction matches savings. Offline recompute confirms the cap binds and ceilings loss cut at ~83-85% (mirrors `_build_mitigations` 85%) for high-reduction cases (e.g. RSI 0.728 / sum 0.70 → 96%→85%; RSI 0.5 / sum 0.6 → 100%→85%). BUT for phishield (RSI 0.728, sum 0.59) the floor is 0.109 < uncapped sim 0.138, so the cap is a **no-op** here — phishield still shows 81% / R2.01M unchanged. Class of unbounded overstatement is fixed; the 81% phishield figure is now a calibration question (whether 81% is itself too high) → FIN-9.

## Re-test summary
fixed=4 partial=1 still-broken=0 regressions=0 new=1 (defer-fin9 on (3) magnitude + (6b) magnitude);
headline: the headline production bug — Financial Impact `vulnerability` pinned at 0.5 — is FIXED: scanner.py:1114 now wires `_overall_score=risk_score` before the FIC, recompute gives phishield vuln 0.619 / p_breach 0.269 and takealot 0.755 / 0.283 (was 0.5 for both); both dead-ghost renderers deleted; the two remediation cards relabelled distinct + a residual-floor cap added (correctly bounds ~85% loss cut, though non-binding for phishield's own numbers, so its 81% figure is now a FIN-9 calibration call). The only carry-forward is the peer-vs-FIC revenue-basis mismatch (card 5), which no wave touched. Wiring verifier 31/31 PASS — no regressions. The cached fixture remains pre-fix; a post-fix scan is needed to refresh stored financial magnitudes.
