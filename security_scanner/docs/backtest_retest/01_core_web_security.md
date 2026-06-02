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
