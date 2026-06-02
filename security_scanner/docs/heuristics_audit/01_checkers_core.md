# checkers_core.py — Heuristics Audit

**Module:** `security_scanner/checkers_core.py` (SSL/TLS, Email Security DNS,
Email Hardening, HTTP Security Headers, WAF, Cloud/CDN, Domain Intel/WHOIS,
Exposed Admin).
**Protocol:** Step 6 (white-box heuristics sweep) of `docs/card_verification_protocol.md`.
**Reference fixed-code data:** `test_fixtures/phishield_live.json` (live phishield.com scan).
**Scope note:** Waves 1-5 already hardened SSL (sslyze-6.x cert API), WAF (F5
markers), DKIM (`v=DKIM1` / `p=` gate), Exposed-Admin (200-only + body sanity),
and HTTP-headers (non-2xx guard). Those are **confirmed clean against the
fixture** (re-checked below) and this audit focuses on the REMAINING heuristics.

Class legend: `justified` (defensible, basis stated) / `fragile` (works on the
sample, brittle elsewhere — hardening proposed) / `arbitrary` (no rationale —
document or remove) / `calibration-gated` (scoring magic-number whose VALUE
belongs to the calibration session — FLAGGED, not intuited).

Scoring context (downstream consumers in `scoring_analytics.py`):
`ssl_risk = inv(ssl.score, default 50)`; `email_risk = inv(score/10*100, default 5)`;
`email_hard_risk = inv(score/10*100, default 0)`; `header_risk = inv(http_headers.score, default 50)`;
`admin_risk = min(100, crit*50 + high*20)`; WAF presence yields a category bonus.
So every SSL/email/header `ded`/`score` constant is a **scoring** magic-number.

---

## SSLChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| `WEAK_CIPHERS = [RC4,DES,3DES,MD5,NULL,EXPORT,ANON,RC2]` | L14 | Substring list flags weak cipher fragments | Loose-substring screen: each token is specific enough (no false hits on modern AEAD names like AES_GCM/CHACHA20); `DES`⊄`AES`/`3DES`-safe. Curated-table: stable (these never become "strong"). | justified | Keep. Empirically sound TLS-weak set; no drift risk. |
| `bits = 256 if "256" in name else (128 if "128" in name else 0)` | L160 | Infers cipher strength from name substring | **Fragile / data-quality bug:** fixture shows `name=TLS_AES_128_CCM_SHA256` → matched on the `SHA256` and reported **bits=256** for an AES-**128** cipher. Substring is checked against the WHOLE name incl. the hash. Not scored today, but rendered. | fragile | Parse bits from the cipher token only (regex `AES_(\d+)` / `_(128\|256)_`), not the hash suffix; or read sslyze's `key_size`. Free, deterministic. |
| `best = all_accepted[-1]` ("last = highest version") | L155 | Picks "best" cipher as last accepted suite | Order assumption: relies on tls_map iteration order (1.0→1.3) + extend order; brittle if a version block is empty/reordered. Cosmetic only (display), not scored. | fragile | Select explicitly by highest negotiated TLS label present, not list position. Low priority (display-only). |
| Cert `valid = chain_valid AND hostname_match AND days_left>=0` | L102 | Composite validity gate | Inversion/fabrication screen: clean — on sslyze parse error it re-`raise`s (L127) so `certificate={}` does NOT silently brand cert invalid (the Wave-1 fix). Confirmed: fixture `valid:True`. | justified | Keep (Wave-1 hardened). |
| `expiring_soon = 0 <= days_left <= 30` | L112,233 | 30-day expiry window | Threshold: 30d is the CA/Browser-forum renewal-alert norm; matches ACME auto-renew lead time. | justified | Keep; cite 30d = industry renewal-alert standard. |
| `_hostname_matches` wildcard: `host.count(".")==name.count(".")` | L199 | RFC6125 single-label wildcard match | Loose-match screen: correctly rejects bare apex vs `*.` and multi-label; label-count guard is the RFC-6125 rule. | justified | Keep. Correct RFC-6125 behaviour. |
| OCSP fallback `dep.ocsp_response is not None` | L120 | Treats any OCSP response as "stapled" | Fabrication-ish: when `ocsp_response_is_trusted` is None it falls back to presence-only (untrusted staple counts as stapled). Low impact (−5 only). | fragile | Prefer the `_is_trusted` boolean; treat unknown as `None` (no deduction) rather than "present". |
| **Grade deductions** `40/40/20/15/20/30/25/20/10/30/20/10/5/5` | L320-360 | Per-issue point deductions → 0-100 score | Calibration screen: these are the SSL **score** magic-numbers; `ssl.score` feeds `ssl_risk` at weight 0.09. No single value is wrong, but the relative sizing (e.g. missing-CAA −5 vs TLS1.0 −20 vs invalid-cert −40) is unanchored. | calibration-gated | FLAG for FIN-9. Do not retune here; anchor relative weights to an external SSL grading rubric (e.g. SSL Labs / Mozilla TLS) in the calibration pass. |
| Grade bands `A+>=95, A>=85, B>=70, C>=55, D>=40, F` | L363 | Maps score→letter grade | Calibration: band cutoffs are arbitrary-but-conventional; cosmetic (grade not scored, score is). | calibration-gated | FLAG with the deductions; align bands to whichever rubric the deductions are calibrated against. |
| Key-size gate `<2048 → −20; <4096 → pass` | L330-333 | Penalises sub-2048 RSA only | Threshold: 2048 = NIST SP800-57 / CA-Browser minimum; the dead `<4096 elif: pass` is a no-op. Note: ECDSA key_size (256/384) would trip `<2048` → false "weak key". Fixture is RSA-2048 (clean). | fragile | Add curve awareness: skip/relabel the 2048 gate for EC keys (key_size 256/384 are strong). Free check on key type. |
| `WEAK_CIPHERS` re-applied to stdlib path bits=`c[2] or 0` | L271-275 | stdlib fallback cipher strength | Fabrication screen: on exception returns `is_weak:True, bits:0` — a hard-fail default that biases toward "weak". Defensible (fail-closed) but can over-penalise on a transient stdlib error. | fragile | Distinguish "could not assess" from "weak" so a connect error doesn't read as a weak-cipher finding (mirror the headers `unreachable` pattern). |

## EmailSecurityChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| `DKIM_SELECTORS` (38 names) | L373-393 | Brute-probes common DKIM selectors | Curated-table + boolean-as-count: list will drift as ESPs add selectors; **a miss ≠ "no DKIM"** (selectors are unbounded). Wave fix on `_probe` (L519 `v=dkim1`/`p=` gate) correctly stops wildcard-TXT false positives — confirmed (fixture found only `k2`). | fragile | Keep the probe gate (clean). For the list: document it as best-effort, never assert "no DKIM"; the score text (below) already over-claims. Add selectors opportunistically. |
| Issue text "across 40 common selector names" | L566 | Hardcoded "40" | **Boolean/count mismatch (cosmetic):** list has **38** entries, message says 40 — silently stale. | arbitrary | Replace literal with `len(self.DKIM_SELECTORS)`; remove the magic "40". |
| SPF `valid = has_all OR has_redirect` | L425 | Validity = presence of `all`/`redirect` | Loose-substring: `has_all = "all" in txt` matches the substring "all" ANYWHERE (e.g. a domain literally containing "all", or `mx:mail.smallco.com`), not the `-all`/`~all`/`+all` mechanism. Over-counts valid. | fragile | Match the qualifier mechanism `[-~?+]all\b` at a word boundary, not bare `"all" in txt`. Free regex. |
| SPF `dangerous = "+all" in txt` | L430 | Flags permissive `+all` | Substring: `+all` is specific; correct. | justified | Keep. |
| SPF `exceeds_lookup_limit = dns_lookups > 10` | L433 | RFC 7208 10-lookup cap | Threshold: 10 is the literal RFC 7208 §4.6.4 limit. The counter (`_count_spf_lookups`) regex-counts `a`/`mx`/`include`/`exists`/`redirect` with `depth>5` recursion guard and `includes[:5]` truncation — under-counts deep chains but won't fabricate. Fixture: 11 lookups flagged, plausible. | justified | Keep threshold (RFC). Note counter may under-report (truncation) — acceptable, fail-low not fail-high. |
| SPF lookup counter `depth>5` / `includes[:5]` caps | L442,454 | Recursion + breadth caps | Arbitrary caps: 5/5 are unstated. They bound runtime; risk is under-count on pathological SPF, not a false finding. | arbitrary | Document the 5/5 as DoS/runtime guards; note they can under-report lookup count on very deep chains. |
| DMARC `policy = p=(\w+)` else `"none"` | L483-484 | Extract policy, default none | Fabrication screen: defaults to `"none"` only when `p=` absent in a present DMARC1 record (malformed) — that IS effectively no enforcement, so the default is conservative-correct. | justified | Keep. |
| DMARC `pct` default `100` (present) / `0` (absent) | L487,503 | Percentage enforcement | Justified: RFC default for pct is 100; absent-record uses 0 (won't trigger partial-enforcement penalty falsely). | justified | Keep (RFC default). |
| `subdomain_policy` defaults to `policy` | L490 | sp= inherits p= | Justified: RFC 7489 — sp defaults to p when omitted. | justified | Keep (RFC). |
| **Email score** start `10`; SPF −3/−3/−1/−1; DMARC −4/−2/−1/−1; DKIM −2 | L541-566 | Builds 0-10 email score | Calibration: these feed `email_risk` (default 5). Relative sizing (DMARC-absent −4 vs DKIM-absent −2 vs SPF-absent −3) is plausible-but-unanchored; DKIM −2 is harsh given selector-probe is best-effort (a real DKIM with an uncommon selector → false −2). | calibration-gated | FLAG for FIN-9. Especially reconsider the DKIM −2: probe-miss is not proof-of-absence. Anchor to DBIR/M3AAWG email-auth posture data. |

## EmailHardeningChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| MTA-STS mode via `re.search(r"mode:\s*(\w+)")` on policy file; fallback `"unknown"` | L608-611 | Reads enforce/testing mode | Fabrication screen: clean — on fetch failure sets `"unknown"`, and scoring only awards the +2 bonus when `mode=="enforce"`, so unknown ≠ enforce. | justified | Keep. |
| BIMI `has_vmc = "a=https" in txt.lower()` | L623 | VMC presence via `a=` tag | Loose-substring: `a=https` is the BIMI VMC evidence tag; specific enough. | justified | Keep. |
| DANE: TLSA on `_25._tcp.{primary MX}` only | L629-642 | Probes only lowest-pref MX | Coverage gap (not a false signal): checks only the primary MX; a domain with DANE on secondary MXs but not primary reads as "absent". Conservative (won't fabricate present). | fragile | Probe all MX hosts (or document "primary-MX only"). Free DNS. Low priority. |
| **Hardening score** MTA-STS +4(+2), BIMI +2(+1), DANE +1, TLS-RPT +1, `min(score,10)` | L665-683 | Builds 0-10 hardening score | Calibration: feeds `email_hard_risk` (default 0 → absent reads as MAX risk via `inv`). The +4 MTA-STS vs +2 BIMI vs +1 DANE sizing is unanchored; BIMI (a brand/deliverability feature) scoring nearly as high as DANE (a security control) is questionable. | calibration-gated | FLAG for FIN-9. Reconsider BIMI weight vs DANE/MTA-STS on a security basis. Note default-0 means a failed/`status:error` hardening check penalises as if fully absent. |

## HTTPHeaderChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| Non-2xx guard → `status:"unreachable"`, drop score/headers | L796-811 | Skips header scoring on WAF/CDN 403/503/429 | Inversion screen: **clean** — this IS the Wave-5 fix; fixture confirms phishield 403 → `unreachable`, no penalty. Downstream falls back to neutral 50. | justified | Keep (Wave-5 hardened). Reference pattern for the SSL stdlib-error case above. |
| Header weights CSP 10, XFO 15, XCTO 15, HSTS 20, Referrer 15, Permissions 15 | L692-699 | Per-header earned/total weighting | Calibration: weights set the header sub-score that becomes `header_risk`. Permissions-Policy weighted equal to XCTO/Referrer (15) despite far lower real-world security value; HSTS 20 is defensible (transport security). Unanchored relative sizing. | calibration-gated | FLAG for FIN-9. Anchor to a header-importance rubric (e.g. Mozilla Observatory weights). Don't retune here. |
| CSP quality base `50`; dangerous −15 each; missing-critical −8 each; bonuses +20/+10/+10/+10 | L758-771 | 0-100 CSP quality sub-score | Calibration: nested magic-numbers feeding a `round(score/10)` 0-10 bonus. Internally plausible (Observatory-like) but unanchored. | calibration-gated | FLAG for FIN-9. Cite/borrow Mozilla Observatory CSP scoring rather than bespoke constants. |
| `CSP_DANGEROUS` + `CSP_CRITICAL_DIRECTIVES` lists | L702-709 | Pattern/directive curation | Curated-table: these are stable CSP semantics (unsafe-inline/eval/*/data:); directive set is the standard critical set. Wildcard checked in `script-src` specifically (good — avoids generic `*` false hit). | justified | Keep. Stable CSP spec, low drift. |
| `csp_bonus = round(quality/10)` added to `earned` | L829 | Folds CSP quality into score | Logic: adds up to +10 earned AND +10 to total_weight (L831) whether or not CSP present (L839) — symmetric, no inflation. | justified | Keep. |

## WAFChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| `WAF_SIGNATURES` header/cookie/body/server markers | L852-895 | Fingerprint table for 7 WAFs | Curated-table + Wave-2 fix: F5 `x-frame-options`/`ts` removed (ubiquitous-header inversion) — confirmed clean. Remaining markers are vendor-specific. Table will drift (new WAFs/renamed headers) but won't fabricate. | justified | Keep (Wave-2 hardened). Document as best-effort; absence ≠ "no WAF" (already only a recommendation, not a hard score). |
| Body match on `r.text[:5000].lower()` substrings (`cloudflare`,`sucuri`,`incap_ses`…) | L912,929 | Body-substring WAF detection | Loose-substring screen: `"cloudflare"`/`"sucuri"` in body could match incidental page text (e.g. a blog mentioning Cloudflare) → false WAF-positive → phantom WAF bonus in scoring. Header/cookie matches are safe; body is the weak channel. | fragile | Tighten body markers to error-page/challenge fingerprints (e.g. `Attention Required! \| Cloudflare`, `Access Denied - Sucuri`), not bare vendor names. Free string change. |
| Cookie prefix-match `name==c or name.startswith(c)` | L926 | Matches dynamic-suffix vendor cookies | Wave-fix: enables `BIGipServer<pool>`/`TS01<hex>`; prefixes are specific. | justified | Keep. |
| `waf_name = detected[0]` (first match wins) | L941 | Reports single WAF when multiple match | Minor: arbitrary tie-break by dict order; `all_detected` preserved so no data loss. | justified | Keep (full list retained). |

## CloudCDNChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| `CLOUD_CNAMES` suffix table (9 providers) | L955-965 | CNAME-suffix → provider | Curated-table: leading-dot suffixes (`.cloudfront.net`) are anchored enough to avoid false hits; drift risk is missing a NEW provider (false-negative, safe), not false-positive. | justified | Keep; document as non-exhaustive. |
| CNAME chase `range(5)` | L989 | Caps CNAME-chain follow at 5 | Arbitrary cap: 5 is unstated but bounds a pathological chain; under-follow only → false-negative, safe. | arbitrary | Document 5 as a loop-DoS guard. |
| `hosting_type = "self-hosted or undetected cloud"` when no CNAME match but IPs exist | L1009 | Fallback label | Fabrication screen: honest fallback ("undetected"), not invented certainty. Not scored. | justified | Keep. |

## DomainIntelChecker (WHOIS)

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| Age bands `<365d` and `<730d` → fraud-risk issues | L1047-1050 | Young-domain flag | Threshold: 1yr/2yr are common newly-registered-domain (NRD) heuristics; reasonable for fraud/typosquat context. Not a hard score (issue text only). | justified | Keep; cite NRD-age convention. |
| Expiry `<30d → renewal risk` | L1055 | Imminent-expiry flag | Threshold: 30d is a sensible renewal-alert window. | justified | Keep. |
| `privacy_keywords = [redacted,privacy,withheld,protected,proxy]` on `str(w).lower()` | L1060-1061 | Detects WHOIS privacy | **Loose-substring screen:** matching against the WHOLE stringified WHOIS object is broad — `"protected"`/`"proxy"` can appear in unrelated fields (registrar names, status URLs, nameservers like `*.proxy.*`), risking false "privacy_protected". `privacy_protected` is informational (not scored) but can mislead attribution. | fragile | Match only registrant/admin contact fields, not the whole blob; or require ≥2 keyword hits. Free. |
| `creation/expiry` list→`[0]` (first element) | L1036-1039 | Picks first date when WHOIS returns a list | Fabrication-ish: some registries return multiple dates; `[0]` may not be authoritative. Low impact. | fragile | Prefer `min(creation)`/`max(expiry)` over positional `[0]`. Low priority. |

## ExposedAdminChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| 200-only + body-sanity gate (`<10` len, `<html`/`<!doctype`, `not found`/`404`) | L1126-1145 | Confirms real exposure | Inversion screen: **clean** — Wave-1 fix; 401/403/3xx/404 no longer count, HTML shells rejected. Fixture: `exposed:[]`, counts 0. | justified | Keep (Wave-1 hardened). Reference pattern. |
| `PATHS` critical/high/medium wordlists (38 paths) | L1076-1095 | Sensitive-path enumeration list | Curated-table: stable, well-known sensitive paths; risk-tier assignment (`.env`=critical, `/admin`=high) is conventional and sound. | justified | Keep; conventional sensitive-path set. |
| Body sanity `len(text) < 10` and `head = text[:300]` / `[:200]` / `[:50]` slices | L1138-1143 | Rejects trivial/error bodies | Arbitrary slice constants (10/300/200/50): pragmatic body-shape checks; risk is a marginal real exposure with a tiny body being missed (false-negative, safe). `404` in first 50 chars could rarely reject a legit file whose body starts with "404". | fragile | Document the slice thresholds; consider matching `404`/`not found` as standalone tokens rather than naked substrings to avoid rejecting a real file literally containing "404…". Low priority. |
| `max_workers=3`, `as_completed timeout=90`, `HTTP.discover timeout=6` | L1156,1159,1117 | Concurrency/wall/probe budgets | Arbitrary-but-justified: documented (SCN-025) as rate-limiter-paced (2 req/s); 90s wall sized to ~38 probes. Operational, not a scoring signal. | justified | Keep (documented rationale present). |

---

## Summary

total=33 justified=18 fragile=10 arbitrary=3 calibration-gated=5

(Counts assign each row its single primary class; the 5 calibration-gated rows
are the SSL grade-deduction set, SSL grade bands, email score set, email-hardening
score set, and the HTTP-header weights + CSP quality constants — all flagged for
FIN-9, none retuned here.)

### Top 3 concerns

1. **NEW DATA-QUALITY BUG — SSL cipher `bits` substring (L160).** `256 if "256"
   in name` matches the `SHA256` hash suffix, so the fixture's `AES_128_CCM_SHA256`
   is reported as **256-bit** (it is AES-128). Not scored today, but it is
   rendered and would mislead an underwriter. Free fix: parse the AES key length
   from the cipher token, not the whole name (or use sslyze's key size).

2. **Loose-substring family (fragile, not yet caught by Waves 1-5).** Three
   ubiquitous-substring reads survive: SPF `"all" in txt` (L423) flags validity on
   any incidental "all"; WAF **body** markers (`"cloudflare"`/`"sucuri"` in page
   text, L929) can fabricate a WAF-positive → phantom WAF scoring bonus; and WHOIS
   privacy keywords matched against the whole WHOIS blob (L1060). All three are
   the same back-test failure mode (generic/incidental string read as a signal)
   and all have free word-boundary / error-page-fingerprint fixes.

3. **Calibration-gated scoring constants (flag only).** Every SSL `ded` value,
   the email 0-10 deltas, the email-hardening +4/+2/+1 bonuses, and the HTTP-header
   weights / CSP-quality base+bonuses are unanchored magic-numbers that flow into
   the category risks (`ssl_risk`/`email_risk`/`header_risk`). Two value-judgements
   to raise with the calibrator: the email **DKIM −2** penalises a probe-miss as
   proof-of-absence (selectors are unbounded — a real DKIM on an uncommon selector
   is mis-scored), and **BIMI weighted near DANE/MTA-STS** scores a brand feature
   like a security control. FLAG for FIN-9; do not intuit new values.

### Confirmed-clean Wave 1-5 fixes (re-screened)
SSL sslyze-6.x cert API + re-`raise` (no fake "Invalid"); DKIM `v=DKIM1`/`p=`
gate (kills wildcard-TXT false positive); Exposed-Admin 200-only + body sanity
(no 403 inversion); HTTP-headers non-2xx `unreachable` guard (no WAF-403 penalty);
WAF F5 marker pruning (no XFO/`ts` ubiquitous-header inversion). All verified
against `phishield_live.json`.
