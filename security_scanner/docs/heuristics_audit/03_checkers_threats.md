# checkers_threats.py — Heuristics Audit

Module: `checkers_threats.py` (+ `darkweb_providers.py`). White-box Step-6 sweep
of the Card Verification Protocol (`docs/card_verification_protocol.md`). RESEARCH
ONLY — no code changed.

**Scoring-flow context (grounds the classification):**
- Every checker's `score` (0-100) is inverted (`inv = 100 - score`) and folded into
  **RSI** through `WEIGHTS` in `scoring_analytics.py` (e.g. `dehashed` 0.03,
  `fraudulent_domains` 0.04, `shodan_vulns` 0.07, `tech_stack` 0.05, `virustotal`
  0.05). So a checker's internal penalty deltas are RSI magic-numbers ⇒ **calibration-gated**.
- `CredentialRiskClassifier.classify()` `risk_level` feeds **p(breach)** directly
  (`scoring_analytics.py` ~L1029: CRITICAL +0.20, HIGH +0.15, MEDIUM +0.08 to base
  probability). Its internal `risk_score` deltas (-50/-20/-30/-15/-10/-3) are the
  5L/FIN-9 credential→p(breach) refactor target ⇒ **calibration-gated, DO NOT intuit**.
- `HudsonRockChecker.score`, `IntelXChecker.score`, `DehashedChecker.score` are
  scored. `BreachChecker`, `HIBPBreachMetadata`, `SecurityTrailsChecker`,
  `GlasswingPartnerChecker` narrative are largely reporting-only / informational.

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| **EOL_SIGNATURES** table (~45 rows, "refreshed 2026-06-02") | TechStack L20-67 | Substring-match header/body for EOL product/version → critical/high/medium | **Stale-table risk** (the exact failure mode the protocol calls out: EOL dates silently age). Refresh-dated, which is good, but no automated drift test. Also substring `"php/7.1".lower() in combined` will match `"php/7.10"` and `"php/7.12"` substrings (false EOL on a *newer* branch) | fragile | Add a drift test asserting refresh-date < N months (mirror Wave-5 vendor-DB drift test). Anchor version tokens with a boundary so `7.1` ≠ `7.10`. |
| EOL penalty deltas **-40/-25/-10** (critical/high/medium) | TechStack L117-121 | Score deduction per EOL hit | Feeds RSI via `tech_stack` 0.05. No empirical basis cited | calibration-gated | Flag for FIN-9 with KEV/DBIR EOL-exploit anchors; don't intuit. |
| X-Powered-By disclosure **-5** | TechStack L108 | Info-leak penalty | Reporting-grade signal scored as risk; small | calibration-gated | Flag for FIN-9 (minor). |
| jQuery `<3.5.0` **-15**, AngularJS EOL **-10** | TechStack L172,180 | JS-lib version penalty | CVE-2020-11022 is real; the *delta size* is unanchored | calibration-gated | Cite CVE; flag delta for FIN-9. |
| jQuery version regex `parts[0]<3 or (==3 and parts[1]<5)` | TechStack L168 | "below 3.5.0" test | Justified (correct semver gate) | justified | Documented. |
| **CMS_SIGNATURES** substrings (WordPress `/wp-content/` etc.) | TechStack L69-78, WebSec L250-258 | Detect CMS from body/header substrings | Loose-substring risk: `squarespace.com`/`shopify.com` appear in any embedded asset/CDN link → false CMS attribution. Reporting-only (not scored) so low blast radius | fragile | Constrain to generator-meta or first-party host; document as reporting-only. |
| **HIBP** `breach_count = len(breaches)` + `most_recent = max(dates)` | Breach L216-229 | Count + recency from HIBP domain breaches | Clean — real list length, real max-date. No boolean-as-count | justified | Documented. |
| **CVSS severity cut-offs** 9.0/7.0/4.0 | Shodan `_cvss_severity` L451 | Map CVSS base → critical/high/medium/low | Justified — standard FIRST CVSS v3 bands | justified | Documented (industry standard). |
| `easily_exploitable` = AV:N & AC:L & PR:N | Shodan L489 | CVSS-vector exploitability gate | Justified — robust vector parse, not a magic number | justified | Documented. |
| EPSS thresholds **>0.5** (high), **>0.4 / pct>0.9** (widely exploited) | Shodan L755,777 | EPSS-based flags | 0.5/0.4 are conventional EPSS triage cut-offs but uncited here; not directly scored (drive issues text + RSI via `score`) | fragile | Cite FIRST EPSS guidance (≈0.1 default actionable; 0.5 is conservative); document rationale. |
| CVE caps: **`[:20]` raw, `[:10]` enriched, `[:30]` EPSS batch** | Shodan L546,568,653,730,744 | Limit CVE enrichment volume | **Silent under-count + inconsistency:** raw list capped 20, only first 10 enriched, remainder dumped to `medium_count` (L825-826) regardless of true severity → can both over- and under-state. The `>10` tail being forced to "medium" is an arbitrary fabrication of severity | fragile | Document the cap; at minimum don't relabel un-enriched CVEs as "medium" — count them as `unknown`. |
| Severity penalty **crit×30 + high×15 + med×5**, `min(100,·)` | Shodan `check` L947-950 | Score from CVE counts | Feeds RSI via `shodan_vulns` 0.07 | calibration-gated | Flag for FIN-9. |
| **RANSOMWARE_CVE_MAP** (~35 rows), **ATTACK_TECHNIQUE_MAP** (~15) | Shodan L670-721 | Tag CVE→ransomware family / ATT&CK | Stale-curated-table: hand-maintained, no source date, will drift as new CVEs are weaponised. Reporting/narrative (drives issues text, not a separate weight) | fragile | Add a "last reviewed" date + periodic-refresh note; document as illustrative not exhaustive. |
| Patch-mgmt age bands **365 / 180 / 90** days | Shodan L844-846,883-888 | Bucket CVE age; warn >365/>180 | Recency-band cut-offs are reasonable patch-SLA conventions but uncited | fragile | Cite a patch-SLA reference (e.g. CISA BOD 22-01 KEV due dates); document. |
| KEV/MSF/ExploitDB caches **86400s TTL** | Shodan L574,594,618 | 24h cache of feeds | Justified — feeds change daily | justified | Documented. |
| `exploit_maturity`: KEV/MSF→weaponized; EDB/EPSS>0.5→poc | Shodan L763-770 | Maturity classification | Justified gate (real feed membership), not magic | justified | Documented. |
| **OSV CVSS-vector approximation** base=5.0 +1.5/+1.0/+0.5… | OSV `_parse_vulns` L1104-1111 | *Invents* a CVSS score from vector when none given | **Fabrication on absent input** — synthesises a numeric severity the source never stated; arbitrary additive weights with no CVSS-spec basis | arbitrary | Remove the synthetic score; fall back to `database_specific.severity` or mark `unknown`. Do not fabricate CVSS. |
| OSV pre-2015 advisory drop | OSV L1122 | Skip advisories published <2015 | Arbitrary recency cut — silently hides genuinely-old-but-live vulns | arbitrary | Document rationale or gate on "fixed/affected version match" instead of publish-year. |
| OSV default severity `"medium"` | OSV L1077 | Fallback when no CVSS/db-sev | Fabrication-lite: unknown rendered as "medium" → inflates RSI tail | fragile | Default to `unknown`, not `medium`. |
| **HASH_PATTERNS** regexes (bcrypt/argon2/SHA-*/MD5/NTLM); MD5≡NTLM both 32-hex | Dehashed L1167-1176 | Identify hash type from string | Justified regexes; the **NTLM==MD5 collision is acknowledged in-code** and can mis-bucket NTLM as MD5 (both `WEAK`, so net-harmless to the weak/strong split) | justified | Documented (collision noted; harmless because both weak). |
| Dehashed penalty **plaintext×5 + weak×3 + strong×1 + other×2**, `min(100,·)` | Dehashed L1376-1377 | Score from credential breakdown | Feeds RSI via `dehashed` 0.03. Wave-3 fixed the case-double-count; the *delta sizes* remain unanchored | calibration-gated | Flag for FIN-9 (plaintext vs hashed severity ratio). |
| `staff_accounts_masked[:60]`, `sample_emails[:5]`, `breach_details[:20]` | Dehashed L1328-1339 | Display caps | Justified display bounds; counts (`staff_accounts_total`) computed on full set, not the cap | justified | Documented. |
| **VirusTotal** penalty `mal×10 + sus×5`, `min(100,·)` | VirusTotal L1495 | Score from engine detections | Feeds RSI via `virustotal` 0.05. Real counts (not boolean), but delta unanchored | calibration-gated | Flag for FIN-9. |
| VT bad-category substrings (`malware/phishing/spam/scam`) | VirusTotal L1488 | Issue text from categories | Reporting-only substring match; low risk | justified | Documented. |
| **SecurityTrails** "associated > 50" shared-hosting flag | SecurityTrails L1595 | Issue text when >50 associated domains | Arbitrary threshold, reporting-only (not in WEIGHTS at 0.01 it barely scores via `score`=100 always here — note: ST `score` never decremented, stays 100) | arbitrary | Document the 50 cut-off or derive from distribution; note ST score is inert. |
| **HudsonRock** penalties **emp×30, user×10, 3p×5** | HudsonRock L1695-1707 | Score from infostealer counts | Real counts (not boolean). Feeds credential_risk + RSI. Active-compromise = strongest p(breach) driver | calibration-gated | Flag for FIN-9 (the 30/10/5 ladder). |
| HR `data.get("employees",0) or 0` etc. | HudsonRock L1650-1652 | Null-safe count extraction | Clean — `or 0` only guards null, doesn't fabricate (no `or 1`) | justified | Documented. |
| HR `days_since_compromise` (no recency *gate*) | HudsonRock L1671-1674 | Computes age but does **not** down-weight stale infections | **Gap (OUTSTANDING §6 date-gate-HR ticket):** a 3-year-old infostealer hit scores identically to a fresh one; protocol step-2 recency not enforced in scoring | calibration-gated | Flag for FIN-9 + §6 ticket: apply a recency decay/gate to HR contribution. Don't intuit the curve. |
| **KNOWN_BREACH_DATES** (10 combo-list dates) | CredRiskClassifier L1817-1828 | Fallback dates for non-HIBP combo lists | Stale-curated-table; small + slow-moving, used only for display/recency band | fragile | Add review-date comment; document as best-effort. |
| Cred-risk **risk_score deltas -50/-20/-30/-15/-10/-3** | CredRiskClassifier L1847-1940 | Per-factor credential risk_score deductions | **Core 5L/FIN-9 target.** Also `darkweb×10` and `pastes×3` are **uncapped per-mention** (40-record IntelX cap ⇒ up to -400, floored at 0 — saturates instantly) | calibration-gated | **DO NOT intuit.** Flag whole ladder for FIN-9; note darkweb/paste per-mention multipliers need a cap or log-scale. |
| Recency band **year ≥ 2023 = "recent"** | CredRiskClassifier L1925 | Split breaches recent vs old | Hardcoded calendar year — silently ages (2023 becomes "3 years stale" by 2026); should be relative (now − N days) | fragile | Replace fixed year with rolling window (e.g. <24 months); document. |
| `pastes > 3` gate | CredRiskClassifier L1871 | Threshold for paste factor | Arbitrary, inconsistent with IntelXChecker's `paste_count > 5` (L2102) | arbitrary | Reconcile the two paste thresholds; document one rationale. |
| **IntelX MAX_RESULTS = 40** + over-return truncation | IntelX L1989,2066-2068 | Cap + truncate (free API over-returns) | Justified — Wave-3 fix, reproducible bound, documented in-code | justified | Documented (clean). |
| **_STEALER_TOKENS** + bucket `darknet/logs/stealer` darkweb-grade gate | IntelX L1996-2013; mirrored darkweb_providers L106-122 | Reclassify generic-text stealer dumps as darkweb | Loose-substring risk: tokens like `"autofill"`, `"screenshot"`, `" default.txt"` could match benign filenames; but conservative and reporting-grade. Bucket gate is sound | fragile | Document false-positive surface; consider requiring token **and** a leak/log bucket. |
| IntelX media map `1,2=paste; 13=darkweb; 5=email` | IntelX L2073-2075 | Media-type classification | Justified — IntelX documented codes | justified | Documented. |
| IntelX penalty **darkweb×15, paste×3** (`paste_count>5`) | IntelX L2096-2103; darkweb_providers L396-405 | Score from counts | Feeds RSI; unanchored deltas, but bounded by 40-cap (max -600 → floor 0) | calibration-gated | Flag for FIN-9; note bound. |
| IntelX poll: `sleep(3)` + 3×`sleep(2)`, statuses `(1,2,4)` | IntelX L2048-2060 | Two-step search poll | Justified — matches IntelX async protocol | justified | Documented. |
| **FraudulentDomain HOMOGLYPHS / IDN_HOMOGLYPHS / KEYBOARD_ADJ** maps | FraudDomain L2139-2173 | Generate typosquat permutations | Justified (Wave-5 IDN fix confirmed clean); high-confidence, one-sub-per-candidate | justified | Documented. |
| IDN cap **12**, permutation check cap **60**, display cap **20** | FraudDomain L2261,2290,2313 | Bound candidate explosion / memory | Justified low-footprint bounds; but `[:60]` truncates *before* DNS check, so resolved-count is capped by generation order not by reality (a real lookalike past index 60 is missed) | fragile | Document the 60-cap as a known recall ceiling; consider ordering high-similarity techniques first. |
| `_split_domain` multi-TLD set `(co,com,org,net,ac,gov)` | FraudDomain L2178 | Handle `.co.za` etc. | Justified for SA market; could miss `.gov.za`/`.web.za` edge TLDs | justified | Documented (SA-appropriate). |
| Similarity %s **90/95/85/80** per technique | FraudDomain L2196-2259 | Display-only similarity score | Cosmetic, not scored | justified | Documented (display heuristic). |
| FraudDomain penalty `resolved×8`, `min(100,·)`; issue bands `>5/>2/>0` | FraudDomain L2315-2333 | Score + issue tiers from resolved count | Feeds RSI via `fraudulent_domains` 0.04. Unanchored delta + bands | calibration-gated | Flag for FIN-9. |
| **Glasswing PARTNERS** static list (12) + `score_bonus 10/10/5` | Glasswing L2682-2743 | Favourable-signal bonus (RSI reduction) | Stale-curated-table (April-2026 snapshot). HTML `"glasswing"+"anthropic"` probe is a loose-substring positive-signal-from-page-content — but bonus is small & favourable | fragile | Add refresh-date enforcement; document the substring probe's FP surface. score_bonus → FIN-9. |
| **WebRanking Tranco** bands `≤1000→100, ≤10k→90, ≤100k→70, else 50`; not-listed→30 | WebRanking L2641-2652 | Popularity→score | Inverted-meaning concern: high popularity = *higher* score (treated as protective) yet popular = bigger target; semantics debatable. Bands arbitrary | calibration-gated | Clarify whether ranking should raise or lower risk; flag bands for FIN-9. |
| **InfoDisclosure** `_probe`: HEAD→GET, **200-only + len≥10 + not "404"/"not found"** | InfoDisc L2791-2808 | Sensitive-file probe | **Reference-grade gate** (the S-3 `_probe` pattern the protocol endorses) — guards against WAF/CDN 200 catch-alls and custom-404 false positives | justified | Documented (model pattern). |
| InfoDisc penalties **critical×20, medium×10, dir-listing −15** | InfoDisc L2824-2873 | Score from exposed paths | Feeds RSI via `info_disclosure` 0.05 | calibration-gated | Flag for FIN-9. |
| **PrivacyCompliance** `_probe`: HEAD→GET 200 + body≥500 | Privacy L2488-2503 | Policy-page discovery | Justified robust gate (body-sanity, avoids WAF 200) | justified | Documented. |
| Privacy REQUIRED_SECTIONS keyword lists (10 sections) | Privacy L2362-2400 | Section-presence via keyword substring | Loose-substring: `"child"`/`"update"`/`"contact us"` are extremely common, will false-positive "section present" on almost any page → over-states compliance % | fragile | Tighten keywords or require ≥2 distinct hits per section; document. |
| Privacy `compliance_pct → score` (= score) | Privacy L2565,2583 | Score = % sections found | Compliance % drives `privacy_compliance` 0.02 weight; the keyword fragility above propagates here | fragile (gate) / calibration-gated (weight) | Harden keywords (above); weight delta → FIN-9. |
| **PaymentSecurity** self-hosted-form regex `card.?number…` on 200 page | Payment L380-417 | Detect self-hosted card form (PCI risk) | Generic-response risk partly mitigated (checks payment keywords first), but probes 9 paths with `timeout=4` and no HEAD/WAF gate; a 200 catch-all + keyword could false-positive | fragile | Route through the `_probe`/HTTP-client pattern used elsewhere; document. |
| `darkweb_providers` Snusbase/LeakCheck table-name substrings (`STEALER/LOG/MALWARE`, `darknet/combolist`) | darkweb_providers L201-253 | Map provider table → darkweb/leak/paste | Loose-substring on provider-controlled names; reasonable but provider-dependent and unverified live (no key in fixture) | fragile | Verify against each provider's real table/origin vocabulary before enabling in prod; document. |

## Summary
total≈42 heuristics catalogued.
**justified=15, fragile=15, arbitrary=4, calibration-gated=13** (several rows carry a
fragile *gate* + a calibration-gated *weight* — counted under their dominant class;
the 4 explicit `arbitrary` are the OSV synthetic-CVSS, OSV pre-2015 drop, ST ">50"
shared-hosting cut, and CredRisk `pastes>3` inconsistency).

**Top 3 concerns**
1. **OSV synthetic CVSS fabrication** (`_parse_vulns` L1104-1111) — invents a numeric
   severity from a vector when the source gives none, with arbitrary additive weights.
   This is the exact "fabrication on absent input" failure mode and it propagates into
   `shodan_vulns`/CVE risk. **Bucket-2 free fix:** fall back to `database_specific.severity`
   or `unknown`; never synthesise a CVSS score.
2. **Stale-curated-table drift** across EOL_SIGNATURES, RANSOMWARE_CVE_MAP,
   KNOWN_BREACH_DATES, Glasswing PARTNERS — all hand-maintained, only EOL is
   refresh-dated, none has an automated drift test. **Bucket-1 free fix:** add a
   refresh-date assertion test (clone the Wave-5 vendor-DB drift test) + boundary-anchor
   the EOL substring so `7.1`≠`7.10`.
3. **Calibration-gated credential/p(breach) ladder** — CredentialRiskClassifier
   `-50/-20/-30/-15/-10/-3` plus **uncapped** `darkweb×10`/`paste×3` per-mention, the
   HR `30/10/5` ladder, and the **un-gated HR recency** (days_since_compromise computed
   but never applied). These drive p(breach) (CRITICAL +0.20) and are the precise
   5L/FIN-9 scope. **FLAGGED for FIN-9 — do not intuit;** the only free pre-FIN-9 note
   is that the darkweb/paste per-mention multipliers need a cap or log-scale, and the
   "year ≥ 2023" recency band should become a rolling window.
