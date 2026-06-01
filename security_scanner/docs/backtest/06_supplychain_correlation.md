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
