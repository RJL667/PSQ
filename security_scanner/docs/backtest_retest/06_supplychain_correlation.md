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
