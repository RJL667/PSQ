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
