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
