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
