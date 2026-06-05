# Cat-Modelling Redesign — Wiring Spec + Session Handoff (2026-06-04)

**Status:** ALL calibration LOCKED (deterministic, data-anchored). Cat-modelling redesign fully
specified below but **NOT yet wired into the real FIC** — this doc is the wiring spec for the next
(supervised) session. **NOTHING SHIPPED** — sandbox worktree `blissful-chandrasekhar-0714c9`, all
uncommitted. The compound-aggregation refactor was deliberately NOT executed autonomously (too subtle
to do + verify within the prior session's remaining context budget; clean spec > half-done refactor).

---

## 1. LOCKED decisions (value · anchor)

| Item | Locked value | Anchor |
|---|---|---|
| **Base rate (LEF)** | **0.30** + convex vuln curve **k=1.8** | Cyentia IRIS: midpoint score → 8.6% ↔ 9.3% all-org; clean → 1.2–1.7% ↔ SMB <2%; worst → 30% ↔ F1000 ~25% |
| **Aggregation** | **Compound** (loss-given-event), NOT prob-weighted | tail must reflect a *realised* event, not a prob-scaled one; stops collapsing with posture |
| **C1 (cat)** | **records-driven stand-alone**: records_held × ~100% exposure × **~R90/record** × lognormal(σ=**0.25**), floored at central residual | exposure ~100% (Yahoo/CapOne/Marriott/Optus = full DB incl. historical); R90 = intl class-action (Anthem R27/CapOne R33/Equifax R53 settlement + legal/monitoring ≈ 5.5% of IBM all-in) |
| **C1 (central)** | stays the **residual** `max(0, anchor − C2..C5)` | a real central loss can legitimately floor a bucket |
| **C2 POPIA** | E[fine]=**R5m** × P(fine)=**0.02** = **R100k** expected; **R10m** cat ceiling | both actual fines (DoJ-2023, DBE-2024) = R5m; P(fine) record-anchored (0 private, recalcitrance-driven) |
| **C3 BI downtime** | **PERT(2,14,90)** (mode 14 / mean ~25 / max 90); IMPACT 0.5; bi_factor unchanged | Coveware avg ~24d; good-IR ~2wk; 90 = indemnity cap. bi_factor is rating-engine-derived → keep; gross-profit reconciliation deferred to the rating-engine project |
| **FIN-9** | **RETIRED** — no α/mix_w/f_sc in the loss number | SC severity already in records-driven C1 (vector moves probability, not severity); systemic SC catastrophe is disclosed-not-modelled (SA Covid-BI precedent) |
| **Supply-chain** | **probability uplift only** (`supply_chain_vulnerability_uplift`) + a systemic-exposure **disclosure** | one-signal-one-channel |
| **K3 combo discount** | **flat 0.3** | credential-stuffing ~1–3% validity; recency-on-publication rejected (publication ≠ credential age) |

bi_factor reachability for big clients is being verified by background task #13 (sub-industry taxonomy
→ `_bi_factor_data.json` keys; takealot must map to **eCommerce 1.5**, not the Consumer 1.0 fallback).

---

## 2. #14 WIRING SPEC — exact, ordered changes to `scoring_analytics.py` `_calculate_zar`

**Use the CRLF-safe mutator pattern** (file is CRLF — see `tooling/_apply_item07/08/09*.py`: read utf-8,
assert no `\r`, assert `count==1` per anchor, replace, write `s.replace("\n","\r\n")`). Do NOT hand-edit
CRLF with the Edit tool. Validate each against the prototypes in `tooling/_proto_*.py`.

**A. Compound aggregation (the big one).** Currently the MC accumulates `mc_p × severity` per scenario
(`mc_breach_total += mc_p*(mc_c1+mc_c2)`, etc., ~L2524–2575) and return periods = percentiles of
`mc_total`. CHANGE so each iteration draws a **Bernoulli event occurrence** per scenario (`np.random.random(N) < scenario_prob`)
and on occurrence adds the **FULL** severity (not prob×severity). KEEP `most_likely`/`total_expected`
(from the `incidents` dict, ~L2466–2477) UNCHANGED — the compound MEAN equals it, so the remediation
card is preserved. Only `return_periods` (P99/P99.5/P99.6) switch to the compound realised-annual-loss
distribution. Ref: `_proto_compound_tail.py` (mean flat, 1-in-250 stops collapsing with posture).

**B. Records-driven cat-C1.** Replace `mc_c1 = np.maximum(0, mc_total_breach - mc_c2 - mc_c3_full - mc_c4 - mc_c5)`
(~L2521) with: `mc_c1 = np.maximum(records_held * 90.0 * np.random.lognormal(0, 0.25, N), residual_floor)`
where `records_held = estimated_records` (revenue/divisor — note: should become *total records held incl.
historical*; client-override is a future input) at ~100% exposure, and `residual_floor` = the old residual.
Keep the CENTRAL `c1_liability` (~L2342) as the residual. Per-record R90 ≈ `cost_per_record × ~0.057` —
document as the international class-action anchor, not a fraction of IBM. Ref: `_proto_catC1.py`,
`_proto_cattotal.py`, `_proto_exposed_fraction.py` (takealot eCommerce → total cat ~R4bn).

**C. BI downtime.** Change `mc_dt = self._pert_sample(3, SA_AVG_DOWNTIME, 120, N)` (~L2517) →
`self._pert_sample(2, 14, 90, N)`. Keep `SA_AVG_DOWNTIME = 25` (≈ new mean 24.7) for the central c3_bi.
Ref: `_proto_bi_downtime.py`.

**D. Remove FIN-9 severity.** Delete the `_apply_item08` additions (FIN9_F_SC/MIX_W/ALPHA, `_fin9_heavy`,
`_fin9_delta`, `mc_breach_total += _fin9_delta`, `mc_total += _fin9_delta`, the `fin9_lgb_tail` dict and
its result-dict surfacing). Replace with a `systemic_supply_chain_exposure` DISCLOSURE block (a flagged
note in the result dict — NOT a loss contribution). Keep `supply_chain_vulnerability_uplift` (probability).
`sc_tail_adj` stays `applied=False`.

**E. POPIA P(fine).** Change `POPIA_P_FINE_GIVEN_BREACH = 0.03` → `0.02` (record-anchored; update the
comment from "colleague-gated" to the DoJ/DBE record basis).

**F. bi_factor / TEF / credential K-model / SA costs.** UNCHANGED (locked in the dry-run / this session).

**G. Manual** (`manual_parts/part5_tech_compliance_insurance.py`): drop in the methodology paragraphs
(drafted verbatim in the session transcript — C1 records-driven cat-liability w/ class-action anchors;
compound loss-given-event; BI downtime PERT(2,14,90); POPIA C2; systemic-SC disclosure; base-rate LEF
Cyentia anchor; K3 combo). Then `py generate_manual.py` + doc-quality audit (12 rules — see
Local-Only `feedback_document_quality.md`; third-person, anchored, no intuited numbers).

**H. Gate.** The structural changes WILL shift the wiring verifier's hardcoded expected deltas →
**re-baseline `tooling/verify_supply_chain_financial_wiring.py`** to the new compound numbers, then it +
`tooling/verify_scan_smoke.py` (exit 0). Confirm end-to-end via `tooling/_calib_recompute.py` on phishield
(R10m FS) and takealot (R20bn — pass `--industry "eCommerce"` or wire `_sub_industry`): expect phishield
1-in-250 to *hold* (not collapse) and takealot total cat ~R4bn.

---

## 3. Task state
- **#12** done — exposed-record fraction locked.
- **#13** DONE — sub-industry is a FIXED dropdown (`templates/index.html` SUB_INDUSTRIES), label written verbatim, read raw (no normalization) into the exact-match lookup. NOT 1:1: 51/87 labels match → **36 silent fallbacks** to coarse industry-level (labels are *shortened* SIC names). **SAFE: eCommerce 1.5 / Depository Institutions 1.75 / General Merchandise Stores 1.25 / Food Stores 1.25 all match → takealot→eCommerce 1.5 IS reachable.** Silently under-rated: Automotive Dealers, Building Materials/Hardware, Home Furniture (all should be 1.25). **NEW FIX (supervised, separate from the wiring): align the dropdown labels to the bi_factor keys, or add a normalization/alias map.**
- **#14** DONE (2026-06-04) — wiring executed in sandbox worktree `blissful-chandrasekhar-0714c9` (all uncommitted, NOTHING SHIPPED). See §7 Execution record below.
- **#15** done — all four gated inputs locked.
- **#16** pending — consolidate design note (this doc largely is it).

## 4. Reference prototypes (`security_scanner/tooling/`)
`_proto_compound_tail.py` (A) · `_proto_catC1.py`,`_proto_cattotal.py`,`_proto_exposed_fraction.py` (B) ·
`_proto_bi_downtime.py`,`_proto_bi_conditional.py`,`_proto_impact_factor.py` (C/BI) · `_calib_recompute.py` (recompute harness).

## 5. Memory (already saved)
- `project_financial_model_anchoring_mechanism.md` — the 4-channel + systemic-disclosure rule for ALL new cards (NEW).
- `project_sophos_partnership.md` — Phase-2 two-tier set (records-override / beacon / conditional-downtime) + contingent-BI deferral.
- `project_fin9_pareto_calibration_flagged_2026-06-03.md` — dry-run + cat-redesign context + bi_factor/rating-engine project + sub-industry finding.

## 7. Execution record — #14 wiring (2026-06-04, sandbox, NOTHING SHIPPED)

Executed in worktree `blissful-chandrasekhar-0714c9` (the dry-run base that already
carries items #02-#13). All changes uncommitted. Applied via CRLF-safe mutators
(`tooling/_apply_item14_cat_wiring.py`, `_apply_item14_manual.py`,
`_apply_item14_verifier_note.py`); `scoring_analytics.py` stayed pure CRLF (AST OK).

**A (compound tail)** — kept the prob-weighted per-category accumulators intact (they
still drive expected/median/CI/per-category). Added a separate COMPOUND
`mc_compound_total` (Bernoulli occurrence per scenario → FULL severity), placed after
all prob-weighted draws so those arrays are unchanged. `return_periods` and
`loss_exposure.return_1_*` now read `mc_compound_stats` (P99/P99.5/P99.6). The WAF
blind-spot `cov_adj` block now also widens the compound tail (so a blinded scan still
loads the cat rows). Full compound distribution surfaced under `monte_carlo.compound_total`.
**B** — `mc_c1 = max(records_held * 90.0 * lognormal(0,0.25), residual_floor)`, `records_held = estimated_records`.
**C** — `mc_dt = _pert_sample(2,14,90)`; central `SA_AVG_DOWNTIME=25` kept.
**D** — FIN-9 block + `fin9_lgb_tail` removed entirely; replaced by
`systemic_supply_chain_exposure` disclosure (modelled_as_loss=False). `sc_tail_adj`
stays applied=False; `supply_chain_vulnerability_uplift` untouched. Stale FIN-9
"conditional LGB Pareto" note in `manual_parts/part4_exposure.py` retired.
**E** — `POPIA_P_FINE_GIVEN_BREACH = 0.02` (record-anchored DoJ-2023 / DBE-2024).
**G** — methodology paragraphs added to `manual_parts/part5_*` (records-driven C1,
POPIA expected-fine, BI PERT(2,14,90), compound aggregation, systemic-SC disclosure,
convex curve + 0.30 LEF Cyentia anchor, K3 0.3 credential-combination). `py
generate_manual.py` OK (no-blank-pages assert passed); paragraphs verified in the docx.

**Gate (step H):**
- `verify_supply_chain_financial_wiring.py` → **31/31 PASS**. NO numeric re-baseline
  needed: the assertions are RELATIVE (directional / min-delta), and the compound tail
  still moves under SC injection (vendor_breach fin_p99 +0.2% ≥ 0.1%; worst_stack
  fin_p99 +19.0% ≥ 5%). A one-line note documents the compound switch.
- `verify_scan_smoke.py` → **exit 0** (example.com, 55.3s, 41 categories).

**Calib recompute (`tooling/_calib_recompute.py`, harness now takes `--sub-industry`):**
- phishield R10m FS (score 164): 1-in-250 = **R27.1m**, and it **HOLDS** with posture
  (`_verify_item14_compound_hold.py`: most_likely R2.15m→R751k = 2.86× drop as score
  700→165, but 1-in-250 R39.4m→R27.1m = only 1.45×, vs ~13.5× collapse under the old
  prob-weighted tail). C2 = R100k (= 0.02×R5M).
- takealot R20bn eCommerce (bi 1.5 via `--sub-industry "eCommerce"`): total cat
  1-in-250 = **R2.88bn** (C3/BI-dominated). This is below the ~R4bn target **because the
  spec locks `records_held = estimated_records`** = revenue/divisor ≈ 400k records (the
  "Ecommerce"→Other divisor 50 000), so cat-C1 is small (~R36m) and the proto's ~R4bn
  assumed the 10m client-records OVERRIDE — exactly the deferred "total records held
  incl. historical" input in §6. Consistent with the locked design; reaches ~R4bn once
  the records-override field lands.

## 6. Deferred (NOT this wiring)
- Phase-2 verified-input set (records-override field, beacon signal, conditional managed-downtime) → Sophos/continuous-monitoring phase.
- Automated corporate **rating-engine project** (owns the BI gross-profit reconciliation; bi_factor absolute-level re-check).
- Records input → "total records held incl. historical" (data-retention/minimisation; the active-base estimate understates large consumer orgs).
- **Contingent BI** (vendor/OSP outage; sublimit 50% of BI cover) → Phase-2, needs client input.

## 8. Post-#14 design evolution (2026-06-05, sandbox, NOTHING SHIPPED) — items #15/#15a/#16

Continued in the same worktree (`blissful-chandrasekhar-0714c9`), all uncommitted, CRLF-safe
mutators. Driven by a design conversation that re-framed the whole output around the FAIR
decomposition. **The three report outputs now map 1:1 to FAIR:** `LM`→cat, `LEF`→probability,
`LEF×LM`→expected loss.

**Applied to `scoring_analytics.py` (gate 28/28 + smoke exit 0):**
- **#15 Cat → severity-PML** (`_apply_item15_cat_pml.py`): return periods are now the SEVERITY of a
  single severe (double-extortion full-stack) event — `mc_pml_severity = mc_c1+mc_c2+mc_c4+mc_c5+mc_c3_full`
  — **posture-INDEPENDENT** (flat across the whole score range; verified delta=0 under SC injection).
  Compound retained under `monte_carlo.compound_total` for audit. **Semantic:** these are severity
  percentiles CONDITIONAL on a severe event, NOT literal annual return periods (disclosed in-code).
- **#15 verifier re-baseline** (`_apply_item15_verifier_rebaseline.py`): SC probability signals
  correctly no longer move the cat; dropped the SC→fin_p99 assertions, ADDED a positive invariance
  lock ("fin_p99 invariant under SC stack"). Kept SC→ALE + score assertions.
- **#15a cover_ladder** (`_apply_item15a_cover_ladder.py` + `_apply_item15a2_ladder_upper.py`):
  client-facing cover tiers use the USEFUL spread P50/P95/**P99.6 (1-in-250, the std reinsurance/SAM
  benchmark)** because the top percentiles compress to ~7%. `return_periods` keeps P99/P99.5/P99.6 for
  audit. phishield R13.0m/R26.6m/R34.3m; takealot R0.99bn/R2.24bn/R2.91bn.
- **#16 Arch 2 — ALE cooled to FAIR-consistent** (`_proto_item14b_fair_rw.py`, NOW APPLIED not reverted):
  ransomware legs use a proper FAIR LEF `p_ransomware = rsi_score × 0.30` (reuse breach LEF; NO extra
  TEF — rsi already carries a modest industry/size tilt, avoids double-count), partitioned by
  conditional shares. ALE now aligns with the reported breach probability (no "warm" inconsistency).
  phishield ALE R750k→**R390k** (3.90%); takealot R192m→**R95.3m** (0.48%). Breach prob unchanged
  (always FAIR): phishield 1.68%, takealot 2.21%.

**Locked design decisions (colleague session done 2026-06-04; these are the implementation):**
- **Architecture 2 chosen:** cool the ALE (above) + re-portray remediation as **percentile/grade move +
  %-reduction + cat-context** (absolute Rand secondary). Fully internally consistent, no disclosure
  caveat. (Arch 1 — warm ALE + "risk-weighted exposure" disclosure — rejected.)
- **Two probability lines, nested, separately defined:** (1) **Data-breach probability** = `p_breach`
  (already FAIR, 1-3% band); (2) **Total cyber-incident probability** = `1−∏(1−p_channel)` over breach +
  ransomware (FAIR). Total ≥ breach by construction; clear definitions mandatory.
- **Availability = separate resilience-indicator line:** an outage / availability **resilience indicator**
  spanning both DDoS and system / infra-failure causes — described by the RISK it measures, with **NO
  coverage claim**. (Policy coverage of outage/system-failure varies by policy and shifts over time —
  some policies DO cover it — so we do NOT bake a covered/not-covered statement into the definition; the
  risk is what's stable and prevalent.) `p_interruption` is a heuristic → ships as **indicative only, NOT
  a calibrated probability**. Kept as its own line because it is a *different risk type* (availability vs
  breach/extortion), on different signals, and indicative-not-calibrated — NOT on any coverage basis.
- **Segregated bands per metric:** breach = firm public anchors (Cyentia SMB<2%, BitSight, SecurityScorecard);
  total cyber-incident = provisional (~<5 Low/5-15 Typical/15-30 Elevated/>30 High); availability = indicative.
  Reusing the breach band on the total was the bug that mislabelled 8% as "High" — it's Typical.

**Levers we measure (per probability):** breach←whole posture score (all weighted checkers)+TEF;
ransomware←RDP/exposed-DB-ports/credential-infostealer/KEV-CVEs/WAF/SSL (RSI factors)+industry/size;
availability←WAF/CDN/single-ASN/DNSBL.

**REMAINING — card-rules-compliant pass:** the new outputs are **reporting-only**
(new views of already-scored signals — no double-count, the correct one-of-four anchoring channel).
Owed before "done": (1) wire the 2 probability lines + availability(fenced/indicative) + cover_ladder
surfacing + segregated bands into the result dict; (2) **manual lock** — methodology paragraphs for each
new card; (3) **Card Verification Protocol** (render & inspect across tiers → benchmark vs reinsurer →
live takealot → trace render→capture); (4) re-portray the remediation panel (percentile/%/cat); (5)
re-anchor availability `p_interruption` (FAIR-treat) before it is ever a calibrated rate. None of (1)-(5)
touches scoring. `docs/card_verification_protocol.md` + `project_financial_model_anchoring_mechanism.md`
govern.

> **STATUS 2026-06-05 (item #17 autonomous pass, sandbox):** **(1)-(4) DONE**; **(5) still deferred**
> (availability ships INDICATIVE-only this pass, by design — see §9). Execution record below.

## 9. Execution record — #17 card pass (2026-06-05, sandbox, NOTHING SHIPPED)

Same worktree (`blissful-chandrasekhar-0714c9`), all uncommitted, CRLF-safe mutators
(`tooling/_apply_item17_probability_cards.py`, `_apply_item17b_pdf_renderers.py`,
`_apply_item17c_html_renderers.py`, `_apply_item17d_manual.py`). AST/Jinja-validated after each edit.
**REPORTING-ONLY — no WEIGHTS/RSI/severity/tail/p_breach edits.**

- **(1) Result dict** (`scoring_analytics.py`): added `risk_probability` block (3 distinct, separately-
  graded concepts) — `data_breach` (= p_breach, firm bands), `cyber_incident`
  (= 1-(1-p_breach)(1-rsi_score×0.30), nested above breach, provisional bands), `availability_resilience`
  (= p_interruption, INDICATIVE, calibrated=False, no coverage claim). `cover_ladder` already present
  (P50/P95/P99.6) — surfaced. Module-level grade helpers + segregated bands added.
- **(2) Manual lock**: new H2 "Probability and cover reporting views (FAIR decomposition)" in
  `manual_parts/part5_*` — the two probability defs, the availability indicator (risk-described, no
  coverage claim), the cover ladder, segregated bands + anchors, and the remediation re-portrayal.
  Third-person, every number anchored. `py generate_manual.py` OK; 5 paragraphs verified in the docx.
  part4 reviewed — **not relevant** (its probability refs are EPSS/CVE + the already-retired FIN-9 note).
- **(3) Card Verification**: `docs/calibration_prep/08_ITEM17_CARD_VERIFICATION.md` + rendered samples in
  `docs/calibration_prep/item17_samples/` (full+summary PDF + HTML for phishield & takealot). Steps 1-6
  documented; Step-6 sweep: 2 knobs correctly **calibration-gated/flagged** (cyber-incident bands;
  availability), the rest justified. **Exec-deck slide visual integration + final aesthetic sign-off
  left for user review** (3 of 4 tiers wired: HTML + summary PDF + full PDF).
- **(4) Remediation re-portrayal** (`cat_risk_mitigations` PDF + HTML risk-mitigation card): LEADS with
  breach grade movement (e.g. phishield 1.7% Good → 0.26% Strong) + %-exposure reduction (85.0%) +
  posture-independent 1-in-250 cover (R34.27m, "unchanged"); absolute Rand savings demoted to secondary.
  Data in `_build_mitigations` → `remediation_summary`.
- **(5) availability FAIR re-anchoring** — DEFERRED (out of scope this pass; ships indicative-only).

**Gate:** wiring verifier **28/28 PASS**, smoke **exit 0** (50.5s). §8 numbers HOLD: phishield
breach 1.68% Good / cyber 8.14% Typical / cover R34.27m / ALE R390k; takealot breach 2.21% Typical /
cyber 8.96% Typical / cover R2.91bn / ALE R95.3m.
