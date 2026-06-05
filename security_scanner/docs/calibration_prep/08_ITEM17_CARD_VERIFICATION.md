# Item #17 — Card Verification Protocol report (probability cards + cover ladder + remediation re-portrayal)

**Date:** 2026-06-05 (autonomous overnight pass) · **Status:** SANDBOX, NOTHING SHIPPED ·
**Worktree:** `blissful-chandrasekhar-0714c9` (all uncommitted) · **Awaiting:** user ship decision +
final visual/aesthetic sign-off.

This report covers the MECHANICAL steps of `docs/card_verification_protocol.md` for the three new
**reporting-only** cards wired in this pass. The final visual / aesthetic sign-off is deliberately
**left for the morning review** — this pass does not self-approve.

## What was wired (all reporting-only — new VIEWS of already-scored signals; no scoring change)
1. **Data-breach probability card** — `p_breach` (FAIR LEF), graded on the firm public bands
   (<1 Strong / 1-2 Good / 2-3 Typical / 3-6 Elevated / 6-12 High / >12 Critical).
2. **Total cyber-incident probability card** — `1 - (1-p_breach)(1-p_ransomware)`, `p_ransomware =
   rsi_score x 0.30`; nested ABOVE the breach figure; provisional bands (<5 Low / 5-15 Typical /
   15-30 Elevated / >30 High).
3. **Availability resilience indicator** — `p_interruption`, INDICATIVE only, no coverage claim.
4. **Cover-sizing ladder** — `cover_ladder` P50 / P95 / P99.6, surfaced.
5. **Remediation panel re-portrayal** — leads with breach grade movement + %-exposure reduction +
   posture-independent 1-in-250 cover; absolute Rand savings demoted to secondary.

Anchoring channel = **reporting-only** (one of the four; no double-count) per
`project_financial_model_anchoring_mechanism.md`. Manual lock written into
`manual_parts/part5_*` (the paragraph *is* the lock). Gate held: wiring verifier **28/28**, smoke
**exit 0**.

## Rendered samples (paths)
`docs/calibration_prep/item17_samples/`
- `phishield_r10m_fs_full.pdf` (27pp) · `phishield_r10m_fs_summary.pdf` (6pp) · `phishield_r10m_fs_results.html`
- `takealot_r20bn_ecom_full.pdf` (23pp) · `takealot_r20bn_ecom_summary.pdf` (5pp) · `takealot_r20bn_ecom_results.html`

Regenerate with: `py tooling/_render_item17_samples.py` (mirrors `regen_outputs_from_cache.py` with the
§8-exact invocation — phishield FS R10M rsi_rev=0; takealot eCommerce R20bn sub_industry=eCommerce).

## §8 numbers — held exactly (live result dict, `py tooling/_verify_item17_cards.py`)
| Target | breach | grade | cyber-incident | grade | avail (IND) | cover 1-in-250 | ALE |
|---|---|---|---|---|---|---|---|
| phishield R10M FS (score 164 Low) | 1.68% | Good | 8.14% | Typical | 15% | R34,265,916 | R389,795 |
| takealot R20bn eCom (score 235 Med) | 2.21% | Typical | 8.96% | Typical | 10% | R2,914,038,160 | R95,274,041 |

Matches §8 (phishield breach 1.68% / cover ~R34.3m / ALE ~R390k; takealot breach 2.21% / cover ~R2.91bn
/ ALE ~R95.3m). p_breach is deterministic; the cover tail is MC but stable to the rand at N iterations.

## Steps 1-5 (black-box) — per card
These cards are **views of the model's own computed values** (not external-infrastructure claims), so
"ground truth from source" = the result-dict value, and "attribution" = correct derivation + labelling.

| Step | Data-breach prob | Total cyber-incident | Availability indicator | Cover ladder | Remediation re-portrayal |
|---|---|---|---|---|---|
| 1 Ground truth (result dict == render) | PASS (1.68% == render) | PASS (8.14% == render) | PASS (15% == render) | PASS (R34.27m == render) | PASS (grade move == render) |
| 2 Attribution (derivation + label correct) | PASS (vuln×TEF×0.30; "Good") | PASS (union ≥ breach; nested label) | PASS (labelled INDICATIVE, no cover claim) | PASS (P50/P95/P99.6 severity, posture-indep) | PASS (cover labelled "unchanged") |
| 3 Render & inspect across tiers | PASS full+summary+HTML | PASS full+summary+HTML | PASS full+summary+HTML | PASS full+summary+HTML | PASS full+HTML (summary tier omits remediation by existing design) |
| 4 Benchmark vs authoritative source | PASS (Cyentia/BitSight/SecurityScorecard bands) | PARTIAL (provisional bands — see Step 6) | N/A-INDICATIVE (flagged) | PASS (1-in-250 = SAM/reinsurance std) | PASS (frequency-first reinsurer convention) |
| 5 Live reference (takealot) | PASS (2.21% Typical) | PASS (8.96% Typical) | PASS (10%) | PASS (R2.91bn) | PASS (2.2% Typical → 0.33% Strong) |

Cross-tier consistency (Step 3 detail): every tier reads from the SAME `fin` result dict, so values are
structurally identical; confirmed by PDF text-extraction (`Cyber-Risk Probability` table shows
`Total cyber-incident 8.1% Typical / of which: data breach 1.68% Good / Availability resilience 15%
Indicative`) and HTML grep (same values + grades present).

## Step 6 — heuristics white-box sweep (run EVERY time; the crux)
Enumerated every knob in the new cards and screened against the back-test failure modes
(fabrication-on-absent-input / generic-response-as-signal / boolean-as-count / inversion / stale table).
**None of those failure modes apply** — these cards are mathematical re-expressions of already-scored
values, not interpreters of external responses. Classifications:

| Heuristic | Value | Classification | Basis / action |
|---|---|---|---|
| Breach grading bands | 1/2/3/6/12% | **justified** | Cyentia IRIS (SMB material breach <2%/yr), BitSight, SecurityScorecard — the same public anchors as the existing risk-band block. |
| Cyber-incident union formula | `1-(1-p_b)(1-p_r)` | **justified** (documented simplification) | Standard independent-union. Channels are assumed independent; under positive correlation the independent union slightly OVER-states the true union, i.e. conservative (higher) — a defensible direction for a risk figure. Noted in-card + manual. |
| Ransomware channel frequency | `rsi_score × 0.30` | **justified** (locked) | The #16 FAIR rewiring (RW_LEF reuses the breach 0.30 LEF; no extra TEF — avoids double-count). Locked in §8. |
| **Cyber-incident bands** | 5/15/30% | **calibration-gated** | Explicitly PROVISIONAL; flagged for a dedicated multi-channel calibration. NOT intuited — labelled "provisional" everywhere it appears. |
| **Availability indicator** | `p_interruption` heuristic | **calibration-gated / indicative** | Ships INDICATIVE-only this pass (per §8 REMAINING item 5, deferred). Flagged not-calibrated in JSON + manual; FAIR re-anchoring is the recorded next step. NOT intuited. |
| Cover-ladder percentiles | P50 / P95 / P99.6 | **justified** | Top percentiles (P99/P99.5/P99.6) compress to within ~7%, so the P50→P99.6 spread is the useful client band; P99.6 = 1-in-250 SAM/reinsurance benchmark. |
| Remediation breach-reduction cap | `min(0.85, …)` | **justified** (reuses existing) | Mirrors the existing `_build_mitigations` 85%-of-loss residual-risk cap ("can't eliminate all risk"); not a new magic number. |
| Remediation freq mapping | breach-loss frac → p_breach frac | **justified** | Breach-family loss scales linearly with p_breach, so the fractional breach-loss reduction maps 1:1 to a frequency movement. Documented in-code. |

**No fabrication, no generic-response-as-signal, no boolean-as-count, no inversion, no stale table.**
Two knobs are correctly **calibration-gated and flagged, not intuited** (cyber-incident bands;
availability indicator).

## Benchmark vs reinsurer card (Step 4 detail)
A typical reinsurer/rating cyber report shows a single coarse "likelihood of incident" figure. This pass
**decomposes** that into a breach probability and a total cyber-incident probability with **segregated**
bands, plus a clearly-fenced availability indicator — strictly more information, and it fixes the
band-reuse bug (§8) that mislabelled a typical multi-channel ~8% as "High" (it is "Typical"). The cover
ladder's 1-in-250 tier matches the FSCA SAM / reinsurance catastrophe convention already documented in
the Loss Exposure Scenarios manual section.

## Open items — for the morning review (NOT self-approved)
1. **Exec-deck financial slide** (`_assessment_slide_financial_impact`) — the probability cards + cover
   ladder were wired into HTML + broker-summary PDF + full-report PDF (3 of 4 tiers). The exec-deck slide
   is a bespoke Kaizen-style navy-card/bar-chart layout; its visual integration was **intentionally
   deferred** to your design call (the task asks me to leave aesthetic sign-off to you). Low risk: the
   slide still renders its existing ALE + loss-exposure content unchanged.
2. **Visual / aesthetic sign-off** across all tiers — colours, spacing, table widths, placement order
   (probability card currently renders ABOVE the loss-exposure table; cover ladder directly AFTER it).
   Open the 6 samples and confirm the look.
3. **Cyber-incident bands (5/15/30%)** — provisional; a dedicated multi-channel calibration is owed
   before they are presented as firm.
4. **Availability `p_interruption`** — ships INDICATIVE-only; FAIR re-anchoring is §8 REMAINING item 5
   (deferred, not in this pass's scope).

## Gate (no regression)
- `py tooling/verify_supply_chain_financial_wiring.py` → **28/28 PASS** (reporting-only; assertions
  unchanged; SC→fin_p99 invariance still holds). Only warning: pre-existing `vendor_breaches.json`
  marketo near-expiry (unrelated).
- `py tooling/verify_scan_smoke.py` → **exit 0** (example.com, 50.5s, 41 categories, 53 checkers).
