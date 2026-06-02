# Calibration pre-read — Catastrophe tail / Pareto (FIN-9 core)

**For:** FIN-9 calibration session, 2026-06-03 (with colleague — international breach-cost / heavy-tail experience).
**Status:** SANDBOX PREP. **Research-grounded PROPOSED values, NOT final. No production code edited.**
**This is the colleague's core domain.** Everything tail-shape-related below is a *defensible starting point + the precise open questions* — **not** a pre-empted decision. The Pareto alpha and the mixture weight are explicitly flagged **needs-colleague-validation**.
**Relates to:** OUTSTANDING §6b + §"Tail recalibration"/"WAF coverage-loading constant"; the cat-tail no-double-count rule (`project_scanner_supplychain_cat_tail_design_2026-05-27`); the FIN-9 memory flag.

---

## 0. Scope of this parameter group

Three sub-groups inside `FinancialImpactCalculator._calculate_zar` (and helpers):

1. **`K_TAIL = 1.20`** — WAF-blind-spot coverage-loss tail-widening constant (epistemic uncertainty; *not* supply-chain).
2. **FIN-9 core** — a **conditional Pareto-mixture loss-given-breach (LGB) widening** applied **only to the ~12% supply-chain-vectored MC trials** (the IBM CoDB SC-root-cause slice). Parameters: **Pareto `alpha`** + **mixture weight `mix_w`** + the SC-vectored **fraction `f_sc`**.
3. **PERT bounds + return-period mapping** — the `0.5× / mode / 5.0×` PERT envelope on `mc_total_breach`, and the P99/P99.5/P99.6 → 1-in-100/200/250 percentile map (incl. the GPD Peaks-Over-Threshold refinement above P95).

**Critical design discipline (do NOT relitigate — confirmed 2026-05-27):** supply-chain risk already enters `p_breach` via the `supply_chain_vulnerability_uplift` (cap +0.15 on `vulnerability`). The whole MC distribution shifts right from that, so the tail *already* moves. **FIN-9 widens LGB (severity) on the SC slice, NOT `p`. Do NOT re-introduce a blanket `K_TAIL_SC` post-MC multiplier — that double-counts.** The verifier asserts `supply_chain_tail_adjustment.applied == False` as a PASS condition.

**Baseline caveat (read first):** calibrate against the **post-Wave-1 fixed-code** loss baseline, not the old inflated one. Wave 1 wired `_overall_score` → `vulnerability` for the first time (was pinned 0.5). The recompute below uses the R10M-finance fixture (vuln=0.5, pre-Wave-1) **only to demonstrate tail SHAPE deltas** — the shape comparison is invariant to the absolute `p_breach`, but **regenerate the magnitude anchors on a fixed-code scan before fixing final numbers** (OUTSTANDING §6b).

---

## 1. Parameter table

| Param | Current | Proposed (range) | Confidence | Anchor (sources) | Recompute (P99 / P99.5 / P99.6 delta) | Open question for colleague |
|---|---|---|---|---|---|---|
| **FIN-9 Pareto `alpha`** (LGB tail shape on SC slice) | none (not implemented) | **1.5 – 2.0** central; 1.2 aggressive (MOVEit-like) … 2.5 conservative | **needs-colleague** (their core domain) | German max-loss EVT study **α = 1.77** [Geneva Papers]; Eling-Ibragimov-Ning tail-dynamics (heavy-tail confirmed, α<2) [ScienceDirect/SSRN]; Advisen aggregate Hill/ECF estimates 0.05–0.32 (= "infinite mean", flagged extreme model-risk) [PMC10024527]; smaller α ⇒ heavier tail (α<2 infinite variance, α<1 infinite mean) | At **f_sc=12%, mix_w=30%**: α=2.0 → **+8% / +14% / +18%**; α=1.5 → **+15% / +36% / +50%**; α=1.2 → +38% / +108% / +141%; α=2.5 → +4% / +6% / +7% | **Q-A:** Given the *whole-portfolio* Advisen tail index sits <1 (infinite-mean, but huge parameter uncertainty) yet a *stable body-tail* fit lands ~1.77, what α do you use for **per-org LGB** on a **conditional SC slice**? Is 1.5–2.0 the right working band, or do you anchor harder to MOVEit (≈1.2)? |
| **FIN-9 mixture weight `mix_w`** (fraction of SC trials that draw the heavy Pareto component) | none | **0.25 – 0.35** central | **needs-colleague** | MOVEit per-org curve: top **1%** of ~2,700 orgs absorbed **~60–70%** of total cost [Emsisoft; ORX]; Coveware Q4-2024 ransom **mean/median ≈ 5.0** ($553,959 / $110,890), 63% of demands ≥ $1M, one $75M outlier [Coveware] | mix_w is the lever that sets how much tail mass the heavy component carries; at α=1.5 moving mix_w 20%→40% roughly doubles the P99.6 uplift | **Q-B:** A literal MOVEit fit (top-1%→60–70%) implies a *very* small mix_w on a *very* heavy α. Do we reproduce that shape, or deliberately temper it for an SA SME book (smaller absolute exposures, FSP/UMA context)? |
| **FIN-9 SC-vectored fraction `f_sc`** | n/a (12% cited in comments, not wired to a tail) | **0.12** (IBM CoDB SC root-cause); sensitivity to 0.20 (DBIR-bounded upper) | medium-high (well-anchored) | IBM CoDB 2024 SC = initial vector in **12%** [IBM]; DBIR 2025 third-party *involvement* 30% (broader, not pure root cause); Mandiant ~3% strict trojanised-vendor — **defensible root-cause band 12–20%** | f_sc=20% (α=1.5) → +32% / +87% / +111% vs the 12% case +15% / +36% / +50% | **Q-C:** Use the strict IBM root-cause 12%, or a wider 12–20% to bracket DBIR "involvement"? (12% is the cleaner causal number; 20% risks bleeding into signals already counted via the vuln uplift.) |
| **`K_TAIL = 1.20`** (WAF blind-spot, coverage-loss) | **1.20** | **hold 1.20** pending paired rescan data | low-medium (heuristic; **separate from FIN-9**) | No empirical anchor yet — designed to be calibrated against blinded-vs-allow-listed **rescan deltas** once continuous monitoring exists (SCN-029) | n/a — independent of FIN-9; documented here for completeness. At 10% coverage shortfall → +12% on 1-in-250; at 40% → +48% | **Q-D:** Any external benchmark for "expected hidden-finding severity given a blinded external scan"? Otherwise hold 1.20 and revisit with paired data. Keep it strictly epistemic (NOT merged with FIN-9). |
| **PERT upper bound** on `mc_total_breach` / `mc_total_base` | **5.0×** mode (lower 0.5×) | **hold 5.0×** if FIN-9 lands; revisit only if NOT | medium | Widened 2.5×→5.0× (Phase B3) for SA cat precedent (Transnet, Life Healthcare, Experian). IBM mega-breach: 1–10M records ≈ $42M (~9× avg); ≥50M ≈ $375M | The current 5.0× envelope alone yields **mean/median ≈ 1.12, P99.6/P50 ≈ 3.1** — *too light* vs empirical cyber tails (Coveware mean/median ≈ 5) | **Q-E:** Is the FIN-9 Pareto mixture the right way to add tail weight (preferred — targeted to SC slice), vs simply widening this PERT bound further (blunt — inflates *all* trials, incl. non-SC)? |
| **Return-period map** P99/P99.5/P99.6 → 1-in-100/200/250 + GPD POT fit above P95 | as-is (MoM GPD, pure-numpy) | **hold**; FIN-9 feeds the *input* dist, map is downstream | medium-high | Standard actuarial RP convention; GPD POT is textbook tail extrapolation (MoM, no scipy on Render) | FIN-9 widens the underlying samples; the existing P95-threshold GPD then refits naturally on the heavier tail | **Q-F:** With a genuine Pareto component in the body of the SC slice, does the P95 POT threshold still sit in the right place, or lift the threshold (e.g. P97/P98) for the SC-conditional refit? MoM→MLE GPD upgrade still deferred (scipy). |

---

## 2. What the recompute shows (throwaway numpy — no production edit)

Faithful reconstruction of the R10M-finance fixture's MC (PERT λ=4, 7-scenario incident decomposition, real cost components C1=R7.29M / C2=R0.2M / C4=R0.90M / C5=R0.35M, `p_breach`=0.2175), then a **conditional Pareto-mixture LGB** multiplier applied to the C1+C2 *breach severity* of the SC-vectored slice only.

**Baseline (current model shape):** P50 R2.98M · P95 R6.59M · P99 R8.43M · P99.5 R9.11M · P99.6 R9.31M · mean R3.33M.
→ **mean/median = 1.12**, **P99.6/P50 = 3.1**. This is **lighter-tailed than empirical cyber loss** (Coveware ransom mean/median ≈ 5.0; the literature repeatedly finds lognormal/PERT *under-predicts* the cyber tail). That gap is the gap FIN-9 closes.

| Scenario (f_sc, α, mix_w) | P99 Δ | P99.5 Δ | P99.6 Δ | mean Δ | P50 Δ | ordering |
|---|---|---|---|---|---|---|
| central (12%, 2.0, 30%) | +8.2% | +14.4% | **+18.2%** | +2.7% | +0.8% | OK |
| heavier (12%, 1.5, 30%) | +14.7% | +35.6% | **+49.8%** | +5.8% | +1.0% | OK |
| aggressive / MOVEit-like (12%, 1.2, 40%) | +37.7% | +108.1% | **+140.9%** | +19.2% | +1.8% | OK |
| conservative (12%, 2.5, 20%) | +3.7% | +5.7% | **+6.7%** | +1.1% | +0.4% | OK |
| upper SC frac (20%, 1.5, 30%) | +31.7% | +87.0% | **+111.1%** | +11.7% | +1.7% | OK |

**Findings:**
- **Median essentially unmoved** (P50 +0.4% … +1.8%) across the entire parameter space → the widening is **tail-only**, confirming no double-count with the `p_breach` channel. Expected-loss view barely shifts (mean +1% … +6% in the plausible band).
- **Ordering P99 ≤ P99.5 ≤ P99.6 preserved in every run.**
- The **central band (α 1.5–2.0, mix_w ~30%, f_sc 12%)** lifts the 1-in-250 by **~18–50%** and the mean/median ratio from 1.12 toward **1.14–1.17** — a *modest* move toward the empirical 1.2–1.3 region, still far short of an unconstrained Coveware ≈5. Reads as defensible, not punitive.
- **α=1.2 is a true upper bound** (1-in-250 +141%, mean/median 1.31) — only justified if the colleague judges the SC tail should literally approach the MOVEit per-org curve.

*Heavy-tail behaviour check (expert validation point):* the recompute reproduces the qualitative MOVEit shape (a thin slice of trials carrying disproportionate loss). The colleague should confirm whether the **top-1%-absorbs-60–70%** property holds at the chosen (α, mix_w) — the literal MOVEit fit needs a heavier α + smaller mix_w than the central band; the central band is a *tempered* version chosen for an SA SME book. **This temper is a proposal, not a decision — Q-B.**

---

## 3. Honesty / confidence statement

- **Pareto `alpha` + mixture `mix_w`: needs-colleague.** These set the catastrophe capital view; they are the colleague's domain. The ranges above are a *defensible starting point* from public literature, **not** a recommendation to adopt a specific value.
- **`f_sc`=12%: medium-high confidence** (clean IBM root-cause anchor); the 12–20% sensitivity is the honest uncertainty band.
- **`K_TAIL`=1.20: hold** — heuristic, no anchor yet, but **independent of FIN-9** (epistemic, not severity). Do not fold the two together.
- **PERT 5.0× / return-period map: hold** — the FIN-9 mixture is the *preferred* mechanism to add SC tail weight (targeted) over further blunt PERT widening (untargeted).
- All deltas are **shape** results valid regardless of the absolute `p_breach`; **magnitudes must be re-anchored on a fixed-code scan** (OUTSTANDING §6b) before any number is fixed.

## 4. The precise asks for the colleague (decision checklist)

1. **Q-A — α:** per-org LGB Pareto shape for a conditional SC slice — working band **1.5–2.0**, or anchor to MOVEit (~1.2)? (Reconcile: whole-portfolio Advisen α<1 infinite-mean *vs* stable body-tail α≈1.77.)
2. **Q-B — mix_w + MOVEit fidelity:** reproduce the literal top-1%→60–70% shape, or the tempered SA-SME version (central band)?
3. **Q-C — f_sc:** strict IBM root-cause **12%**, or widen toward DBIR-involvement 20%?
4. **Q-D — K_TAIL:** any external benchmark for blinded-scan hidden-severity, or hold 1.20 until paired-rescan data?
5. **Q-E — mechanism:** confirm Pareto-mixture-on-SC-slice (targeted) is preferred over a wider blanket PERT bound (untargeted).
6. **Q-F — RP map / GPD threshold:** keep the P95 POT threshold for the SC-conditional refit, or lift it; MoM→MLE GPD upgrade timing.
7. **Cross-check (do together):** confirm the resulting 1-in-100/200/250 ZAR figures for a CRITICAL-SC org sit sensibly vs SA cat precedent (Transnet/Life Healthcare/Experian) and the colleague's international per-org loss curves — and that the **mean/expected-loss is essentially unchanged** (capital view only).

## 5. No-double-count guardrails (hard rules — carry into implementation)

- FIN-9 widens **LGB severity on the SC slice**, never `p`. SC already raises `p_breach` via the vulnerability uplift.
- **No `K_TAIL_SC`.** Verifier must still PASS `supply_chain_tail_adjustment.applied == False`.
- `K_TAIL` (WAF) stays strictly epistemic and separate.
- Run the 2-step gate after any wiring (`verify_supply_chain_financial_wiring.py` 31/31 + `verify_scan_smoke.py` exit 0) and present per-percentile deltas + sanity-check before shipping.

## Sources

- German max-loss EVT study (selected Pareto **α = 1.77**) — Geneva Papers on Risk and Insurance: https://link.springer.com/article/10.1057/s41288-023-00293-x
- Eling, Ibragimov, Ning — *The Changing Landscape of Cyber Risk: loss severity & tail dynamics* (heavy-tail confirmed, α<2): https://www.sciencedirect.com/science/article/pii/S0167668725001428 · SSRN: https://papers.ssrn.com/sol3/papers.cfm?abstract_id=5158032
- Cyber loss model risk / Advisen tail-index estimates (Hill/ECF 0.05–0.32, infinite-mean caveat) — PMC10024527: https://pmc.ncbi.nlm.nih.gov/articles/PMC10024527/
- *Nature of losses from cyber-related events* (Advisen, sector tails) — Oxford Journal of Cybersecurity: https://academic.oup.com/cybersecurity/article/9/1/tyac016/7000422
- MOVEit per-org / top-victim statistics — Emsisoft: https://www.emsisoft.com/en/blog/44123/unpacking-the-moveit-breach-statistics-and-analysis/ · ORX deep dive: https://orx.org/resource/moveit-transfer-data-breaches-orx-news-deep-dive
- Coveware Q4-2024 ransom distribution (mean/median ≈ 5.0; 63% ≥ $1M; $75M outlier): https://www.coveware.com/blog/2025/1/31/q4-report · https://www.coveware.com/ransomware-quarterly-reports
- IBM Cost of a Data Breach 2024 (mega-breach $42M / $375M tiers; SC 12% root cause): https://www.ibm.com/think/insights/whats-new-2024-cost-of-a-data-breach-report
- Spliced/mixture cyber-loss severity modelling (lognormal under-predicts tail; Pareto for large claims) — SCIRP: https://www.scirp.org/journal/paperinformation?paperid=126218
