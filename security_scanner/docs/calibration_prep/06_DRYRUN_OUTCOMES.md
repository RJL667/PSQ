# Calibration — Solo Dry-Run Outcomes (prep-proposal vs result vs still-open)

**Date:** 2026-06-03 · **Status: SANDBOX — nothing shipped** (no master merge, no push, no deploy; all edits uncommitted).
**Companion to** [`00_CALIBRATION_SUMMARY.md`](00_CALIBRATION_SUMMARY.md) (the *input* brief). This is the *output*: what the autonomous pass actually produced, against the fixed-code baseline (`test_fixtures/phishield_live.json`).
**Gate:** `verify_supply_chain_financial_wiring.py` **31/31 PASS** · `verify_scan_smoke.py` **exit 0** (59.6s, example.com 145/Low).
**Legend:** **LOCKED** = data-anchored, applied, sign-off only · **GATED** = colleague-gated value (best-effort set) · **STRUCTURAL** = design decision, not a parameter.

## 1. Decision table

| # | Item | Prep proposal (range) | Dry-run result (applied) | Status |
|---|------|----------------------|--------------------------|--------|
| 1 | Vuln curve **shape** | fix polarity → convex `(score/1000)^k`, k 1.5–2.0 | polarity fixed (`1cc204d`); convex **k=1.8**. phishield vuln 0.169→0.0386 | **LOCKED** |
| 2 | **Base rate** (LEF `0.3`) | retain 0.20–0.35 if convex | **retained 0.3**. p_breach 0.0735→0.0168 | **GATED** ← highest leverage |
| 3 | Credential K1–K7 + caps | K1 1.0/0.4/0.1, K2 decay, K3 ×0.3, dehashed→class, darkweb −40/paste −30 | full K-model applied. phishield HIGH→**LOW** (W=0.432, contrib 10); takealot **CRITICAL** (infostealer floor, contrib 100) | **LOCKED**; K3 combo-recency **GATED** |
| 4 | RSI factor rebalance | RDP 0.18–0.22, CRIT-cred ≥ RDP, trim surfaces | applied. phishield RSI 0.451→0.219 (dropped false HIGH-cred factor, 3→2); takealot CRIT-cred is sole factor | **LOCKED** |
| 5 | SA per-record / industry cost | hold (IBM-2025-SA), add refresh stamp | values held + dated sourcing stamp | **LOCKED** |
| 6 | POPIA C2 fine | P(fine)×E[fine] ≈ R100k–250k; hold R10M cat ceiling | **0.03 × R5M = R150k** (was R200k @ R10M); R10M ceiling held for cat view | **GATED** ← P(fine\|breach) |
| 7 | TEF SA tilt | Gov 1.40–1.50, Comms 1.20–1.30 | Gov/PublicSector **1.45**, Comms **1.25**, Consumer **1.10**; FS held 1.45 | **LOCKED**; Healthcare 1.40 trim = soft-open |
| 8 | FIN-9 Pareto LGB tail | alpha 1.5–2.0, mix_w 0.25–0.35, f_sc 0.12 | **alpha 1.77, mix_w 0.30, f_sc 0.12**; severity-only on SC slice; `supply_chain_tail_adjustment.applied=False` kept | **GATED** ← alpha + mix_w |
| 9 | Risk-level bands | re-fit to de-inflated dist + p_breach tiers | **RETAIN 200/400/600** (= inverse of neutral {2%,6%,12%}); comment-only, byte-identical | **LOCKED** |

## 2. Evidence (verified from saved iterations)

**phishield — clean FSP, R10M floor, Financial Services (iter0 → iter7):**

| Metric | iter0 (fixed-code) | iter7 (final) | Δ |
|--------|-------------------:|--------------:|----|
| risk_score / level | 169 / Low | 164 / Low | flat (correct) |
| vulnerability | 0.169 (linear) | 0.0386 (convex k=1.8) | curve |
| p_breach | 0.0735 | **0.0168** | **−77%** |
| ML annual loss | R1,793,092 | **R750,247** | **−58%** |
| 1-in-250 (P99.6) | R7,989,625 | R4,822,195 | −40% |
| credential class | HIGH | **LOW** | de-escalated |

The big moves are **de-inflation** (removing false-positive inflation that landed on well-postured orgs), not parameter tuning. `p_breach = vuln × TEF × 0.3 = 0.0386 × 1.45 × 0.3 = 0.0168` — wiring confirmed.

**takealot — R20bn, Consumer (iter8):** risk 235 / Medium · p_breach 0.0243 · ML **R124.0M** · 1-in-250 **R577.0M** · credential CRITICAL (infostealer) · C4 ransom R25.7M. **Flags C1_liability=0** (see §3.5).

**FIN-9 tail-only proof (iter5 → iter6, phishield):** median / ML / p_breach **byte-flat**; 1-in-100 **+20.1%**, 1-in-200 **+38.1%**, 1-in-250 **+45.5%** — inside the doc-05 18–50% design band, ordering preserved, no double-count.

**Severity anchor:** at the R200M median-revenue pivot (revenue_scale=1.0) the FS severity reproduces the IBM-SA Financial Services anchor (~R70.1M) to within ~4% — the median is pinned to real SA breach data, not invented.

## 3. Still-open — the session agenda (ranked)

**Tier A — needs the colleague's judgement:**
1. **Base rate** (the `0.3` LEF constant). Annual loss-event (~1–3% SME) vs material-incident moves the constant **3–5×**; everything downstream keys off it. **Lock this first.**
2. **FIN-9 tail: alpha (1.77) + mix_w (0.30).** The colleague's actual domain (international breach-cost / EVT). alpha 1.2–2.5; mix_w 0.25–0.35. f_sc=0.12 is data-anchored (IBM CoDB), *not* gated.
3. **POPIA P(fine | private-SME breach) = 0.03.** Inferred from enforcement scarcity (0 private fines; both s109 fines R5M public-sector). A compliance-officer call.
4. **K3 combo-recency interaction.** Flat ×0.3 is wrong for the fresh+combo case (e.g. ALIEN TXTBASE 2024-12 in a combolist) — should it be recency-aware?

**Tier B — STRUCTURAL (design decision, surfaced by the dry-run, NOT a parameter):**
5. **C1 liability — give it its own factor in the cat model, not the residual balance.** Today `C1 = max(0, severity − C2 − C3 − C4 − C5)` is a residual/plug. C3/BI is independently revenue-scaled, overruns the breach anchor, and floors C1 to 0 for big orgs (takealot: `C1=0`; `cost_components` also omits C3, so the *visible* ≈R30.8M understates the MC-derived ML R124M). **The residual is only the symptom — a residual cannot carry its own tail, yet liability is the heaviest-tailed bucket in real cyber cat (class actions / regulatory cascade).** Direction: in the CAT model (`mc_c1`, `:2521`) model C1 as an independent severity + tail; keep the residual in the central/point estimate (`:2342` — a real central loss can legitimately floor a bucket). Side effects: removes the floor artefact AND restores a non-zero C1+C2 severity for FIN-9 (`:2531`) to widen. Candidate drivers: records × per-record liability (records already estimated, currently disclosure-only) or an independent lognormal/Pareto anchor; demote the IBM total to a coherence cap. Also surface C3 in `cost_components` (display fix).
6. **Annual-expected-loss runs warm (~3.35%) for a clean R200M org.** Driven by the 7 incident-scenario probabilities + BI scaling, which sit *outside* the FAIR p_breach params calibrated here. Single-breach point estimates are well-anchored; the *annualised aggregation* is where the warmth enters.

**Tier C — resolved, sign-off only (don't spend session time unless challenged):** TEF SA tilts · risk bands (retain) · severity anchor · C4 ransom (Sophos-aligned) · credential de-escalation.

## 4. Where the raw data lives
Per-iteration numbers: [`tooling/_calib_iterations/iter0…iter8.json`](../../tooling/_calib_iterations/) · per-edit rationale: [`tooling/_apply_item02…09.py`](../../tooling/) docstrings · per-topic sources: [`01_…05_*.md`](.) · in-code anchored comments: `scoring_analytics.py` (band-retain block, FIN-9 basis, POPIA/TEF).
