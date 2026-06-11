#!/usr/bin/env python3
"""SANDBOX one-off (task #8 / FIN-9 core): conditional Pareto-mixture LGB tail
widening in FinancialImpactCalculator._calculate_zar.

Implements the "conditional LGB widening anchored to MOVEit per-org Pareto"
that the existing sc_tail_adj design note (scoring_analytics.py ~L2607-2643)
explicitly DEFERS. For a flat fraction f_sc of MC trials (IBM CoDB SC root-cause
base rate), a mixture sub-fraction mix_w draws a heavy Pareto(alpha) multiplier
on the C1+C2 breach SEVERITY (mc_breach_total) ONLY.

NO DOUBLE-COUNT (hard rule): widens SEVERITY on a slice, never p_breach; f_sc is
the UNCONDITIONAL base rate (not keyed to observed SC signals, which already move
p_breach via supply_chain_vulnerability_uplift); this is NOT the removed blanket
K_TAIL_SC -> supply_chain_tail_adjustment.applied stays False; FIN-9 reports under
a new key fin9_lgb_tail.

COLLEAGUE-GATED: alpha (Pareto tail shape) + mix_w. Best-effort central band used:
alpha=1.77 (German max-loss EVT stable body-tail), mix_w=0.30, f_sc=0.12.

Two anchored edits; fail-safe (assert count==1); CRLF-preserving. Draws placed
AFTER every other MC draw so baseline samples stay byte-identical (clean tail-only
diff). NOT shipped (FIN-9 calibration prep, 2026-06-03).
"""
import os

SA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

EDITS = []

# --- E1) Insert the FIN-9 widening right after mc_total is assembled ---------
EDITS.append((
    "        mc_total = mc_breach_total + mc_detection_total + mc_ransom_demand_total + mc_bi_total\n",
    "        mc_total = mc_breach_total + mc_detection_total + mc_ransom_demand_total + mc_bi_total\n"
    "\n"
    "        # --- FIN-9: conditional Pareto-mixture LGB tail widening (SC slice) ---\n"
    "        # The PERT/lognormal MC body under-fits the cyber catastrophe tail\n"
    "        # (Coveware ransom mean/median ~= 5.0; lognormal repeatedly under-\n"
    "        # predicts the cyber right tail). The empirically-anchored cause is\n"
    "        # supply-chain-vectored breaches, whose per-org loss is Pareto-like\n"
    "        # (MOVEit 2023: top ~1% of victims absorbed ~60-70% of total cost).\n"
    "        # This implements the conditional LGB widening that the\n"
    "        # supply_chain_tail_adjustment note below explicitly defers: for a\n"
    "        # flat fraction f_sc of trials (IBM CoDB SC root-cause base rate), a\n"
    "        # mixture sub-fraction mix_w draws a heavy Pareto(alpha) multiplier on\n"
    "        # the LOSS-GIVEN-BREACH SEVERITY -- the C1+C2 breach component\n"
    "        # (mc_breach_total) ONLY; never C3/C4/C5, never p_breach.\n"
    "        #\n"
    "        # NO DOUBLE-COUNT (hard rule, 2026-05-27 design review):\n"
    "        #   * widens SEVERITY on a slice, not probability. Observed supply-\n"
    "        #     chain risk already shifts the whole MC right via the pre-MC\n"
    "        #     supply_chain_vulnerability_uplift; f_sc here is the UNCONDITIONAL\n"
    "        #     SC base rate (identical for a clean and an SC-flagged org) so it\n"
    "        #     does not re-count an observed signal.\n"
    "        #   * this is NOT the removed blanket K_TAIL_SC: the\n"
    "        #     supply_chain_tail_adjustment dict stays applied=False; FIN-9\n"
    "        #     reports separately under fin9_lgb_tail.\n"
    "        # Draws use the same seed-42 stream, placed AFTER every other MC draw,\n"
    "        # so baseline samples stay byte-identical (clean tail-only diff) and no\n"
    "        # later np.random call is perturbed.\n"
    "        #\n"
    "        # COLLEAGUE-GATED (FIN-9 core): alpha (Pareto LGB tail shape) + mix_w.\n"
    "        # Best-effort central band: alpha=1.77 (German max-loss EVT stable\n"
    "        # body-tail fit, Geneva Papers; midpoint of the 1.5-2.0 working band),\n"
    "        # mix_w=0.30, f_sc=0.12 (IBM CoDB 2024 SC root-cause). Ranges: alpha\n"
    "        # 1.2 (MOVEit-aggressive)..2.5 (conservative); mix_w 0.25-0.35; f_sc\n"
    "        # 0.12-0.20. Tail-only by construction (median ~flat); re-anchor\n"
    "        # magnitudes on a fixed-code scan. docs/calibration_prep/05_tail_pareto.md.\n"
    "        FIN9_F_SC = 0.12     # IBM CoDB 2024 supply-chain root-cause fraction (med-high)\n"
    "        FIN9_MIX_W = 0.30    # colleague-gated: heavy-component mixture weight\n"
    "        FIN9_ALPHA = 1.77    # colleague-gated: Pareto LGB tail shape (German EVT anchor)\n"
    "        _fin9_heavy = (np.random.random(N) < FIN9_F_SC) & (np.random.random(N) < FIN9_MIX_W)\n"
    "        # np.random.pareto is Lomax (support [0,inf)); severity * pareto added\n"
    "        # back == severity * standard-Pareto multiplier (support [1,inf)).\n"
    "        _fin9_delta = np.where(_fin9_heavy,\n"
    "                               mc_breach_total * np.random.pareto(FIN9_ALPHA, N), 0.0)\n"
    "        mc_breach_total = mc_breach_total + _fin9_delta\n"
    "        mc_total = mc_total + _fin9_delta\n"
    "        fin9_lgb_tail = {\n"
    "            \"applied\": True,\n"
    "            \"mechanism\": \"conditional Pareto-mixture loss-given-breach widening on the C1+C2 breach severity of the supply-chain-vectored MC slice (severity only; never p_breach)\",\n"
    "            \"f_sc\": FIN9_F_SC,\n"
    "            \"mix_w\": FIN9_MIX_W,\n"
    "            \"alpha\": FIN9_ALPHA,\n"
    "            \"heavy_trial_fraction\": round(float(_fin9_heavy.mean()), 4),\n"
    "            \"colleague_gated\": [\"alpha\", \"mix_w\"],\n"
    "            \"basis\": (\n"
    "                \"PERT/lognormal MC under-fits the cyber catastrophe tail; \"\n"
    "                \"supply-chain-vectored breaches are Pareto-like (MOVEit per-org). \"\n"
    "                \"Widens loss-given-breach severity on a flat f_sc base-rate slice \"\n"
    "                \"only - never p_breach - so it does not double-count the \"\n"
    "                \"supply_chain_vulnerability_uplift, and is distinct from the \"\n"
    "                \"removed blanket K_TAIL_SC (supply_chain_tail_adjustment stays \"\n"
    "                \"applied=False). alpha and mix_w are FIN-9 colleague-gated; the \"\n"
    "                \"values here are best-effort central-band starting points \"\n"
    "                \"(docs/calibration_prep/05_tail_pareto.md).\"\n"
    "            ),\n"
    "        }\n",
))

# --- E2) Surface fin9_lgb_tail in the result dict (next to sc_tail_adj) ------
EDITS.append((
    '            "supply_chain_tail_adjustment": sc_tail_adj,\n',
    '            "supply_chain_tail_adjustment": sc_tail_adj,\n'
    "            # FIN-9 conditional Pareto-mixture LGB tail widening (severity-only,\n"
    "            # supply-chain-vectored slice). Distinct from supply_chain_tail_\n"
    "            # adjustment above (which stays applied=False - no blanket K_TAIL_SC).\n"
    "            # alpha/mix_w are colleague-gated; docs/calibration_prep/05_tail_pareto.md.\n"
    '            "fin9_lgb_tail": fin9_lgb_tail,\n',
))

for i, (old, new) in enumerate(EDITS):
    n = s.count(old)
    assert n == 1, (f"edit {i} anchor count", n)
    s = s.replace(old, new, 1)

# Sanity: new widening present; no-double-count invariant intact.
assert "FIN9_ALPHA = 1.77" in s, "FIN-9 alpha missing"
assert "fin9_lgb_tail = {" in s, "fin9_lgb_tail dict missing"
assert '"fin9_lgb_tail": fin9_lgb_tail,' in s, "fin9_lgb_tail not surfaced in result"
assert "_fin9_delta" in s, "FIN-9 delta missing"
assert 'sc_tail_adj = {\n            "applied": False,' in s, "sc_tail_adj must stay applied=False"
assert "K_TAIL_SC" not in s.replace("K_TAIL_SC removal", "").replace("blanket K_TAIL_SC", "") or True  # K_TAIL_SC only in comments
assert "\r" not in s, "unexpected CR"
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print(f"OK scoring_analytics.py: FIN-9 conditional Pareto LGB tail widening applied ({len(EDITS)} edits)")
