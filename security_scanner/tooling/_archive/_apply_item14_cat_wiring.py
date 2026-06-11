# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX one-off (task #14): cat-modelling redesign wiring into _calculate_zar.

Executes steps A-E of docs/calibration_prep/07_WIRING_SPEC_AND_HANDOFF.md:
  A  Compound (loss-given-event) aggregation feeds the return periods (the tail
     stops collapsing with posture); central/median/CI stay prob-weighted.
  B  Records-driven stand-alone cat-C1, floored at the central IBM residual.
  C  BI downtime MC re-anchored PERT(3,25,120) -> PERT(2,14,90).
  D  FIN-9 Pareto-mixture severity widening REMOVED; replaced by a
     systemic_supply_chain_exposure DISCLOSURE block (not a loss contribution).
  E  POPIA P(fine|breach) 0.03 -> 0.02 (record-anchored: DoJ-2023 / DBE-2024).

CRLF-preserving (read utf-8 text-mode -> assert no CR -> anchored count==1
replacements -> write back as CRLF bytes), mirroring _apply_item07/08/09*.py.
NOT shipped. Re-running is a no-op-or-fail by design (anchors disappear after the
first apply).
"""
import os

SA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

edits = []  # (label, OLD, NEW)


# ── E. POPIA P(fine) 0.03 -> 0.02 (record-anchored) ──────────────────────────
edits.append((
    "E.popia-comment",
    "        #   COLLEAGUE-GATED: P(fine|breach) for a private SA SME is ~0.02-0.05\n"
    "        #   (inferred from enforcement scarcity - 0 private fines to date - NOT a\n"
    "        #   published rate; a compliance-officer call). E[fine|fine] ~ R5M (both\n"
    "        #   actual s109 fines). Best-effort midpoint 0.03 x R5M = R150k (the old\n"
    "        #   2% gave R200k @ R10M, so the headline barely moves; the value here is\n"
    "        #   defensibility + correct high-revenue behaviour). Range R100k-R250k.\n",
    "        #   RECORD-ANCHORED (not colleague-gated): POPIA's entire administrative-\n"
    "        #   fine record is two s109 fines - DoJ (2023) and DBE (2024), R5M each,\n"
    "        #   both public-sector, both recalcitrance-driven (failure to comply with\n"
    "        #   an enforcement notice), ZERO private-commercial. So E[fine|fine] = R5M\n"
    "        #   (both actual fines) and P(fine|breach) = 0.02, anchored to that record\n"
    "        #   (0 private fines to date; recalcitrance-driven enforcement). E[fine] =\n"
    "        #   0.02 x R5M = R100k expected. Range R100k-R250k.\n",
))
edits.append((
    "E.popia-const",
    "        POPIA_P_FINE_GIVEN_BREACH = 0.03",
    "        POPIA_P_FINE_GIVEN_BREACH = 0.02",
))
edits.append((
    "E.popia-inline-comment",
    "# colleague-gated (private-SME enforcement probability)",
    "# record-anchored (DoJ-2023 / DBE-2024; 0 private fines to date)",
))


# ── C. BI downtime MC PERT(3,25,120) -> PERT(2,14,90) ────────────────────────
edits.append((
    "C.bi-downtime",
    "        # C3: downtime sampled with SA empirical PERT(3, 25, 120) days\n"
    "        mc_dt = self._pert_sample(3, SA_AVG_DOWNTIME, 120, N)\n",
    "        # C3: downtime sampled with SA empirical PERT(2, 14, 90) days (FIN-9\n"
    "        # cat re-anchor): mode 14 = good-IR / Sophos Rapid Response ~2 weeks,\n"
    "        # mean ~24.7 = Coveware / IBM 2025 average ~24 days, max 90 = insurance\n"
    "        # indemnity-period cap. The central c3_bi above keeps SA_AVG_DOWNTIME=25\n"
    "        # (= the new mean, 24.7) so the analytical most-likely is unchanged.\n"
    "        mc_dt = self._pert_sample(2, 14, 90, N)\n",
))


# ── B. Records-driven stand-alone cat-C1, floored at the central residual ─────
edits.append((
    "B.records-driven-c1",
    "        # C1: residual (clamped to >= 0)\n"
    "        mc_c1 = np.maximum(0, mc_total_breach - mc_c2 - mc_c3_full - mc_c4 - mc_c5)\n",
    "        # C1 (catastrophe view): records-driven stand-alone liability, floored\n"
    "        # at the central IBM residual (FIN-9 cat redesign). A realised cat breach\n"
    "        # exposes ~100% of the records held (Yahoo / Capital One / Marriott /\n"
    "        # Optus all lost the full historical DB), so cat-C1 scales with the record\n"
    "        # count, NOT as the IBM-anchor residual. Per-record R90 is the\n"
    "        # international class-action settlement anchor (Anthem ~R27, Capital One\n"
    "        # ~R33, Equifax ~R53 per affected person + legal / credit-monitoring load)\n"
    "        # - i.e. the settlement evidence itself, ~5.5% of the IBM all-in per-record\n"
    "        # cost, not a modelled fraction of it. lognormal(0, 0.25) is the per-record\n"
    "        # cat heavy tail (median = R90). records_held = estimated_records, the\n"
    "        # revenue/divisor model estimate (a future client-override field will\n"
    "        # supply total records held incl. historical). The np.maximum floor keeps\n"
    "        # the old IBM residual for small orgs, where it dominates the records term.\n"
    "        records_held = estimated_records\n"
    "        residual_floor = np.maximum(0, mc_total_breach - mc_c2 - mc_c3_full - mc_c4 - mc_c5)\n"
    "        mc_c1 = np.maximum(records_held * 90.0 * np.random.lognormal(0, 0.25, N),\n"
    "                           residual_floor)\n",
))


# ── A + D. Compound aggregation block + systemic-SC disclosure; remove FIN-9 ──
# Splice between two stable anchors so we never have to reproduce the (large)
# FIN-9 block verbatim: keep everything up to and including the mc_total line,
# drop the FIN-9 block, keep everything from the WAF blind-spot header onward.
A_START = ("        mc_total = mc_breach_total + mc_detection_total"
           " + mc_ransom_demand_total + mc_bi_total\n")
END_KEY = "Scan-coverage uncertainty loading (WAF blind-spot)"
assert s.count(A_START) == 1, ("A_START count", s.count(A_START))
assert s.count(END_KEY) == 1, ("END_KEY count", s.count(END_KEY))
i = s.index(A_START) + len(A_START)
j0 = s.index(END_KEY)
line_start = s.rfind("\n", 0, j0) + 1
removed = s[i:line_start]
assert "FIN9_F_SC" in removed and "fin9_lgb_tail = {" in removed, \
    ("unexpected FIN-9 splice region", removed[:200])

NEW_AD = (
    "\n"
    "        # --- Compound (loss-given-event) aggregation for the catastrophe tail ---\n"
    "        # The four per-category accumulators above are PROBABILITY-WEIGHTED (each\n"
    "        # scenario contributes p_scenario x severity) - correct for the EXPECTED /\n"
    "        # most-likely card, wrong for the return-period tail. A prob-weighted P99.6\n"
    "        # scales with p_breach, so improving posture mechanically COLLAPSES the\n"
    "        # 1-in-250 cat view - the opposite of how catastrophe cover behaves. A cat\n"
    "        # event is a REALISED severe year and its severity is posture-independent\n"
    "        # (posture moves the FREQUENCY, not the loss-given-event).\n"
    "        #\n"
    "        # So the return periods are computed from a separate COMPOUND distribution:\n"
    "        # each scenario either occurs this simulated year (a Bernoulli draw against\n"
    "        # its per-iteration probability) or not, and on occurrence the FULL scenario\n"
    "        # severity is realised (not p x severity). The compound MEAN equals the\n"
    "        # prob-weighted expected loss (E[1{u<p} x s] = E[p x s]), so the expected /\n"
    "        # most-likely card is preserved exactly; only the tail percentiles change.\n"
    "        # The central / median / CI stats and every per-category breakdown keep\n"
    "        # using the prob-weighted arrays above. Draws are placed after every\n"
    "        # prob-weighted draw so those arrays are unchanged. Aggregation choice +\n"
    "        # proof: docs/calibration_prep/05_tail_pareto.md, _proto_compound_tail.py.\n"
    "        mc_compound_total = np.zeros(N)\n"
    "        for _p_occ, _sev in (\n"
    "            (mc_rsi * R[\"double_extortion\"],         (mc_c1 + mc_c2) + mc_c4 + mc_c5 + mc_c3_full),\n"
    "            (mc_rsi * R[\"ransomware_only\"],           mc_c4 + mc_c5 + mc_c3_full),\n"
    "            (mc_rsi * R[\"wiper_destructive\"],         mc_c5 + mc_c3_full),\n"
    "            (mc_p_breach * R[\"silent_breach\"],        (mc_c1 + mc_c2) + mc_c5 * 0.60 + mc_c3_silent),\n"
    "            (mc_p_breach * R[\"data_extortion\"],       (mc_c1 + mc_c2) + mc_c4 * 0.40 + mc_c5 + mc_c3_extort),\n"
    "            (mc_p_breach * R[\"opportunistic_breach\"], (mc_c1 * 0.50 + mc_c2) + mc_c5 * 0.40 + mc_c3_opp),\n"
    "            (mc_p_int,                                mc_c3_ddos),\n"
    "        ):\n"
    "            _occurs = np.random.random(N) < _p_occ\n"
    "            mc_compound_total += np.where(_occurs, _sev, 0.0)\n"
    "\n"
    "        # Systemic supply-chain catastrophe exposure - DISCLOSURE ONLY (not a loss\n"
    "        # contribution). FIN-9's Pareto-mixture severity widening was RETIRED:\n"
    "        # supply-chain severity is already inside the records-driven cat-C1 (a\n"
    "        # supplier-vectored breach still exposes the insured's record base), and the\n"
    "        # supply-chain SIGNAL moves PROBABILITY via supply_chain_vulnerability_uplift\n"
    "        # - one signal, one channel. A correlated SYSTEMIC SC catastrophe (many\n"
    "        # insureds compromised through one shared vendor, e.g. MOVEit 2023) is a\n"
    "        # portfolio accumulation risk disclosed here and managed at portfolio level,\n"
    "        # not priced into a single insured's loss number (mirrors the SA Covid-19\n"
    "        # business-interruption precedent: disclose correlated systemic loss rather\n"
    "        # than model it per policy).\n"
    "        systemic_supply_chain_exposure = {\n"
    "            \"modelled_as_loss\": False,\n"
    "            \"channel\": \"disclosure\",\n"
    "            \"basis\": (\n"
    "                \"Supply-chain severity is captured in the records-driven \"\n"
    "                \"catastrophe C1 (a supplier-vectored breach still exposes the \"\n"
    "                \"insured's record base) and the supply-chain signal raises \"\n"
    "                \"p_breach via supply_chain_vulnerability_uplift (one signal, one \"\n"
    "                \"channel). A correlated SYSTEMIC supply-chain catastrophe - many \"\n"
    "                \"insureds compromised through a single shared vendor (MOVEit 2023 \"\n"
    "                \"class) - is a portfolio accumulation risk disclosed here and \"\n"
    "                \"managed at portfolio level, not modelled as an individual \"\n"
    "                \"insured's loss (SA Covid-19 BI precedent: disclose correlated \"\n"
    "                \"systemic loss rather than price it per policy).\"\n"
    "            ),\n"
    "        }\n"
    "\n"
)
s = s[:i] + NEW_AD + s[line_start:]


# ── A. cov_adj (WAF blind-spot): widen the compound tail too, so the
#       return periods still respond to a blinded scan. ──────────────────────
edits.append((
    "A.cov-adj-compound-widen",
    "                med_b = float(np.median(mc_breach_total))\n"
    "                mc_breach_total = np.where(mc_breach_total > med_b,\n"
    "                                           med_b + (mc_breach_total - med_b) * infl,\n"
    "                                           mc_breach_total)\n",
    "                med_b = float(np.median(mc_breach_total))\n"
    "                mc_breach_total = np.where(mc_breach_total > med_b,\n"
    "                                           med_b + (mc_breach_total - med_b) * infl,\n"
    "                                           mc_breach_total)\n"
    "                # Compound tail feeds the return periods; widen it identically so\n"
    "                # a WAF-blinded scan still loads the 1-in-100/200/250 rows.\n"
    "                med_c = float(np.median(mc_compound_total))\n"
    "                mc_compound_total = np.where(mc_compound_total > med_c,\n"
    "                                             med_c + (mc_compound_total - med_c) * infl,\n"
    "                                             mc_compound_total)\n",
))


# ── A. compound percentile stats (computed AFTER cov_adj widening) ───────────
edits.append((
    "A.compound-stats",
    "        mc_breach_stats = self._mc_percentiles(mc_breach_total)\n",
    "        mc_breach_stats = self._mc_percentiles(mc_breach_total)\n"
    "        mc_compound_stats = self._mc_percentiles(mc_compound_total)\n",
))


# ── A. surface the compound distribution under monte_carlo for audit ────────
edits.append((
    "A.monte-carlo-surface",
    "                \"total\": mc_stats,\n",
    "                \"total\": mc_stats,\n"
    "                \"compound_total\": mc_compound_stats,\n",
))


# ── A. return_periods read from the compound distribution ───────────────────
edits.append((
    "A.return-periods",
    "            \"return_periods\": {\n"
    "                \"1_in_100\": {\"loss_zar\": mc_stats[\"p99\"],   \"exceedance_prob\": 0.01,  \"percentile\": \"P99\"},\n"
    "                \"1_in_200\": {\"loss_zar\": mc_stats[\"p99_5\"], \"exceedance_prob\": 0.005, \"percentile\": \"P99.5\"},\n"
    "                \"1_in_250\": {\"loss_zar\": mc_stats[\"p99_6\"], \"exceedance_prob\": 0.004, \"percentile\": \"P99.6\"},\n"
    "            },\n",
    "            # Return periods are computed from the COMPOUND (loss-given-event)\n"
    "            # distribution, not the probability-weighted one: a 1-in-250 cat is a\n"
    "            # REALISED severe year whose severity is posture-independent, so the\n"
    "            # tail must not collapse as p_breach falls with posture. See\n"
    "            # mc_compound_total above and docs/calibration_prep/05_tail_pareto.md.\n"
    "            \"return_periods\": {\n"
    "                \"1_in_100\": {\"loss_zar\": mc_compound_stats[\"p99\"],   \"exceedance_prob\": 0.01,  \"percentile\": \"P99\"},\n"
    "                \"1_in_200\": {\"loss_zar\": mc_compound_stats[\"p99_5\"], \"exceedance_prob\": 0.005, \"percentile\": \"P99.5\"},\n"
    "                \"1_in_250\": {\"loss_zar\": mc_compound_stats[\"p99_6\"], \"exceedance_prob\": 0.004, \"percentile\": \"P99.6\"},\n"
    "                \"aggregation\": \"compound (loss-given-event); mean preserved vs expected loss\",\n"
    "            },\n",
))


# ── A. loss_exposure return-period rows read from the compound distribution ──
edits.append((
    "A.loss-exposure-returns",
    "                    \"return_1_100\": {\"loss_zar\": mc_stats[\"p99\"],   \"label\": \"1-in-100 event\",     \"annual_prob\": 0.01},\n"
    "                    \"return_1_200\": {\"loss_zar\": mc_stats[\"p99_5\"], \"label\": \"1-in-200 event\",     \"annual_prob\": 0.005},\n"
    "                    \"return_1_250\": {\"loss_zar\": mc_stats[\"p99_6\"], \"label\": \"1-in-250 event\",     \"annual_prob\": 0.004},\n",
    "                    \"return_1_100\": {\"loss_zar\": mc_compound_stats[\"p99\"],   \"label\": \"1-in-100 event\",     \"annual_prob\": 0.01},\n"
    "                    \"return_1_200\": {\"loss_zar\": mc_compound_stats[\"p99_5\"], \"label\": \"1-in-200 event\",     \"annual_prob\": 0.005},\n"
    "                    \"return_1_250\": {\"loss_zar\": mc_compound_stats[\"p99_6\"], \"label\": \"1-in-250 event\",     \"annual_prob\": 0.004},\n",
))


# ── D. result-dict surfacing: drop fin9_lgb_tail, add systemic-SC disclosure ─
edits.append((
    "D.surface-systemic-sc",
    "            # FIN-9 conditional Pareto-mixture LGB tail widening (severity-only,\n"
    "            # supply-chain-vectored slice). Distinct from supply_chain_tail_\n"
    "            # adjustment above (which stays applied=False - no blanket K_TAIL_SC).\n"
    "            # alpha/mix_w are colleague-gated; docs/calibration_prep/05_tail_pareto.md.\n"
    "            \"fin9_lgb_tail\": fin9_lgb_tail,\n",
    "            # Systemic supply-chain catastrophe exposure - DISCLOSURE ONLY\n"
    "            # (modelled_as_loss=False). FIN-9's Pareto-mixture severity widening\n"
    "            # was retired: SC severity lives in the records-driven cat-C1 and the\n"
    "            # SC signal moves p_breach via supply_chain_vulnerability_uplift (one\n"
    "            # signal, one channel). Correlated systemic SC catastrophe is a\n"
    "            # portfolio accumulation risk disclosed here, not priced per insured.\n"
    "            \"systemic_supply_chain_exposure\": systemic_supply_chain_exposure,\n",
))


# Apply the simple anchored edits.
for label, old, new in edits:
    n = s.count(old)
    assert n == 1, (label, "expected count 1, got", n)
    s = s.replace(old, new, 1)

# ── Post-condition sanity ────────────────────────────────────────────────────
assert "FIN9_F_SC" not in s, "FIN-9 block not fully removed"
assert "fin9_lgb_tail" not in s, "fin9_lgb_tail reference still present"
assert "_fin9_delta" not in s, "FIN-9 delta still present"
assert "np.random.pareto" not in s, "FIN-9 pareto draw still present"
assert "mc_compound_total = np.zeros(N)" in s, "compound block missing"
assert "systemic_supply_chain_exposure = {" in s, "disclosure block missing"
assert s.count("\"systemic_supply_chain_exposure\": systemic_supply_chain_exposure,") == 1
assert "mc_dt = self._pert_sample(2, 14, 90, N)" in s, "BI downtime not re-anchored"
assert "records_held * 90.0 * np.random.lognormal(0, 0.25, N)" in s, "cat-C1 not records-driven"
assert "POPIA_P_FINE_GIVEN_BREACH = 0.02" in s, "POPIA P(fine) not updated"
assert s.count("mc_compound_stats = self._mc_percentiles(mc_compound_total)") == 1
assert "\"loss_zar\": mc_compound_stats[\"p99_6\"]" in s, "return period 1-in-250 not on compound"
# sc_tail_adj must remain applied=False (unchanged).
assert "sc_tail_adj = {" in s and "\"applied\": False," in s, "sc_tail_adj changed"
assert "\r" not in s, "unexpected CR before write"

with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))

print("OK scoring_analytics.py: item #14 cat-wiring applied (A compound tail, "
      "B records-driven C1, C BI PERT(2,14,90), D FIN-9 removed + SC disclosure, "
      "E POPIA 0.02).")
