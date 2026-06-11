# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #15, user-approved): make the catastrophe return periods
posture-INDEPENDENT by basing them on the SEVERITY of a single severe event
(double-extortion full-stack: C1+C2+C3+C4+C5), i.e. a PML / cover-sizing view,
instead of the compound realised-annual-loss distribution (which retained a
modest frequency-dependence). Frequency now lives only in the separate breach /
cyber-incident probability outputs. Severities don't depend on the risk score,
so the 1-in-100/200/250 are now FLAT across posture.

Definitional note baked into the output: these are severity percentiles
CONDITIONAL on a severe breach, NOT literal annual-frequency return periods.
The compound distribution is retained under monte_carlo.compound_total for audit.
CRLF-preserving. NOT shipped.
"""
import os

SA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

edits = []

# 1. Define the severity-PML array right after the compound loop.
edits.append((
    "pml-define",
    "            mc_compound_total += np.where(_occurs, _sev, 0.0)\n",
    "            mc_compound_total += np.where(_occurs, _sev, 0.0)\n"
    "\n"
    "        # Severity-PML (posture-independent cover view): the loss distribution\n"
    "        # of a single severe (double-extortion full-stack) event. Severities do\n"
    "        # NOT depend on the risk score, so these return periods are FLAT across\n"
    "        # posture - a realised catastrophe is severe regardless of how likely it\n"
    "        # was. Frequency is reported separately (breach / cyber-incident\n"
    "        # probability). These are severity percentiles CONDITIONAL on a severe\n"
    "        # breach, NOT literal annual-frequency return periods.\n"
    "        mc_pml_severity = mc_c1 + mc_c2 + mc_c4 + mc_c5 + mc_c3_full\n",
))

# 2. cov_adj (WAF blind-spot): widen the PML tail too, so a blinded scan still
#    loads the cat rows (mirrors the compound widening).
edits.append((
    "pml-cov-adj",
    "                med_c = float(np.median(mc_compound_total))\n"
    "                mc_compound_total = np.where(mc_compound_total > med_c,\n"
    "                                             med_c + (mc_compound_total - med_c) * infl,\n"
    "                                             mc_compound_total)\n",
    "                med_c = float(np.median(mc_compound_total))\n"
    "                mc_compound_total = np.where(mc_compound_total > med_c,\n"
    "                                             med_c + (mc_compound_total - med_c) * infl,\n"
    "                                             mc_compound_total)\n"
    "                # PML severity feeds the return periods; widen it identically.\n"
    "                med_p = float(np.median(mc_pml_severity))\n"
    "                mc_pml_severity = np.where(mc_pml_severity > med_p,\n"
    "                                           med_p + (mc_pml_severity - med_p) * infl,\n"
    "                                           mc_pml_severity)\n",
))

# 3. Percentile stats for the PML severity (next to the compound stats).
edits.append((
    "pml-stats",
    "        mc_compound_stats = self._mc_percentiles(mc_compound_total)\n",
    "        mc_compound_stats = self._mc_percentiles(mc_compound_total)\n"
    "        mc_pml_stats = self._mc_percentiles(mc_pml_severity)\n",
))

# 4. Surface the PML under monte_carlo for audit (alongside compound_total).
edits.append((
    "pml-surface",
    "                \"compound_total\": mc_compound_stats,\n",
    "                \"compound_total\": mc_compound_stats,\n"
    "                \"severity_pml\": mc_pml_stats,\n",
))

# 5. return_periods read the PML severity (posture-independent).
edits.append((
    "pml-return-periods",
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
    "            # Return periods are the SEVERITY of a single severe (double-extortion\n"
    "            # full-stack) event - a PML / cover-sizing view. Severities are\n"
    "            # posture-independent, so these are FLAT across the risk score: a\n"
    "            # realised catastrophe is severe regardless of how likely it was. The\n"
    "            # annual frequency is reported separately (breach / cyber-incident\n"
    "            # probability outputs). NOTE: these are severity percentiles\n"
    "            # CONDITIONAL on a severe breach, NOT literal annual-frequency return\n"
    "            # periods - the percentile labels describe the severity tier.\n"
    "            \"return_periods\": {\n"
    "                \"1_in_100\": {\"loss_zar\": mc_pml_stats[\"p99\"],   \"exceedance_prob\": 0.01,  \"percentile\": \"P99\"},\n"
    "                \"1_in_200\": {\"loss_zar\": mc_pml_stats[\"p99_5\"], \"exceedance_prob\": 0.005, \"percentile\": \"P99.5\"},\n"
    "                \"1_in_250\": {\"loss_zar\": mc_pml_stats[\"p99_6\"], \"exceedance_prob\": 0.004, \"percentile\": \"P99.6\"},\n"
    "                \"basis\": \"severity-PML (single severe event); posture-independent; conditional on a severe breach, not an annual frequency\",\n"
    "            },\n",
))

# 6. loss_exposure return-period rows read the PML severity.
edits.append((
    "pml-loss-exposure",
    "                    \"return_1_100\": {\"loss_zar\": mc_compound_stats[\"p99\"],   \"label\": \"1-in-100 event\",     \"annual_prob\": 0.01},\n"
    "                    \"return_1_200\": {\"loss_zar\": mc_compound_stats[\"p99_5\"], \"label\": \"1-in-200 event\",     \"annual_prob\": 0.005},\n"
    "                    \"return_1_250\": {\"loss_zar\": mc_compound_stats[\"p99_6\"], \"label\": \"1-in-250 event\",     \"annual_prob\": 0.004},\n",
    "                    \"return_1_100\": {\"loss_zar\": mc_pml_stats[\"p99\"],   \"label\": \"Severe event (P99 severity)\",   \"annual_prob\": None},\n"
    "                    \"return_1_200\": {\"loss_zar\": mc_pml_stats[\"p99_5\"], \"label\": \"Extreme event (P99.5 severity)\", \"annual_prob\": None},\n"
    "                    \"return_1_250\": {\"loss_zar\": mc_pml_stats[\"p99_6\"], \"label\": \"Catastrophic (P99.6 severity)\",  \"annual_prob\": None},\n",
))

for label, old, new in edits:
    n = s.count(old)
    assert n == 1, (label, "expected 1, got", n)
    s = s.replace(old, new, 1)

assert "mc_pml_severity = mc_c1 + mc_c2 + mc_c4 + mc_c5 + mc_c3_full" in s
assert "mc_pml_stats = self._mc_percentiles(mc_pml_severity)" in s
assert s.count("mc_pml_stats[\"p99") == 6  # 3 return_periods + 3 loss_exposure
assert "\r" not in s
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print("OK scoring_analytics.py: cat return periods -> severity-PML (posture-independent).")
