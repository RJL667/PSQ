# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX severity mutator (2026-06-05) for scoring_analytics.py: duration-graded
BI impact factor for SHORT acute events. The flat IMPACT_FACTOR=0.50 is the
model's 90%->10%/25-day recovery curve PRE-AVERAGED for a 25-day rebuild; applying
it to 1-5 day acute events (DDoS + opportunistic/silent/extortion breach legs)
understates severity (an acute outage stays near full loss throughout). Replace
with _recovery_impact_factor(days) = 0.90 - (0.40/24)*(days-1) clamped [0.50,0.90]
- the SAME curve un-averaged. 25-day ransomware legs keep the 0.50 literal.
CRLF-safe. NOT shipped by this script."""
import ast, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA = os.path.join(ROOT, "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s
n = 0

# ── Helper: append after _grade_probability ────────────────────────────────
OLD = (
    "def _grade_probability(pct, bands):\n"
    "    \"\"\"Map a percentage probability to its segregated band label (reporting-only).\"\"\"\n"
    "    for upper, label in bands:\n"
    "        if pct < upper:\n"
    "            return label\n"
    "    return bands[-1][1]\n"
)
NEW = OLD + (
    "\n\n"
    "def _recovery_impact_factor(days):\n"
    "    \"\"\"Duration-graded BI revenue-impact factor (severity, C3).\n"
    "\n"
    "    Derived from the model's OWN recovery curve: revenue loss declines roughly\n"
    "    linearly from ~0.90 on day 1 to ~0.10 by day 25, so the AVERAGE impact over\n"
    "    a D-day outage = 0.90 - (0.40/24)*(D-1). Short ACUTE events stay near full\n"
    "    loss throughout (no 25-day decay to average down): 1d -> 0.90, 5d (DDoS) ->\n"
    "    0.83. The 25-day ransomware rebuild averages to 0.50 - the old flat constant,\n"
    "    now just the D=25 special case (the ransomware legs keep the 0.50 literal).\n"
    "    Clamped [0.50, 0.90]. Accepts a scalar (central path) or a numpy array\n"
    "    (per-sample Monte-Carlo downtimes).\"\"\"\n"
    "    f = 0.90 - (0.40 / 24.0) * (days - 1.0)\n"
    "    try:\n"
    "        return max(0.50, min(0.90, f))      # scalar (central) path\n"
    "    except (TypeError, ValueError):\n"
    "        import numpy as np                  # numpy-array (Monte-Carlo) path\n"
    "        return np.clip(f, 0.50, 0.90)\n"
)
assert s.count(OLD) == 1, ("helper anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# ── Central short events (fixed day counts) ────────────────────────────────
for tag, old, new in [
    ("c3_silent",
     "c3_silent = 2 * daily_revenue * IMPACT_FACTOR * bi_factor  # minimal downtime",
     "c3_silent = 2 * daily_revenue * _recovery_impact_factor(2) * bi_factor  # minimal downtime (acute, duration-graded)"),
    ("c3_extort",
     "c3_extort = 3 * daily_revenue * IMPACT_FACTOR * bi_factor",
     "c3_extort = 3 * daily_revenue * _recovery_impact_factor(3) * bi_factor"),
    ("c3_opp",
     "c3_opp = 1 * daily_revenue * IMPACT_FACTOR * bi_factor",
     "c3_opp = 1 * daily_revenue * _recovery_impact_factor(1) * bi_factor"),
    ("c3_ddos",
     "c3_ddos = 5 * daily_revenue * IMPACT_FACTOR * bi_factor",
     "c3_ddos = 5 * daily_revenue * _recovery_impact_factor(5) * bi_factor"),
]:
    assert s.count(old) == 1, (tag, s.count(old))
    s = s.replace(old, new, 1); n += 1

# ── Monte-Carlo short events (per-sample graded) ───────────────────────────
for tag, old, new in [
    ("mc_c3_silent",
     "        mc_c3_silent = self._pert_sample(1, 2, 5, N) * daily_revenue * IMPACT_FACTOR * bi_factor\n",
     "        mc_dt_silent = self._pert_sample(1, 2, 5, N)\n"
     "        mc_c3_silent = mc_dt_silent * daily_revenue * _recovery_impact_factor(mc_dt_silent) * bi_factor\n"),
    ("mc_c3_extort",
     "        mc_c3_extort = self._pert_sample(1, 3, 21, N) * daily_revenue * IMPACT_FACTOR * bi_factor\n",
     "        mc_dt_extort = self._pert_sample(1, 3, 21, N)\n"
     "        mc_c3_extort = mc_dt_extort * daily_revenue * _recovery_impact_factor(mc_dt_extort) * bi_factor\n"),
    ("mc_c3_opp",
     "        mc_c3_opp = self._pert_sample(0.5, 1, 3, N) * daily_revenue * IMPACT_FACTOR * bi_factor\n",
     "        mc_dt_opp = self._pert_sample(0.5, 1, 3, N)\n"
     "        mc_c3_opp = mc_dt_opp * daily_revenue * _recovery_impact_factor(mc_dt_opp) * bi_factor\n"),
    ("mc_c3_ddos",
     "        mc_c3_ddos = mc_dt_ddos * daily_revenue * IMPACT_FACTOR * bi_factor\n",
     "        mc_c3_ddos = mc_dt_ddos * daily_revenue * _recovery_impact_factor(mc_dt_ddos) * bi_factor\n"),
]:
    assert s.count(old) == 1, (tag, s.count(old))
    s = s.replace(old, new, 1); n += 1

ast.parse(s)
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(SA, encoding="utf-8").read())
print(f"OK scoring_analytics.py: {n} edits (helper + 4 central + 4 MC short-event "
      f"impact factors duration-graded; 25-day ransomware legs keep 0.50). AST valid.")
