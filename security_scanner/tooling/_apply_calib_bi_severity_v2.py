# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX revision (2026-06-05): replace the 25-day-ANCHORED duration-graded BI
impact factor with a flat ACUTE_IMPACT_FACTOR for short events, decoupled from the
(drifting) recovery-period figure.

Rationale: a linear 90%->10% recovery curve averages 0.50 over ANY span (25 or 80
days), so the ransomware-rebuild factor is duration-independent - 0.50 stays. An
acute outage (DDoS / short breach legs) is a DIFFERENT regime: near-full loss
throughout while down, no recovery tail. -> flat 0.85, no duration anchor. In the
MC the PERT day-count already carries duration, so intensity is flat.

  1. remove module-level _recovery_impact_factor() helper
  2. add local ACUTE_IMPACT_FACTOR = 0.85 next to IMPACT_FACTOR
  3. 4 central + 4 MC short-event sites -> ACUTE_IMPACT_FACTOR (MC reverts to 1-line)
  4. rewrite the part5 manual bullet (regime distinction)
CRLF-safe. NOT shipped by this script."""
import ast, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA = os.path.join(ROOT, "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s
n = 0

# 1. Remove the module-level helper (restore _grade_probability spacing) ─────
HELPER = (
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
assert s.count(HELPER) == 1, ("helper removal", s.count(HELPER))
s = s.replace(HELPER, "", 1); n += 1

# 2. Add ACUTE_IMPACT_FACTOR next to IMPACT_FACTOR ──────────────────────────
OLD = "        IMPACT_FACTOR = 0.50  # Average revenue loss across recovery period\n"
NEW = (
    "        IMPACT_FACTOR = 0.50  # Average revenue loss across recovery period\n"
    "        # Acute outages (DDoS + the short opportunistic / silent / extortion\n"
    "        # legs) are a DIFFERENT regime: while the service is down the loss is\n"
    "        # near-total throughout, with no 90->10 recovery tail to average\n"
    "        # against. A linear 90->10 recovery averages 0.50 for ANY recovery\n"
    "        # length (25 or 80 days), so the rebuild factor is duration-independent;\n"
    "        # acute events are flat-high and decoupled from the (drifting) recovery\n"
    "        # period. In the MC the PERT day-count carries the duration spread.\n"
    "        ACUTE_IMPACT_FACTOR = 0.85\n"
)
assert s.count(OLD) == 1, ("impact_factor anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 3. Central short events ──────────────────────────────────────────────────
for tag, old, new in [
    ("c3_silent",
     "c3_silent = 2 * daily_revenue * _recovery_impact_factor(2) * bi_factor  # minimal downtime (acute, duration-graded)",
     "c3_silent = 2 * daily_revenue * ACUTE_IMPACT_FACTOR * bi_factor  # minimal downtime (acute outage)"),
    ("c3_extort",
     "c3_extort = 3 * daily_revenue * _recovery_impact_factor(3) * bi_factor",
     "c3_extort = 3 * daily_revenue * ACUTE_IMPACT_FACTOR * bi_factor"),
    ("c3_opp",
     "c3_opp = 1 * daily_revenue * _recovery_impact_factor(1) * bi_factor",
     "c3_opp = 1 * daily_revenue * ACUTE_IMPACT_FACTOR * bi_factor"),
    ("c3_ddos",
     "c3_ddos = 5 * daily_revenue * _recovery_impact_factor(5) * bi_factor",
     "c3_ddos = 5 * daily_revenue * ACUTE_IMPACT_FACTOR * bi_factor"),
]:
    assert s.count(old) == 1, (tag, s.count(old))
    s = s.replace(old, new, 1); n += 1

# 4. Monte-Carlo short events (revert per-sample capture -> flat) ───────────
for tag, old, new in [
    ("mc_c3_silent",
     "        mc_dt_silent = self._pert_sample(1, 2, 5, N)\n"
     "        mc_c3_silent = mc_dt_silent * daily_revenue * _recovery_impact_factor(mc_dt_silent) * bi_factor\n",
     "        mc_c3_silent = self._pert_sample(1, 2, 5, N) * daily_revenue * ACUTE_IMPACT_FACTOR * bi_factor\n"),
    ("mc_c3_extort",
     "        mc_dt_extort = self._pert_sample(1, 3, 21, N)\n"
     "        mc_c3_extort = mc_dt_extort * daily_revenue * _recovery_impact_factor(mc_dt_extort) * bi_factor\n",
     "        mc_c3_extort = self._pert_sample(1, 3, 21, N) * daily_revenue * ACUTE_IMPACT_FACTOR * bi_factor\n"),
    ("mc_c3_opp",
     "        mc_dt_opp = self._pert_sample(0.5, 1, 3, N)\n"
     "        mc_c3_opp = mc_dt_opp * daily_revenue * _recovery_impact_factor(mc_dt_opp) * bi_factor\n",
     "        mc_c3_opp = self._pert_sample(0.5, 1, 3, N) * daily_revenue * ACUTE_IMPACT_FACTOR * bi_factor\n"),
    ("mc_c3_ddos",
     "        mc_c3_ddos = mc_dt_ddos * daily_revenue * _recovery_impact_factor(mc_dt_ddos) * bi_factor\n",
     "        mc_c3_ddos = mc_dt_ddos * daily_revenue * ACUTE_IMPACT_FACTOR * bi_factor\n"),
]:
    assert s.count(old) == 1, (tag, s.count(old))
    s = s.replace(old, new, 1); n += 1

assert "_recovery_impact_factor" not in s, "stale helper reference remains"
ast.parse(s)
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(SA, encoding="utf-8").read())
print(f"OK scoring_analytics.py: {n} edits (flat ACUTE_IMPACT_FACTOR=0.85, helper removed).")

# 5. Manual lock rewrite (part5) ───────────────────────────────────────────
P5 = os.path.join(ROOT, "manual_parts", "part5_tech_compliance_insurance.py")
m = open(P5, encoding="utf-8").read()
assert "\r" not in m
OLDM = (
    "    add_bullet(doc,\n"
    "        \"C3 revenue impact is duration-graded. The daily revenue-loss \"\n"
    "        \"fraction follows the recovery curve - roughly 90 percent on day one \"\n"
    "        \"easing to about 10 percent by the 25-day mark - so its average over \"\n"
    "        \"an outage depends on the outage length. A long 25-day ransomware \"\n"
    "        \"rebuild averages to 50 percent (the long-standing figure), but short \"\n"
    "        \"acute events lose near their full daily revenue throughout: a one-day \"\n"
    "        \"opportunistic outage uses about 90 percent, a five-day denial-of-\"\n"
    "        \"service outage about 83 percent. This was corrected on 5 June 2026, \"\n"
    "        \"replacing a single flat 50 percent that had under-counted the \"\n"
    "        \"severity of short, sharp outages.\"\n"
    "    )\n"
)
NEWM = (
    "    add_bullet(doc,\n"
    "        \"C3 distinguishes two outage regimes. A ransomware or breach REBUILD \"\n"
    "        \"recovers gradually - revenue loss easing from roughly 90 percent on \"\n"
    "        \"day one to about 10 percent by the end of recovery - which averages \"\n"
    "        \"to 50 percent over the recovery period regardless of how long that \"\n"
    "        \"period runs (a linear 90-to-10 curve averages 50 percent whether \"\n"
    "        \"recovery takes 25 days or 80, so this figure does not drift as \"\n"
    "        \"recovery times change). An ACUTE outage such as a denial-of-service \"\n"
    "        \"attack is a different regime: while it is live the service is simply \"\n"
    "        \"down, at near-full revenue loss throughout, with no gradual-recovery \"\n"
    "        \"tail to average against. Acute events (denial-of-service and the \"\n"
    "        \"short opportunistic, silent and extortion legs) therefore use a flat \"\n"
    "        \"85 percent daily impact, independent of the average recovery period, \"\n"
    "        \"while the longer rebuilds retain the 50 percent recovery average. \"\n"
    "        \"Corrected on 5 June 2026; previously a single flat 50 percent had \"\n"
    "        \"under-counted short, sharp outages.\"\n"
    "    )\n"
)
assert m.count(OLDM) == 1, ("manual bullet", m.count(OLDM))
m = m.replace(OLDM, NEWM, 1)
ast.parse(m)
with open(P5, "wb") as f:
    f.write(m.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P5, encoding="utf-8").read())
print("OK part5: manual lock rewritten (regime distinction; decoupled from recovery period).")
