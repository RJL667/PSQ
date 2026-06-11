# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #15): re-baseline verify_supply_chain_financial_wiring.py for the
severity-PML cat. The return periods are now posture-independent, so SC
probability signals correctly do NOT move fin_p99/p99_5 (delta == 0 exactly).
Drop those assertions, keep the ALE (fin_most_likely) + score assertions that
prove wiring, and ADD an explicit invariance lock in the worst-stack block.
CRLF-preserving. NOT shipped."""
import os

V = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "tooling", "verify_supply_chain_financial_wiring.py")
s = open(V, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

edits = []

# 1. related_domains: drop the fin_p99 expectation.
edits.append((
    "related_domains",
    "            (\"fin_most_likely\", True, 0, 0.5),\n"
    "            (\"fin_p99\", True, 0, 0.5),\n"
    "        ],\n",
    "            (\"fin_most_likely\", True, 0, 0.5),\n"
    "            # fin_p99 (cat) is now severity-PML - posture-independent, so SC\n"
    "            # probability signals correctly do NOT move it (locked invariant in\n"
    "            # the worst-stack block). It moves the ALE + scores instead.\n"
    "        ],\n",
))

# 2. vendor_breach: drop fin_p99 + fin_p99_5, keep fin_most_likely.
edits.append((
    "vendor_breach",
    "            (\"overall_risk_score\", True, 0, 0.5),\n"
    "            # No separate K_TAIL_SC widening — supply-chain effect flows\n"
    "            # through the vulnerability uplift only (per 2026-05-27 design\n"
    "            # review). The MC distribution shifts up naturally, so any\n"
    "            # positive movement on fin_p99 proves wiring without needing\n"
    "            # a large delta threshold.\n"
    "            (\"fin_p99\", True, 0, 0.1),\n"
    "            (\"fin_p99_5\", True, 0, 0.1),\n"
    "            (\"fin_most_likely\", True, 0, 0.1),\n"
    "        ],\n",
    "            (\"overall_risk_score\", True, 0, 0.5),\n"
    "            # Cat (fin_p99/p99_5) is now severity-PML - posture-independent, so\n"
    "            # SC probability signals do NOT move it (locked invariant in the\n"
    "            # worst-stack block). SC flows through the ALE + scores instead.\n"
    "            (\"fin_most_likely\", True, 0, 0.1),\n"
    "        ],\n",
))

# 3. worst_stack: replace the fin_p99 'must increase 5%' with an invariance lock.
edits.append((
    "worst_stack",
    "    _assert_moves(\"worst_stack\", baseline, after_all, \"fin_p99\",\n"
    "                   must_increase=True, min_delta_pct=5.0,\n"
    "                   passes=passes, failures=failures)\n",
    "    # Cat return periods are now severity-PML (posture-independent): the SC\n"
    "    # stack raises p_breach / rsi / the ALE, but must leave the cat UNCHANGED\n"
    "    # (a realised catastrophe is severe regardless of how likely it was).\n"
    "    if abs((after_all[\"fin_p99\"] or 0) - (baseline[\"fin_p99\"] or 0)) < 1.0:\n"
    "        passes.append((\"worst_stack\", \"fin_p99 invariant (severity-PML)\", None, True, None))\n"
    "        print(\"PASS [worst_stack] fin_p99 invariant under SC stack (severity-PML, posture-independent)\")\n"
    "    else:\n"
    "        failures.append((\"worst_stack\", \"fin_p99 not invariant\", None, after_all[\"fin_p99\"], None, False))\n"
    "        print(f\"FAIL [worst_stack] fin_p99 moved under SC stack (should be invariant): \"\n"
    "              f\"{baseline['fin_p99']:,.0f} -> {after_all['fin_p99']:,.0f}\")\n",
))

# 4. Update the stale #14 'compound' note to reflect the PML.
edits.append((
    "note",
    "        # NOTE (item #14, 2026-06-04): return_periods now read the COMPOUND\n"
    "        # (loss-given-event) distribution, not the prob-weighted one. These\n"
    "        # assertions are RELATIVE (directional / min-delta), so no numeric\n"
    "        # baseline changed - the thresholds were re-confirmed under compound\n"
    "        # (31/31 PASS). A 1-in-100/250 that holds with posture is expected.\n",
    "        # NOTE (item #15, 2026-06-05): return_periods are now the severity-PML\n"
    "        # (single severe event), which is POSTURE-INDEPENDENT. SC probability\n"
    "        # signals deliberately do NOT move fin_p99/p99_5 (asserted invariant in\n"
    "        # the worst-stack block); they move the ALE (fin_most_likely) + scores.\n",
))

for label, old, new in edits:
    n = s.count(old)
    assert n == 1, (label, "expected 1, got", n)
    s = s.replace(old, new, 1)

assert "fin_p99 invariant under SC stack" in s
assert "severity-PML" in s
assert "\r" not in s
with open(V, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print("OK verify_supply_chain_financial_wiring.py: re-baselined for severity-PML cat.")
