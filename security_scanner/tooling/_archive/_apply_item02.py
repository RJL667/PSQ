#!/usr/bin/env python3
"""SANDBOX one-off (item 0.2): remove the dead legacy-USD branch from
FinancialImpactCalculator.calculate() and the three constants that only it
used. Correctness-only: production always sends annual_revenue_zar>0, so this
must produce ZERO behavioural change on the live ZAR path.

Uses content anchors + asserts so it fails safe (writes nothing) if the source
has drifted. Run from security_scanner/.  NOT shipped.
"""
import os, sys

P = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "scoring_analytics.py")
s = open(P, encoding="utf-8").read()
orig_len, orig_lines = len(s), s.count("\n")

# ---- 1) Remove the three dead constants (only the USD branch referenced them).
const_block = (
    "    # Industry cost-per-record (IBM/Ponemon averages)\n"
    "    COST_PER_RECORD = {\n"
    '        "healthcare": 239, "finance": 219, "tech": 183,\n'
    '        "education": 173, "manufacturing": 165, "retail": 157,\n'
    '        "legal": 190, "government": 155, "other": 165,\n'
    "    }\n"
    "    # Regulatory fine estimates (typical ranges)\n"
    "    REGULATORY_FINE = {\n"
    '        "healthcare": 1_000_000, "finance": 750_000, "legal": 500_000,\n'
    '        "government": 250_000, "other": 250_000,\n'
    "    }\n"
    "    # Average ransom demand as % of revenue (capped)\n"
    "    RANSOM_PCT = 0.03  # 3% of annual revenue\n\n"
)
assert s.count(const_block) == 1, ("const_block count", s.count(const_block))
s = s.replace(const_block, "")

# ---- 2) Replace the routing + delete the dead USD body.
start_anchor = "        # Use ZAR path when ZAR revenue is provided (SA-specific model)\n"
# End anchor: the method's closing `return output` immediately followed by the
# (kept) class-level TEF comment block. The TEF comment is unique in the file.
end_anchor = (
    "        return output\n\n"
    "    # ------------------------------------------------------------------\n"
    "    # Threat Event Frequency (TEF) multipliers per industry\n"
)
assert s.count(start_anchor) == 1, ("start_anchor count", s.count(start_anchor))
assert s.count(end_anchor) == 1, ("end_anchor count", s.count(end_anchor))
i = s.index(start_anchor)
j = s.index(end_anchor)
assert j > i, ("anchors out of order", i, j)

ro = "        return output\n"
del_end = j + len(ro)  # keep everything from the blank line + TEF comment onward

new_routing = (
    "        # Production always uses the SA ZAR model. The scanner resolves the\n"
    "        # revenue basis via resolve_effective_revenue_zar() (peer_benchmarking),\n"
    "        # which floors an absent / non-positive value to R10M, so in production\n"
    "        # annual_revenue_zar is always > 0. We floor here too, so any direct\n"
    "        # caller (tests / tooling) routes through the same SA model rather than\n"
    "        # the legacy USD scenario branch that previously lived here. The USD\n"
    "        # `annual_revenue` argument is now vestigial (kept for call-site compat).\n"
    "        if annual_revenue_zar <= 0:\n"
    "            annual_revenue_zar = 10_000_000  # peer_benchmarking.DEFAULT_REVENUE_ZAR_WHEN_ABSENT\n"
    "        return self._calculate_zar(categories, rsi_result, annual_revenue_zar, industry,\n"
    "                                   regulatory_flags, sub_industry,\n"
    "                                   scan_completeness=scan_completeness)\n"
)

s2 = s[:i] + new_routing + s[del_end:]

# Sanity: the removed names must no longer appear (they lived only in the branch).
for dead in ("COST_PER_RECORD", "REGULATORY_FINE", "RANSOM_PCT",
             "Scenario 1: Data Breach", "Monte Carlo Simulation (USD)"):
    assert dead not in s2, ("residual after edit", dead)

# Original file is CRLF (autocrlf=true); read() normalised to \n, so write
# back as CRLF to avoid a whole-file line-ending diff.
assert "\r" not in s2, "unexpected CR in normalised buffer"
with open(P, "wb") as f:
    f.write(s2.replace("\n", "\r\n").encode("utf-8"))
print(f"OK: {orig_len}->{len(s2)} chars, {orig_lines}->{s2.count(chr(10))} lines "
      f"(removed {orig_lines - s2.count(chr(10))} lines)")
