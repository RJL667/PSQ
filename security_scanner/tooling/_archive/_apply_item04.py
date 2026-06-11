#!/usr/bin/env python3
"""SANDBOX one-off (item 0.3 / task #4): replace the linear posture->vulnerability
placeholder with the calibrated CONVEX curve (s/1000)^1.8, retaining the 0.3 scalar.
Anchored + asserted so it fails safe. Run from security_scanner/. NOT shipped."""
import os

P = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "scoring_analytics.py")
s = open(P, encoding="utf-8").read()

start_anchor = '        overall_score = categories.get("_overall_score", 500)\n'
old_code = ("        vulnerability = min(1.0, max(0.0, overall_score / 1000))"
            "  # 0.0 (no risk) -> 1.0 (max risk)\n")
assert s.count(start_anchor) == 1, ("start_anchor", s.count(start_anchor))
assert s.count(old_code) == 1, ("old_code", s.count(old_code))

i = s.index(start_anchor)
after = i + len(start_anchor)
j = s.index(old_code, after)
end = j + len(old_code)

new_comment = (
    "        # `_overall_score` is the 0-1000 overall RISK score (higher = worse), wired in at\n"
    "        # scanner.py. vulnerability = P(a threat event succeeds | posture) and must RISE\n"
    "        # with the risk score. CONVEX map (s/1000)^k, k=1.8 (FIN-9 calibration): a Low-\n"
    "        # posture org is genuinely safe; risk accelerates only toward Critical. Anchors:\n"
    "        # SecurityScorecard A->F breach-likelihood ladder 1.0->13.8x (steeply convex);\n"
    "        # BitSight/Marsh absolutes (>=700 rating <1%, <500 ~3%); Cyentia IRIS SMB loss-\n"
    "        # event <2%/yr. With the 0.3 scalar below: 169(Low)->1.8%, 300(Med)->5.0%,\n"
    "        # 450(High)->10.3%, 650(Crit)->20%, worst->36% (TEF=1.45). Bands: k in [1.5,2.0],\n"
    "        # 0.3 in [0.20,0.35]. COLLEAGUE-GATED: the absolute SME loss-event base rate\n"
    "        # (~1-3%) is triangulated, not firm; confirm we underwrite to loss-event vs\n"
    "        # material-incident (docs/calibration_prep/01_p_breach_core.md). 500 -> vuln 0.287.\n"
)
new_code = ("        vulnerability = (min(1000.0, max(0.0, overall_score)) / 1000.0) ** 1.8"
            "  # convex (s/1000)^k, k=1.8\n")

s2 = s[:after] + new_comment + new_code + s[end:]

assert "min(1.0, max(0.0, overall_score / 1000))" not in s2, "old linear curve still present"
assert "** 1.8" in s2, "convex curve missing"
assert "\r" not in s2, "unexpected CR in normalised buffer"
with open(P, "wb") as f:
    f.write(s2.replace("\n", "\r\n").encode("utf-8"))
print("OK: convex curve applied (k=1.8). chars", len(s), "->", len(s2))
