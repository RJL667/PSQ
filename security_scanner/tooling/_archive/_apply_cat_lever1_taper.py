# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (2026-06-08) Lever 1: small->large taper on the IBM-average C1 residual so
the catastrophe stops scaling to multiples of a small company's revenue. Applied to
BOTH the analytical c1_liability (most-likely) and the MC residual_floor (cat tail),
with one shared factor. Records-driven C1 and the C2 fines are NOT tapered (no cap).
CRLF-safe. NOT shipped by this script."""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA = os.path.join(ROOT, "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s
n = 0

# 1. Analytical C1 — compute the taper factor here, apply to the residual.
OLD = "        c1_liability = max(0, total_breach_magnitude - c2_regulatory_fine - c3_bi - c4_ransom - c5_ir)\n"
NEW = (
    "        # Lever 1 (cat refinement, 2026-06-08): small->large taper on the\n"
    "        # IBM-average C1 residual. The residual is the SA-average breach cost\n"
    "        # (IBM anchor) scaled to revenue minus the other pillars; that average\n"
    "        # is dominated by large-org breaches, so for sub-large-cap entities it\n"
    "        # over-states third-party liability (~60x the records-driven value at\n"
    "        # R10M -> a 1-in-250 of 343% of revenue). Taper the residual from\n"
    "        # CAT_RESIDUAL_TAPER_MIN at <=R10M to 1.0 at/above R2bn (where the floor\n"
    "        # is already non-binding and the upper end behaves). NO cap: records-\n"
    "        # driven C1 and the genuine C2 fines are untapered, so a small FSP can\n"
    "        # still exceed revenue via real exposure. Applied to the analytical C1\n"
    "        # (most-likely) and the MC residual_floor (cat tail) with one factor.\n"
    "        import math as _math\n"
    "        CAT_RESIDUAL_TAPER_MIN = 0.30\n"
    "        CAT_RESIDUAL_TAPER_HI_ZAR = 2_000_000_000\n"
    "        _cat_t = (_math.log10(max(float(annual_revenue_zar), 1.0)) - 7.0) / \\\n"
    "                 (_math.log10(CAT_RESIDUAL_TAPER_HI_ZAR) - 7.0)\n"
    "        cat_residual_taper = float(min(1.0, max(CAT_RESIDUAL_TAPER_MIN,\n"
    "                                       CAT_RESIDUAL_TAPER_MIN + (1.0 - CAT_RESIDUAL_TAPER_MIN) * _cat_t)))\n"
    "        c1_liability = cat_residual_taper * max(0, total_breach_magnitude - c2_regulatory_fine - c3_bi - c4_ransom - c5_ir)\n"
)
assert s.count(OLD) == 1, ("analytical c1", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 2. MC residual_floor — apply the same factor.
OLD = "        residual_floor = np.maximum(0, mc_total_breach - mc_c2 - mc_c3_full - mc_c4 - mc_c5)\n"
NEW = "        residual_floor = cat_residual_taper * np.maximum(0, mc_total_breach - mc_c2 - mc_c3_full - mc_c4 - mc_c5)\n"
assert s.count(OLD) == 1, ("MC residual_floor", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

ast.parse(s)
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(SA, encoding="utf-8").read())
print(f"OK scoring_analytics.py: {n} edits (Lever-1 C1 residual taper, MIN=0.30, HI=R2bn).")
