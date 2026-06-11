# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (2026-06-08) Lever 2: floor the capacity factor used for the FIXED-CAP
statutory fines (POPIA s109 R10M, ECTA, sector ceilings) so a small entity that
QUALIFIES for them faces most of the genuine statutory exposure in the catastrophe
view - a serious breach at a micro FSP can attract close to the full R10M, which the
capacity-scaled-down model under-states. The %-of-turnover frameworks (GDPR, CPA,
PCI) are NOT touched (they already scale with revenue). Only qualifying fines fire
(POPIA baseline; GDPR/PCI/sector by reg_flags). CRLF-safe. NOT shipped by this script."""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA = os.path.join(ROOT, "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s
n = 0

# 1. Define fine_capacity_factor right after capacity_factor.
OLD = "        capacity_factor = self._capacity_factor(annual_revenue_zar)\n"
NEW = (
    "        capacity_factor = self._capacity_factor(annual_revenue_zar)\n"
    "        # Lever 2 (cat refinement, 2026-06-08): a statutory FIXED-CAP fine\n"
    "        # (POPIA s109 R10M, ECTA, sector ceilings) does not scale down with\n"
    "        # company size the way discretionary enforcement does - a serious\n"
    "        # breach at a micro FSP can attract most of the statutory ceiling in a\n"
    "        # 1-in-X catastrophe. Floor the capacity factor used for the fixed-cap\n"
    "        # fines so small QUALIFYING entities carry genuine fine exposure. The\n"
    "        # %-of-turnover frameworks (GDPR / CPA / PCI) are untouched - they\n"
    "        # already scale with revenue. Only the fines that QUALIFY fire (POPIA\n"
    "        # baseline; GDPR / PCI / sector by reg_flags), so this lifts real\n"
    "        # exposure, not phantom fines.\n"
    "        FINE_CAPACITY_FLOOR = 0.60\n"
    "        fine_capacity_factor = max(capacity_factor, FINE_CAPACITY_FLOOR)\n"
)
assert s.count(OLD) == 1, ("capacity_factor anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 2-6. Swap capacity_factor -> fine_capacity_factor on the fixed-cap fine sites.
for tag, old, new in [
    ("sector_cat_scaled",
     "        sector_cat_scaled = int(round(sector_cat_raw * capacity_factor))\n",
     "        sector_cat_scaled = int(round(sector_cat_raw * fine_capacity_factor))\n"),
    ("sector_cat_breakdown",
     "             \"cat_scaled_zar\": int(round(stat_max * capacity_factor))}\n",
     "             \"cat_scaled_zar\": int(round(stat_max * fine_capacity_factor))}\n"),
    ("popia cat-stack",
     "            c2_popia_statutory_max * capacity_factor  # statutory POPIA at cat\n",
     "            c2_popia_statutory_max * fine_capacity_factor  # statutory POPIA at cat\n"),
    ("ecta cat-stack",
     "            + c2_ecta_cat * capacity_factor\n",
     "            + c2_ecta_cat * fine_capacity_factor\n"),
    ("popia display",
     "                        int(round(c2_popia_statutory_max * capacity_factor)),\n",
     "                        int(round(c2_popia_statutory_max * fine_capacity_factor)),\n"),
    ("ecta display",
     "                        int(round(c2_ecta_cat * capacity_factor)),\n",
     "                        int(round(c2_ecta_cat * fine_capacity_factor)),\n"),
    ("capacity display",
     "                    \"capacity_factor\": round(capacity_factor, 3),\n",
     "                    \"capacity_factor\": round(capacity_factor, 3),\n"
     "                    \"fine_capacity_factor\": round(fine_capacity_factor, 3),\n"),
]:
    assert s.count(old) == 1, (tag, s.count(old))
    s = s.replace(old, new, 1); n += 1

ast.parse(s)
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(SA, encoding="utf-8").read())
print(f"OK scoring_analytics.py: {n} edits (Lever-2 fine-capacity floor=0.60 on POPIA/ECTA/sector).")
