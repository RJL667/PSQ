#!/usr/bin/env python3
"""SANDBOX (not shipped): exposed-record fraction — the cat-C1 lever.

cat_C1 = (total_records × EXPOSED_FRACTION) × (cpr × SHARE) × lognormal(SIGMA), floored at residual.
EXPOSED_FRACTION = fraction of held records that translate to COMPENSABLE liability in a cat
  (full-database exfil exposes ~all, but SA litigation propensity is low vs US class-action).
takealot is eCommerce -> bi_factor 1.5 (the corrected sub-industry).
"""
import numpy as np
np.random.seed(42); N = 400_000; IMPACT = 0.5
def pert(a, m, b, n, lamb=4.0):
    a, m, b = float(a), float(m), float(b)
    al = 1 + lamb * (m - a) / (b - a); be = 1 + lamb * (b - m) / (b - a)
    return a + np.random.beta(al, be, n) * (b - a)
def pe(x, q): return float(np.percentile(x, q))

SHARE, SIGMA = 0.20, 0.25
DT = (2, 14, 90)
REV, CPR, BI = 20e9, 1580, 1.5          # takealot eCommerce
TOTAL_RECORDS = 10_000_000               # client-provided base
C2, C4, C5T = 10_000_000.0, 25_000_000.0, 5_000_000.0

c3 = pert(*DT, N) * (REV / 365) * IMPACT * BI
c5 = pert(C5T * 0.5, C5T, C5T * 2.5, N)
print(f"takealot eCommerce(bi=1.5)  C3/BI 1-in-250 = R{pe(c3,99.6):,.0f}   (median R{pe(c3,50):,.0f})")
print(f"target TOTAL 1-in-250 = R2-5bn\n")
print(f"  {'exposed %':>10} {'exp records':>13} {'C1 1-in-250':>15} {'TOTAL 1-in-250':>16}")
for frac in (1.00, 0.50, 0.35, 0.25, 0.15):
    er = TOTAL_RECORDS * frac
    c1 = np.maximum(er * (CPR * SHARE) * np.random.lognormal(0, SIGMA, N), 0)
    tot = c1 + c3 + C2 + C4 + c5
    flag = "  <-- in band" if 2e9 <= pe(tot, 99.6) <= 5e9 else ""
    print(f"  {frac:>9.0%} {er:>13,.0f} R{pe(c1,99.6):>13,.0f} R{pe(tot,99.6):>14,.0f}{flag}")
print(f"\n  effective SA per-record liability at each frac = cpr×share×frac = "
      f"R{CPR*SHARE*1.0:.0f}(100%) .. R{CPR*SHARE*0.35:.0f}(35%) .. R{CPR*SHARE*0.15:.0f}(15%)")
