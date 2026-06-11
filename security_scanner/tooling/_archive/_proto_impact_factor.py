#!/usr/bin/env python3
"""SANDBOX (not shipped): pressure-test the BI IMPACT_FACTOR.
Standard BI = lost SALES x gross-profit-rate (variable costs saved are deducted),
NOT lost turnover. Current model: C3 = downtime x daily_REVENUE x 0.5 x bi_factor
-- the 0.5 is only the recovery curve; the gross-profit-rate is missing.
  C3 = downtime x daily_rev x RECOVERY(0.5) x bi_factor x GROSS_PROFIT_RATE
"""
import numpy as np
np.random.seed(42); N = 400_000
def pert(a, m, b, n, lamb=4.0):
    a, m, b = float(a), float(m), float(b)
    al = 1 + lamb * (m - a) / (b - a); be = 1 + lamb * (b - m) / (b - a)
    return a + np.random.beta(al, be, n) * (b - a)
def pe(x, q): return float(np.percentile(x, q))

DT = (2, 14, 90); RECOVERY = 0.5; SHARE, SIGMA = 0.20, 0.25

# takealot R20bn Consumer, 3m exposed records, bi=1.0
c1 = np.maximum(3_000_000 * (1580 * SHARE) * np.random.lognormal(0, SIGMA, N), 0)
c2, c4 = 10_000_000.0, 25_000_000.0
c5 = pert(2_500_000, 5_000_000, 12_500_000, N)
print("TAKEALOT R20bn Consumer, 3m records, downtime PERT(2,14,90):")
print(f"  {'gross-profit rate':>22}   {'C3/BI 1-in-250':>16}   {'TOTAL 1-in-250':>16}")
for gp, lbl in ((1.00, "1.00 = current (revenue)"), (0.50, "0.50"), (0.35, "0.35 (retail typical)"), (0.30, "0.30")):
    c3 = pert(*DT, N) * (20e9 / 365) * RECOVERY * 1.0 * gp
    tot = c1 + c2 + c3 + c4 + c5
    print(f"  {lbl:>22}   R{pe(c3,99.6):>14,.0f}   R{pe(tot,99.6):>14,.0f}")
print(f"\n  (C1 liability 1-in-250 = R{pe(c1,99.6):,.0f} -- once BI is on gross profit, C1 dominates the cat)")
