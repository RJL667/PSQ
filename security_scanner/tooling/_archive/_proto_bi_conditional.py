#!/usr/bin/env python3
"""SANDBOX (not shipped): downtime is conditional on IR posture.
  COLD IR     PERT(2,14,90)  - no EDR/MDR; Sophos Rapid Response goes in cold (~2wk mode)
  MANAGED/EDR PERT(1, 4,21)  - EDR/MDR already deployed (e.g. Sophos-managed client) (~few days)
The blended PERT(2,14,90) is right for an UNKNOWN org; the fast tier applies only to a
VERIFIED EDR-deployed / Sophos-managed client.
"""
import numpy as np
np.random.seed(42); N = 400_000; IMPACT = 0.5
def pert(a, m, b, n, lamb=4.0):
    a, m, b = float(a), float(m), float(b)
    al = 1 + lamb * (m - a) / (b - a); be = 1 + lamb * (b - m) / (b - a)
    return a + np.random.beta(al, be, n) * (b - a)
def pe(x, q): return float(np.percentile(x, q))

COLD = (2, 14, 90); MANAGED = (1, 4, 21)
SHARE, SIGMA = 0.20, 0.25
def cat(rev, cpr, bi, c5, c4, resid, records, dt):
    daily = rev / 365.0
    c3 = pert(*dt, N) * daily * IMPACT * bi
    c1 = np.maximum(records * (cpr * SHARE) * np.random.lognormal(0, SIGMA, N), resid)
    c5s = pert(c5 * 0.5, c5, c5 * 2.5, N)
    return c1 + 10_000_000 + c3 + c4 + c5s, c3

for n, dt in (("COLD IR  PERT(2,14,90)", COLD), ("MANAGED  PERT(1,4,21)", MANAGED)):
    d = pert(*dt, N)
    print(f"  {n:<24} mean {d.mean():4.1f}d   median {pe(d,50):3.0f}d   1-in-250 {pe(d,99.6):3.0f}d")

print("\nTAKEALOT R20bn Consumer, 3m exposed records  (BI is a big pillar; C1 dominates):")
for n, dt in (("COLD IR (no EDR)", COLD), ("MANAGED (Sophos-deployed)", MANAGED)):
    tot, c3 = cat(20e9, 1580, 1.0, 5_000_000, 25_000_000, 0, 3_000_000, dt)
    print(f"  {n:<28} C3/BI R{pe(c3,99.6):>14,.0f}   TOTAL R{pe(tot,99.6):>14,.0f}")

print("\nBI-DOMINATED PROFILE  R2bn Consumer, only 50k records (BI is the whole story):")
for n, dt in (("COLD IR (no EDR)", COLD), ("MANAGED (Sophos-deployed)", MANAGED)):
    tot, c3 = cat(2e9, 1580, 1.0, 2_500_000, 2_500_000, 0, 50_000, dt)
    print(f"  {n:<28} C3/BI R{pe(c3,99.6):>14,.0f}   TOTAL R{pe(tot,99.6):>14,.0f}")
