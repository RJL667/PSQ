#!/usr/bin/env python3
"""SANDBOX (not shipped): re-anchor the BI downtime distribution to recorded data
and show the effect on takealot's C3 and total cat.

  OLD downtime PERT(3, 25, 120)  -> mean 37.2 days   (120 max unsupported)
  NEW downtime PERT(2, 14, 90)   -> mean 24.7 days
        mode 14  = good-IR / Sophos Rapid Response ~2 weeks
        mean ~25 = Coveware/IBM 2025 average ~24 days
        max 90   = insurance indemnity-period cap / slow-cohort ceiling
"""
import numpy as np
np.random.seed(42); N = 400_000
IMPACT = 0.5

def pert(a, m, b, n, lamb=4.0):
    a, m, b = float(a), float(m), float(b)
    al = 1 + lamb * (m - a) / (b - a); be = 1 + lamb * (b - m) / (b - a)
    return a + np.random.beta(al, be, n) * (b - a)
def pe(x, q): return float(np.percentile(x, q))

OLD = (3, 25, 120); NEW = (2, 14, 90)
SHARE, SIGMA = 0.20, 0.25

def cat(rev, cpr, bi, c5_tier, c4, residual, records, dt_params):
    daily = rev / 365.0
    dt = pert(*dt_params, N)
    c3 = dt * daily * IMPACT * bi
    c1 = np.maximum(records * (cpr * SHARE) * np.random.lognormal(0, SIGMA, N), residual)
    c2 = 10_000_000.0
    c5 = pert(c5_tier * 0.5, c5_tier, c5_tier * 2.5, N)
    return c1 + c2 + c3 + c4 + c5, c3, dt

for name, dt in (("OLD PERT(3,25,120)", OLD), ("NEW PERT(2,14,90)", NEW)):
    dts = pert(*dt, N)
    print(f"{name}:  mean downtime {dts.mean():.1f} d   median {pe(dts,50):.0f} d   1-in-250 {pe(dts,99.6):.0f} d")
print()

print("TAKEALOT R20bn Consumer (bi=1.0)   C3/BI and TOTAL 1-in-250, OLD vs NEW downtime:")
print(f"  {'records':>11} {'C3 OLD':>14} {'C3 NEW':>14} {'TOTAL OLD':>16} {'TOTAL NEW':>16}")
for rec in (666_667, 3_000_000, 5_000_000):
    to, c3o, _ = cat(20e9, 1580, 1.0, 5_000_000, 25_000_000, 0, rec, OLD)
    tn, c3n, _ = cat(20e9, 1580, 1.0, 5_000_000, 25_000_000, 0, rec, NEW)
    print(f"  {rec:>11,} R{pe(c3o,99.6):>12,.0f} R{pe(c3n,99.6):>12,.0f} R{pe(to,99.6):>14,.0f} R{pe(tn,99.6):>14,.0f}")

print("\nPHISHIELD R10m FS (bi=1.5, residual C1 R7.22m):")
to, c3o, _ = cat(10e6, 2992, 1.5, 350_000, 900_000, 7_220_000, 1_333, OLD)
tn, c3n, _ = cat(10e6, 2992, 1.5, 350_000, 900_000, 7_220_000, 1_333, NEW)
print(f"  TOTAL 1-in-250  OLD R{pe(to,99.6):,.0f}   NEW R{pe(tn,99.6):,.0f}")
