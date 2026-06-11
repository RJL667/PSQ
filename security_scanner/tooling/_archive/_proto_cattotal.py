#!/usr/bin/env python3
"""SANDBOX (not shipped): FULL compound cat stack, fit the TOTAL 1-in-250 to the
R2-5bn takealot feel. Pillars at realised-cat levels per simulated severe breach:

  C1 liability   = records x (IBM_cpr x SHARE) x lognormal(SIGMA), floored at residual
  C2 regulatory  = POPIA cap ~R10m
  C3 BI          = downtime[PERT 3/25/120] x daily_rev x 0.5 x bi_factor   <-- dominant
  C4 ransom      = ~from model
  C5 IR          = PERT(0.5x, 1x, 2.5x) of the tier
"""
import numpy as np
np.random.seed(42); N = 400_000
IMPACT = 0.5

def pert(a, m, b, n, lamb=4.0):
    a, m, b = float(a), float(m), float(b)
    if b <= a: return np.full(n, m)
    al = 1 + lamb * (m - a) / (b - a); be = 1 + lamb * (b - m) / (b - a)
    return a + np.random.beta(al, be, n) * (b - a)
def pe(x, q): return float(np.percentile(x, q))

def cat(rev, cpr, bi, c5_tier, c4, residual, records, share, sigma):
    daily = rev / 365.0
    c1 = np.maximum(records * (cpr * share) * np.random.lognormal(0, sigma, N), residual)
    c3 = pert(3, 25, 120, N) * daily * IMPACT * bi
    c2 = 10_000_000.0
    c5 = pert(c5_tier * 0.5, c5_tier, c5_tier * 2.5, N)
    tot = c1 + c2 + c3 + c4 + c5
    return tot, c1, c3

SHARE, SIGMA = 0.20, 0.25
print(f"SHARE={SHARE:.0%}  SIGMA={SIGMA}   (cat-C1 records-driven; C3/BI is the dominant non-C1 pillar)\n")

# takealot R20bn Consumer: bi=1.0, c5 tier 5m, c4 ~25m (from iter8), residual 0
print("TAKEALOT  R20bn Consumer  (target TOTAL 1-in-250 = R2-5bn)")
print(f"  {'records':>10} {'C1 1-in-250':>16} {'C3 1-in-250':>16} {'TOTAL 1-in-250':>18}")
for rec in (666_667, 3_000_000, 5_000_000, 7_000_000, 10_000_000):
    tot, c1, c3 = cat(20e9, 1580, 1.0, 5_000_000, 25_000_000, 0, rec, SHARE, SIGMA)
    tag = "  <- model est" if rec == 666_667 else ""
    print(f"  {rec:>10,} R{pe(c1,99.6):>14,.0f} R{pe(c3,99.6):>14,.0f} R{pe(tot,99.6):>16,.0f}{tag}")

print("\n  C3/BI alone (no C1):  median R{:,.0f}   1-in-250 R{:,.0f}".format(
    pe(pert(3,25,120,N)*(20e9/365)*IMPACT*1.0, 50), pe(pert(3,25,120,N)*(20e9/365)*IMPACT*1.0, 99.6)))

# phishield R10m FS: bi~1.5, c5 tier 350k, c4 ~0.9m, residual 7.22m
print("\nPHISHIELD  R10m FS  est 1,333 rec")
tot, c1, c3 = cat(10e6, 2992, 1.5, 350_000, 900_000, 7_220_000, 1_333, SHARE, SIGMA)
print(f"  C1 1-in-250 R{pe(c1,99.6):,.0f}   C3 1-in-250 R{pe(c3,99.6):,.0f}   TOTAL 1-in-250 R{pe(tot,99.6):,.0f}")
