#!/usr/bin/env python3
"""SANDBOX (not shipped): records-driven stand-alone cat-C1 pillar.

cat_C1 = records x (IBM_cost_per_record x LIABILITY_SHARE) x heavy_tail
         floored at the central residual C1.

Two gated params we own (best-effort, fit to the R2-5bn takealot cat 'feel'):
  LIABILITY_SHARE  - liability slice of IBM's all-in per-record cost
  SIGMA            - lognormal sigma = cat heavy-tail on per-record liability
Records: model estimate (revenue // industry divisor) OR client override.
"""
import numpy as np
np.random.seed(42); N = 400_000

LIABILITY_SHARE = 0.20    # gated #1: liability slice of IBM all-in per-record
def cat_c1(records, cpr, residual, sigma):
    base = cpr * LIABILITY_SHARE                       # central per-record liability
    pr = base * np.random.lognormal(0.0, sigma, N)     # median=base, heavy right tail
    return np.maximum(records * pr, residual)          # floored at central residual

def pe(x, q): return float(np.percentile(x, q))

# (label, records, cost_per_record, central_residual_C1)
ROWS = [
    ("phishield  R10m FS      est 1,333 rec", 1_333, 2992, 7_220_000),
    ("takealot   R20bn Consumer  MODEL EST 667k", 666_667, 1580, 0),
    ("takealot   R20bn Consumer  OVERRIDE 7m",  7_000_000, 1580, 0),
    ("takealot   R20bn Consumer  OVERRIDE 10m", 10_000_000, 1580, 0),
]
OTHER_PILLARS = {"phishield": 4_000_000, "takealot": 550_000_000}  # ~C2+C3+C4+C5 at cat (rough, for total)

print(f"LIABILITY_SHARE = {LIABILITY_SHARE:.0%}   (cat-C1 = records x IBM_cpr x share x lognormal tail, floored at residual)\n")
for sigma in (0.20, 0.30, 0.40):
    print(f"=== cat heavy-tail SIGMA = {sigma} " + "=" * 50)
    for label, rec, cpr, resid in ROWS:
        c = cat_c1(rec, cpr, resid, sigma)
        base_central = rec * cpr * LIABILITY_SHARE
        other = OTHER_PILLARS["phishield"] if "phishield" in label else OTHER_PILLARS["takealot"]
        tot_250 = pe(c, 99.6) + other
        print(f"  {label:<42}  per-rec-liab R{cpr*LIABILITY_SHARE:>6,.0f}")
        print(f"      cat-C1   median R{pe(c,50):>15,.0f}   1-in-250 R{pe(c,99.6):>15,.0f}")
        print(f"      TOTAL 1-in-250 (cat-C1 + ~other pillars)  R{tot_250:>15,.0f}")
    print()
