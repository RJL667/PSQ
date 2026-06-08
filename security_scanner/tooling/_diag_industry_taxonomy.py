# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX diagnostic (read-only): classify every industry <select> option by what
the INDUSTRY-LEVEL value actually drives, to decide whether the 'aliases' are
redundant (safe to drop) or risk-differentiated (dropping loses accuracy):
  - SA_INDUSTRY_COSTS  (breach-cost anchor + cost/record + cost multiplier)
  - RansomwareIndex.INDUSTRY_MULTIPLIER (ransomware targeting)
  - INDUSTRY_BI_FACTOR (industry-level BI fallback when no sub-industry picked)
Flags exact-duplicate value tuples (true synonyms) vs distinct profiles. NOT shipped."""
import os, sys, re, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import SA_INDUSTRY_COSTS, RansomwareIndex, FinancialImpactCalculator as F
RSI = RansomwareIndex.INDUSTRY_MULTIPLIER
BI = F.INDUSTRY_BI_FACTOR

# Industry <select> options (from templates/index.html)
html = open(os.path.join(SEC, "templates", "index.html"), encoding="utf-8").read()
m = re.search(r'<select[^>]*id="industry"[^>]*>(.*?)</select>', html, re.S)
opts = re.findall(r'<option[^>]*value="([^"]*)"', m.group(1)) if m else []
opts = [o for o in opts if o]

# Hierarchy divisions (canonical SIC source)
hier = json.load(open(os.path.join(SEC, "_bi_factor_data.json"), encoding="utf-8")).get("hierarchy", {})
print("Canonical SIC hierarchy divisions:", list(hier.keys()))
print()

def cost(o):
    d = SA_INDUSTRY_COSTS.get(o.title()) or SA_INDUSTRY_COSTS.get(o)
    return d
def rsi(o):
    return RSI.get(o.lower())
def bifb(o):
    return BI.get(o.title()) or BI.get(o)

print(f"{'industry <select>':<28} {'breach_cost':>12} {'costMult':>8} {'rsiMult':>7} {'BIfallbk':>8}  notes")
print("-"*92)
profiles = {}
for o in opts:
    c = cost(o); r = rsi(o); b = bifb(o)
    bc = c["breach_cost_zar"] if c else None
    cm = c["multiplier"] if c else None
    key = (bc, cm, r)
    profiles.setdefault(key, []).append(o)
    miss = []
    if c is None: miss.append("NO SA_COST")
    if r is None: miss.append("NO RSI_MULT")
    if b is None: miss.append("NO BI_fallback")
    print(f"{o:<28} {('R%.1fM'%(bc/1e6)) if bc else '—':>12} {cm if cm else '—':>8} {r if r else '—':>7} {b if b else '—':>8}  {','.join(miss)}")

print("\n=== Value-identical groups (true synonyms = safe to consolidate) ===")
for key, members in profiles.items():
    if len(members) > 1:
        print(f"  cost={('R%.1fM'%(key[0]/1e6)) if key[0] else '—'} costMult={key[1]} rsiMult={key[2]}  ->  {members}")

print("\n=== Distinct risk profiles (NOT redundant; dropping loses calibration) ===")
singles = [m[0] for m in profiles.values() if len(m) == 1]
print("  ", singles)
