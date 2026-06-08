# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX diagnostic (read-only): verify the scan-form sub-industry dropdown labels
map 1:1 to INDUSTRY_BI_FACTOR keys. A label that does NOT exact-match a key silently
falls back to the coarse industry-level factor (scoring_analytics.py:2415-2418,
industry_key = industry.title()), so the 86-entry sub-industry granularity is
unreachable and BI is mis-stated. Enumerates every mismatch + the resulting
fallback delta. NOT shipped."""
import os, sys, re, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import FinancialImpactCalculator as F
BI = F.INDUSTRY_BI_FACTOR

# Extract the SUB_INDUSTRIES literal from index.html
html = open(os.path.join(SEC, "templates", "index.html"), encoding="utf-8").read()
m = re.search(r"const SUB_INDUSTRIES = (\{.*?\});", html, re.S)
assert m, "SUB_INDUSTRIES literal not found"
SUB = json.loads(m.group(1))

total = ok = miss = 0
material = []   # mismatches whose fallback differs materially from intended bi
print(f"{'INDUSTRY':<28} {'DROPDOWN LABEL':<46} {'intended':>8} {'resolved':>8}  status")
print("-" * 104)
for industry, subs in SUB.items():
    fallback = BI.get(industry.title(), 1.0)
    for s in subs:
        total += 1
        label, intended = s["label"], s["bi"]
        if label in BI:
            resolved = BI[label]
            if abs(resolved - intended) < 1e-9:
                ok += 1
                continue
            else:
                # label matches a key but the dropdown bi disagrees with the table
                status = f"KEY/BI-DISAGREE (table={resolved})"
                miss += 1
        else:
            resolved = fallback
            miss += 1
            d = abs(resolved - intended)
            status = f"FALLBACK->{industry.title()} ({fallback})"
            if d >= 0.10:
                material.append((industry, label, intended, fallback, d))
            print(f"{industry:<28} {label[:46]:<46} {intended:>8} {resolved:>8}  {status}")
print("-" * 104)
print(f"TOTAL dropdown entries: {total}   exact-match OK: {ok}   MISMATCH: {miss}")
print(f"\nMATERIAL mismatches (|intended - fallback| >= 0.10): {len(material)}")
for industry, label, intended, fb, d in sorted(material, key=lambda x: -x[4]):
    print(f"   {industry:<22} {label[:40]:<40} intended {intended} -> fallback {fb}  (Δ {d:.2f})")
