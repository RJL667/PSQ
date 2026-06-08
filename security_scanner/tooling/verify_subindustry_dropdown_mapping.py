# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""PRE-DEPLOY GUARD: the scan-form sub-industry dropdown must map 1:1 to the
server-side lookup tables, so a broker's selection always resolves to the intended
BI factor / sector cat stack / FIC + B2C inference instead of silently falling back
to the coarse industry level.

This locks the fix shipped 2026-06-09 (commit 699f0d0). Run it whenever
templates/index.html SUB_INDUSTRIES, INDUSTRY_BI_FACTOR, SECTOR_FRAMEWORKS, or the
flag_inference label sets change. Exit 0 = aligned; exit 1 = drift (hard failure).

The lookup tables (single source of truth for the submitted value):
  - scoring_analytics.FinancialImpactCalculator.INDUSTRY_BI_FACTOR  (BI factor)
  - scoring_analytics.FinancialImpactCalculator.SECTOR_FRAMEWORKS   (cat reg stack)
  - flag_inference.ACCOUNTABLE_INSTITUTION_LABELS / B2C_SUB_INDUSTRY_LABELS

Run from security_scanner/: py tooling/verify_subindustry_dropdown_mapping.py
"""
import os, sys, re, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import FinancialImpactCalculator as F
import flag_inference as fi

BI = F.INDUSTRY_BI_FACTOR
SECTOR_SUBS = set(F.SECTOR_FRAMEWORKS.keys())
AI = fi.ACCOUNTABLE_INSTITUTION_LABELS
B2C = fi.B2C_SUB_INDUSTRY_LABELS

html = open(os.path.join(SEC, "templates", "index.html"), encoding="utf-8").read()
m = re.search(r"const SUB_INDUSTRIES = (\{.*?\});", html, re.S)
assert m, "SUB_INDUSTRIES literal not found in templates/index.html"
SUB = json.loads(m.group(1))

PASS = FAIL = 0
def check(cond, label, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"FAIL [{label}] {detail}")

# ── A. every dropdown entry carries a canonical key that resolves 1:1 ──
submitted_keys = set()
for industry, subs in SUB.items():
    for e in subs:
        label = e.get("label", "?")
        key = e.get("key")
        check(key is not None, "key-present", f"{industry}/{label!r} has no 'key' field")
        if key is None:
            continue
        submitted_keys.add(key)
        check(key in BI, "key-in-BI", f"{industry}/{label!r} -> key {key!r} not in INDUSTRY_BI_FACTOR")
        if key in BI and "bi" in e:
            check(abs(BI[key] - e["bi"]) < 1e-9, "bi-matches",
                  f"{industry}/{label!r} key {key!r}: dropdown bi {e['bi']} != table {BI[key]}")

# ── B. cross-table label sets are all valid sub-industry keys ──
for x in sorted(AI):
    check(x in BI, "AI-label-valid", f"ACCOUNTABLE_INSTITUTION label {x!r} not in INDUSTRY_BI_FACTOR")
for x in sorted(B2C):
    check(x in BI, "B2C-label-valid", f"B2C label {x!r} not in INDUSTRY_BI_FACTOR")
for x in sorted(SECTOR_SUBS):
    check(x in BI, "sector-sub-valid", f"SECTOR_FRAMEWORKS sub-industry {x!r} not in INDUSTRY_BI_FACTOR")

print("=" * 70)
print(f"PASS: {PASS}    FAIL: {FAIL}")
print("=" * 70)

# ── Coverage report (informational; never fails the gate) ──
# AI / B2C labels that no dropdown option submits -> a broker cannot reach
# that auto-inference from the form (selecting that sub-industry).
ai_unreachable = sorted(AI - submitted_keys)
b2c_unreachable = sorted(B2C - submitted_keys)
if ai_unreachable:
    print(f"\nINFO: {len(ai_unreachable)} FIC accountable-institution label(s) are not "
          f"selectable from the dropdown (broker must tick the toggle manually):")
    for x in ai_unreachable:
        print(f"   - {x}")
if b2c_unreachable:
    print(f"\nINFO: {len(b2c_unreachable)} B2C label(s) not selectable from the dropdown:")
    for x in b2c_unreachable:
        print(f"   - {x}")

sys.exit(1 if FAIL else 0)
