# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SHIP (2026-06-09): complete the industry taxonomy — add the 3 SIC divisions that
were missing from the scan form (Mining, Construction, Wholesale Trade). They already
had RSI INDUSTRY_MULTIPLIER + INDUSTRY_BI_FACTOR entries but NO SA_INDUSTRY_COSTS
entry (so they fell back to the 'Other' baseline). Add SA_INDUSTRY_COSTS entries
anchored BY ANALOGY to the nearest IBM-SA-calibrated sibling already in the table
(reuses calibrated values, does NOT invent numbers); flagged provisional pending a
dedicated per-sector IBM/DBIR pass:
  - Mining        -> Transportation profile (heavy-asset, OT-exposed, moderate data)
  - Construction  -> Agriculture profile     (lowest data intensity, low IT-dependency)
  - Wholesale Trade -> Retail profile        (trade / distribution)
CRLF-safe. Run from security_scanner/: py tooling/_apply_add_sic_industries.py
"""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA = os.path.join(ROOT, "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected universal-newline read to strip CR"

OLD = '    "Agriculture":                {"breach_cost_zar": 28_670_000, "cost_per_record": 1223, "multiplier": 0.65},\n'
NEW = (
    '    "Agriculture":                {"breach_cost_zar": 28_670_000, "cost_per_record": 1223, "multiplier": 0.65},\n'
    '    # SIC divisions added 2026-06-09 (were missing -> fell back to "Other").\n'
    '    # Breach-cost anchored BY ANALOGY to the nearest IBM-SA sibling (PROVISIONAL,\n'
    '    # pending a per-sector IBM/DBIR calibration pass); RSI + BI already distinct.\n'
    '    "Mining":                     {"breach_cost_zar": 39_690_000, "cost_per_record": 1693, "multiplier": 0.90},  # ~Transportation\n'
    '    "Construction":               {"breach_cost_zar": 28_670_000, "cost_per_record": 1223, "multiplier": 0.65},  # ~Agriculture\n'
    '    "Wholesale Trade":            {"breach_cost_zar": 35_280_000, "cost_per_record": 1505, "multiplier": 0.80},  # ~Retail\n'
)
assert s.count(OLD) == 1, ("Agriculture cost row", s.count(OLD))
s = s.replace(OLD, NEW, 1)

ast.parse(s)
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(SA, encoding="utf-8").read())
print("OK scoring_analytics.py: added Mining / Construction / Wholesale Trade to SA_INDUSTRY_COSTS.")
