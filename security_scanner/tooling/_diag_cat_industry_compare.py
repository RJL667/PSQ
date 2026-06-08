# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX diagnostic (read-only): why does a R7B manufacturer's cat exceed a ~R17B
e-commerce platform's? Decompose both by pillar (C1-C5) on the CURRENT production model
(cat is posture-independent), and back out the effective industry multiplier and
bi_factor. NOT shipped."""
import os, sys, json, math
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import RiskScorer, RansomwareIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier

IBM = 49_220_000
def load():
    d = json.load(open(os.path.join(SEC, "test_fixtures", "takealot_baseline.json"), encoding="utf-8"))
    cats = dict(d.get("categories", d))
    try:
        cats["credential_risk"] = CredentialRiskClassifier.classify(
            dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {},
            intelx=cats.get("intelx", {}) or {})
    except Exception:
        pass
    return cats

def decompose(label, rev, ind, sub=None):
    cats = load()
    sc, lv, _ = RiskScorer().calculate(cats, waf_apex_status=None); cats["_overall_score"] = sc
    rsi = RansomwareIndex().calculate(cats, industry=ind, annual_revenue=rev)
    fin = FinancialImpactCalculator().calculate(cats, rsi, 0, ind, annual_revenue_zar=rev, sub_industry=sub)
    de = fin["incident_types"]["double_extortion"]; p = de["probability"]
    full = {k: de["components"][k] / p for k in de["components"]}
    mag = sum(full.values())
    recs = fin["scenarios"]["data_breach"]["records_assumption_disclosure"]
    pml = fin["monte_carlo"]["severity_pml"]
    daily = rev / 365.0
    elasticity = 0.35  # >= R1bn band
    rev_scale = (rev / 200_000_000) ** elasticity
    eff_mult = (mag / IBM) / rev_scale
    bi_factor = full["C3"] / (25 * daily * 0.5) if daily else 0
    print(f"\n=== {label}  (R{rev/1e9:.1f}bn, {ind}{'/'+sub if sub else ''}) ===")
    print(f"  revenue_scale (rev^0.35)     : {rev_scale:.2f}")
    print(f"  effective industry multiplier: {eff_mult:.2f}")
    print(f"  bi_factor (backed out of C3) : {bi_factor:.2f}")
    print(f"  estimated_records            : {recs['estimated_records']:,}  (@ R{recs['records_divisor_zar']:,}/rec)")
    print(f"  records-driven C1 (recs x R90): R{recs['estimated_records']*90/1e6:,.0f}M")
    print(f"  --- central full-stack severity (= magnitude) R{mag/1e6:,.0f}M ---")
    for k in ("C1", "C2", "C3", "C4", "C5"):
        print(f"     {k}: R{full[k]/1e6:>9,.0f}M  ({full[k]/mag*100:4.0f}%)")
    print(f"  1-in-250 cat (P99.6)         : R{pml['p99_6']/1e9:.2f}bn  ({pml['p99_6']/rev*100:.0f}% of revenue)")
    return pml['p99_6']

a = decompose("SAMETAL (manufacturer)", 7_000_000_000, "Manufacturing")
b = decompose("TAKEALOT (e-commerce)", 17_000_000_000, "eCommerce", "eCommerce")
print(f"\nRESULT: manufacturer R{a/1e9:.2f}bn vs e-commerce R{b/1e9:.2f}bn  ->",
      "MANUFACTURER HIGHER (the inconsistency)" if a > b else "e-commerce higher")
