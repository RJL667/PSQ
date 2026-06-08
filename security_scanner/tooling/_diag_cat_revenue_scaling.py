# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX diagnostic (read-only): show how the catastrophe severity scales with
revenue. The cat magnitude scales SUB-LINEARLY (revenue^elasticity, elasticity
0.35-0.60), so cat-as-%-of-revenue is REGRESSIVE - tiny for large-cap, huge for
mid-market. Demonstrates the mamamoney (mid) vs takealot (large) inconsistency.
NOT shipped."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import RiskScorer, RansomwareIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier

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

def cat(rev, ind, sub=None):
    cats = load()
    sc, lv, _ = RiskScorer().calculate(cats, waf_apex_status=None); cats["_overall_score"] = sc
    rsi = RansomwareIndex().calculate(cats, industry=ind, annual_revenue=rev)
    fin = FinancialImpactCalculator().calculate(cats, rsi, 0, ind, annual_revenue_zar=rev, sub_industry=sub)
    de = fin["incident_types"]["double_extortion"]; p = de["probability"]
    full = sum(de["components"][k] / p for k in de["components"])   # central full-stack severity = magnitude
    pml = fin["monte_carlo"]["severity_pml"]
    return full, pml["p99"], pml["p99_6"]

print("=" * 92)
print("SAME-INDUSTRY revenue sweep (Financial Services) — isolates the revenue scaling")
print("=" * 92)
print(f"  {'revenue':>14} | {'central magnitude':>18} {'%rev':>6} | {'P99 severity':>16} {'%rev':>6} | {'1-in-250':>16} {'%rev':>6}")
print("  " + "-" * 88)
for rev in (10_000_000, 100_000_000, 424_000_000, 2_000_000_000, 20_000_000_000):
    mag, p99, p996 = cat(rev, "Financial Services")
    print(f"  R{rev:>13,} | R{mag:>16,.0f} {mag/rev*100:5.0f}% | R{p99:>14,.0f} {p99/rev*100:5.0f}% | R{p996:>14,.0f} {p996/rev*100:5.0f}%")

print("\n" + "=" * 92)
print("THE TWO REAL ENTITIES")
print("=" * 92)
for label, rev, ind, sub in [("mamamoney (mid)", 424_000_000, "Financial Services", None),
                              ("takealot (large)", 20_000_000_000, "eCommerce", "eCommerce")]:
    mag, p99, p996 = cat(rev, ind, sub)
    print(f"  {label:<18} R{rev:>14,} {ind:<20} | P99 R{p99:>15,.0f} ({p99/rev*100:4.0f}% rev) | 1-in-250 R{p996:>15,.0f} ({p996/rev*100:4.0f}% rev)")
print("\n  -> magnitude scales ~revenue^0.4 (sub-linear), so %-of-revenue FALLS as revenue rises:")
print("     the fixed IBM anchor (R49.22M) is a big slice of R424M but a rounding error on R20bn.")
