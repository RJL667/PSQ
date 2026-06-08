# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX diagnostic (read-only): the Loss Exposure Scenario card rows (most-likely,
P50, P99, P99.5, P99.6) for an FSP across revenue bands, with % of revenue. Run BEFORE
and AFTER the Lever-1 C1 taper to show the scenario impact. NOT shipped."""
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

def run(rev):
    cats = load()
    sc, lv, _ = RiskScorer().calculate(cats, waf_apex_status=None); cats["_overall_score"] = sc
    rsi = RansomwareIndex().calculate(cats, industry="Financial Services", annual_revenue=rev)
    return FinancialImpactCalculator().calculate(cats, rsi, 0, "Financial Services", annual_revenue_zar=rev)

def M(x): return f"R{x/1e6:,.1f}M" if x < 1e9 else f"R{x/1e9:,.2f}bn"

BANDS = [10_000_000, 50_000_000, 100_000_000, 424_000_000, 2_000_000_000, 20_000_000_000]
tag = sys.argv[1] if len(sys.argv) > 1 else "MODEL"
print("=" * 104)
print(f"LOSS EXPOSURE SCENARIOS — FSP by revenue band   [{tag}]")
print("=" * 104)
h = (f"{'revenue':>10} | {'most-likely':>12} | {'P50':>12} | {'P99 (severe)':>14} {'%rev':>5} | "
     f"{'P99.5':>13} | {'P99.6 (cat)':>14} {'%rev':>5}")
print(h); print("-" * len(h))
for rev in BANDS:
    fin = run(rev)
    ml = fin["estimated_annual_loss"]["most_likely"]
    p50 = fin["monte_carlo"]["total"]["p50"]
    rp = fin["return_periods"]
    p99 = rp["1_in_100"]["loss_zar"]; p995 = rp["1_in_200"]["loss_zar"]; p996 = rp["1_in_250"]["loss_zar"]
    print(f"{M(rev):>10} | {M(ml):>12} | {M(p50):>12} | {M(p99):>14} {p99/rev*100:4.0f}% | "
          f"{M(p995):>13} | {M(p996):>14} {p996/rev*100:4.0f}%")
