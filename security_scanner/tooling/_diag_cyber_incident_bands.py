# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX diagnostic (read-only): what does the model's p_cyber_incident
actually OUTPUT, and which _CYBER_INCIDENT_BANDS label does each land in?

p_cyber_incident = 1 - (1 - p_breach) * (1 - rsi_score * 0.30)

Prints (a) real-fixture outputs and (b) a parametric sweep over the plausible
(p_breach, rsi_score) space, so the band boundaries can be judged against the
model's real output distribution rather than against the empirical base rate
alone. NOT shipped."""
import os, sys, json, glob
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import (RiskScorer, RansomwareIndex, FinancialImpactCalculator,
                               _grade_probability, _CYBER_INCIDENT_BANDS, _BREACH_PROB_BANDS)
from checkers_threats import CredentialRiskClassifier


def grade_cyber(pct):
    return _grade_probability(pct, _CYBER_INCIDENT_BANDS)


def load_fixture(path):
    d = json.load(open(path, encoding="utf-8"))
    cats = dict(d.get("categories", d))
    try:
        cats["credential_risk"] = CredentialRiskClassifier.classify(
            dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {},
            intelx=cats.get("intelx", {}) or {})
    except Exception:
        pass
    return cats


def run_fixture(path, rev, industry):
    cats = load_fixture(path)
    score, level, _ = RiskScorer().calculate(cats, waf_apex_status=None)
    c = dict(cats); c["_overall_score"] = score
    rsi = RansomwareIndex().calculate(cats, industry=industry, annual_revenue=rev)
    fin = FinancialImpactCalculator().calculate(
        c, rsi, annual_revenue=0, industry=industry, annual_revenue_zar=rev)
    pb = fin["probability_drivers"]["p_breach"]
    rsi_s = rsi["rsi_score"]
    p_ci = 1.0 - (1.0 - pb) * (1.0 - rsi_s * 0.30)
    return score, level, pb, rsi_s, p_ci


print("=" * 92)
print("REAL FIXTURE OUTPUTS")
print("=" * 92)
print(f"  {'fixture':<42}{'score':>6}{'p_breach':>10}{'rsi':>7}{'p_cyber':>9}  band")
print("  " + "-" * 88)
FIX = [
    ("phishield_R10M_finance_2026-05-15.json", 10_000_000, "Financial Services"),
    ("takealot_baseline.json", 20_000_000_000, "eCommerce"),
]
for fname, rev, ind in FIX:
    p = os.path.join(SEC, "test_fixtures", fname)
    if not os.path.exists(p):
        continue
    try:
        score, level, pb, rsi_s, p_ci = run_fixture(p, rev, ind)
        print(f"  {fname[:42]:<42}{score:>6}{pb*100:>9.2f}%{rsi_s:>7.3f}{p_ci*100:>8.2f}%  {grade_cyber(p_ci*100)}")
    except Exception as e:
        print(f"  {fname[:42]:<42}  ERROR {e}")

print()
print("=" * 92)
print("PARAMETRIC SWEEP  p_cyber_incident = 1 - (1-p_breach)(1 - rsi*0.30)")
print("Rows = p_breach (breach-band label); Cols = rsi_score.  Cell = p_cyber% [cyber-band]")
print("=" * 92)
rsis = [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70]
pbs = [0.005, 0.01, 0.02, 0.03, 0.06, 0.10, 0.15]
hdr = f"  {'p_breach':>10} {'(breach)':>9} |" + "".join(f"  rsi={r:.2f}" for r in rsis)
print(hdr)
print("  " + "-" * (len(hdr)))
for pb in pbs:
    bl = _grade_probability(pb * 100, _BREACH_PROB_BANDS)
    row = f"  {pb*100:>9.1f}% {bl:>9} |"
    for r in rsis:
        p_ci = 1.0 - (1.0 - pb) * (1.0 - r * 0.30)
        row += f" {p_ci*100:>4.0f}[{grade_cyber(p_ci*100)[0]}]"
    print(row)
print()
print("  Band legend: L=Low(<5) T=Typical(5-15) E=Elevated(15-30) H=High(>30)")
print("  p_ransomware = rsi*0.30, so even a 'Typical' breach posture (p_breach~2-3%)")
print("  combined with mid rsi (0.3-0.5) lands p_cyber ~10-17%.")
