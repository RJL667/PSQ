# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX diagnostic (read-only): decompose the catastrophe return-period tail for a
R424M financial-services profile (mamamoney-like) to explain how the 1-in-100/200/250
severity-PML reaches ~R290-320M. Shows the central full-stack severity by component
(C1-C5), the PERT-widened percentiles, and the WAF-coverage uplift. NOT shipped."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import RiskScorer, RansomwareIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier

REV = 424_000_000
IND = "Financial Services"

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

def run(scan_completeness=None):
    cats = load()
    sc, lv, _ = RiskScorer().calculate(cats, waf_apex_status=None); cats["_overall_score"] = sc
    rsi = RansomwareIndex().calculate(cats, industry=IND, annual_revenue=REV)
    fin = FinancialImpactCalculator().calculate(cats, rsi, 0, IND, annual_revenue_zar=REV,
                                                scan_completeness=scan_completeness)
    return fin

fin = run()  # no coverage adjustment (base severity)
de = fin["incident_types"]["double_extortion"]
p = de["probability"]; comp = de["components"]
full = {k: comp[k] / p for k in comp}                 # un-weight to FULL severity
full_sev = sum(full.values())
pml = fin["monte_carlo"]["severity_pml"]
rp = fin["return_periods"]

print("=" * 74)
print(f"R{REV:,} turnover  |  {IND}  |  daily revenue R{REV/365:,.0f}")
print("=" * 74)
print(f"  total_breach_magnitude (IBM-anchored, revenue-scaled): "
      f"R{fin['scenarios']['data_breach'].get('estimated_records','?') and 0 or 0:,}".replace(' R0',''))
print("\n  CENTRAL full-stack double-extortion severity (mode), by component:")
labels = {"C1": "C1 data-breach liability (records-driven)", "C2": "C2 regulatory fines",
          "C3": "C3 business interruption", "C4": "C4 ransom", "C5": "C5 incident response"}
for k in ("C1", "C2", "C3", "C4", "C5"):
    print(f"     {labels[k]:<42} R{full[k]:>14,.0f}   {full[k]/full_sev*100:4.1f}%")
print(f"     {'FULL-STACK SEVERITY (central)':<42} R{full_sev:>14,.0f}")
print(f"\n  C2 regulatory breakdown: {json.dumps({k:v for k,v in fin['regulatory_exposure'].items() if k.startswith('c2_')})}")
recs = fin['scenarios']['data_breach']['records_assumption_disclosure']
print(f"  records assumed: {recs['estimated_records']:,} @ R{recs['records_divisor_zar']:,}/record divisor")
print(f"\n  Severity-PML percentiles (PERT-widened, BEFORE coverage uplift):")
for k in ("p50", "p95", "p99", "p99_5", "p99_6"):
    print(f"     {k:<6} R{pml[k]:>14,.0f}   ({pml[k]/REV*100:4.0f}% of turnover)")
print(f"\n  return_periods (as shipped, no coverage adj): "
      f"1-in-100 R{rp['1_in_100']['loss_zar']:,}  1-in-250 R{rp['1_in_250']['loss_zar']:,}")

print("\n" + "=" * 74)
print("WITH WAF-coverage uplift (81% coverage, waf_challenge) — matches broker doc")
print("=" * 74)
fin2 = run({"waf_status": {"blocked": True, "kind": "waf_challenge"}, "coverage_pct": 81})
rp2 = fin2["return_periods"]; cadj = fin2["coverage_adjustment"]
print(f"  coverage_adjustment: {json.dumps(cadj_clean := {k: cadj[k] for k in cadj if k in ('applied','shortfall','inflation_factor','coverage_pct')})}" if (cadj := cadj) else "")
for tag in ("1_in_100", "1_in_200", "1_in_250"):
    print(f"     {tag:<10} R{rp2[tag]['loss_zar']:>14,.0f}   ({rp2[tag]['loss_zar']/REV*100:4.0f}% of turnover)")
print(f"  most_likely R{fin2['estimated_annual_loss']['most_likely']:,}  median(P50) R{fin2['monte_carlo']['total']['p50']:,}")
