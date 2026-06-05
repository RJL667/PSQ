# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX diagnostic (read-only): decompose the annual-expected-loss 'warmth'
(structural finding #6). Runs the REAL wired FIC on the clean phishield fixture
scaled to R200M Financial Services and shows, per incident type, the driver
(rsi_score vs p_breach vs p_interruption), the probability, and the expected
loss, plus the total as a % of revenue and the implied annual event frequency.
NOT shipped."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import RiskScorer, RansomwareIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier

REV = 200_000_000
fx = os.path.join(SEC, "test_fixtures", "phishield_live.json")
d = json.load(open(fx, encoding="utf-8"))
cats = dict(d.get("categories", d))
cats["credential_risk"] = CredentialRiskClassifier.classify(
    dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {},
    intelx=cats.get("intelx", {}) or {})
risk_score, level, _ = RiskScorer().calculate(cats, waf_apex_status=None)
c = dict(cats); c["_overall_score"] = risk_score
rsi = RansomwareIndex().calculate(cats, industry="Financial Services", annual_revenue=REV)
fin = FinancialImpactCalculator().calculate(
    c, rsi, annual_revenue=0, industry="Financial Services", annual_revenue_zar=REV)

pd = fin["probability_drivers"]
rsi_score = rsi["rsi_score"]
incs = fin["incident_types"]
ml = fin["total"]["most_likely"]

DRIVER = {  # which probability channel drives each incident
    "double_extortion": "rsi", "ransomware_only": "rsi", "wiper_destructive": "rsi",
    "silent_breach": "p_breach", "data_extortion": "p_breach",
    "opportunistic_breach": "p_breach", "ddos_infra": "p_interruption",
}

print(f"Clean R200M Financial Services  (fixture=phishield_live, score={risk_score} {level})")
print(f"  p_breach={pd['p_breach']:.4f}  rsi_score={rsi_score:.4f}  (vuln={pd['vulnerability']:.4f}, tef={pd['tef']})")
print(f"\n  {'incident':<22}{'driver':<14}{'prob':>8}{'expected_loss':>18}")
print("  " + "-" * 62)
sum_p = 0.0
for k, inc in incs.items():
    p = inc["probability"]; el = inc["expected_loss"]; sum_p += p
    print(f"  {k:<22}{DRIVER[k]:<14}{p:>8.4f}R{el:>16,.0f}")
print("  " + "-" * 62)
print(f"  {'TOTAL':<22}{'(sum)':<14}{sum_p:>8.4f}R{ml:>16,.0f}")
print(f"\n  annual expected loss / revenue = {ml/REV*100:.2f}%   (finding: 'runs warm ~3.35%')")
print(f"  implied E[# incidents/yr] = sum of incident probabilities = {sum_p:.3f}")
print(f"\n  CONTRAST - a single calibrated FAIR loss event:")
sev_breach = fin['scenarios_4cat']['data_breach']['estimated_loss']
print(f"    p_breach alone = {pd['p_breach']:.4f}; if annual loss = p_breach x single-breach severity,")
print(f"    the breach leg would be far smaller than the aggregated total above.")
print(f"\n  Note: the 3 rsi-driven legs use rsi_score (a 0-1 susceptibility INDEX), and the")
print(f"  split ratios sum to >1 (rsi legs 0.70, p_breach legs 1.00) + a separate ddos leg,")
print(f"  so the annualised aggregation is NOT bounded by the calibrated p_breach base rate.")
