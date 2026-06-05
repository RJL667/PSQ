# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX verify (item #14): the compound return-period tail must HOLD as
posture improves (lower risk score), instead of collapsing the way the old
prob-weighted tail did. Runs the REAL wired FinancialImpactCalculator on the
phishield fixture at several overall scores and prints the 1-in-250 + most-
likely. Expectation: most_likely (expected card) FALLS with better posture;
1-in-250 (realised cat) stays roughly flat (posture-independent severity).
NOT shipped.
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import RansomwareIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier

fx = os.path.join(SEC, "test_fixtures", "phishield_live.json")
d = json.load(open(fx, encoding="utf-8"))
cats = dict(d.get("categories", d))
cats["credential_risk"] = CredentialRiskClassifier.classify(
    dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {},
    intelx=cats.get("intelx", {}) or {})
rsi = RansomwareIndex().calculate(cats, industry="Financial Services", annual_revenue=0)
REV = 10_000_000

print("phishield R10m Financial Services - compound tail vs posture")
print(f"  {'score':>6} {'p_breach':>9} {'most_likely':>15} {'1-in-100':>15} {'1-in-250':>15}")
prev_250 = None
for score in (700, 500, 380, 250, 165):
    c = dict(cats); c["_overall_score"] = score
    fin = FinancialImpactCalculator().calculate(
        c, rsi, annual_revenue=0, industry="Financial Services", annual_revenue_zar=REV)
    pb = fin["probability_drivers"]["p_breach"]
    ml = fin["total"]["most_likely"]
    p100 = fin["return_periods"]["1_in_100"]["loss_zar"]
    p250 = fin["return_periods"]["1_in_250"]["loss_zar"]
    print(f"  {score:>6} {pb:>9.4f} R{ml:>13,.0f} R{p100:>13,.0f} R{p250:>13,.0f}")
    prev_250 = p250

print("\nReading: most_likely should fall sharply with better posture (the value-")
print("prop / remediation card); the 1-in-250 realised-cat stays in the same band")
print("(severity is posture-independent) - it does NOT collapse toward zero.")
