# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX diagnostic (read-only): show the proposed report outputs side by side.
  1. Data-breach probability         = p_breach (already FAIR; vuln x TEF x 0.3)
  2. Total cyber-incident probability = 1 - PROD(1 - p_channel) over breach,
     ransomware (FAIR-restored = rsi x 0.30), and availability (p_interruption).
     Shown with AND without availability (ddos p_interruption is still a warm
     heuristic that needs its own FAIR treatment).
  3. Severity-PML ladder (posture-independent cover view) - P50/P75/P95/P99/P99.6.
Bands use the neutral p_breach tiers already documented in the risk-band block.
NOT shipped."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import RiskScorer, RansomwareIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier

RW_LEF = 0.30  # FAIR-restored ransomware loss-event-frequency scalar (reuse breach LEF)

def band(p):
    pct = p * 100
    if pct < 1:   return "Strong   (<1%)"
    if pct < 2:   return "Good     (1-2%)"
    if pct < 3:   return "Typical  (2-3%)"
    if pct < 6:   return "Elevated (3-6%)"
    if pct < 12:  return "High     (6-12%)"
    return "Critical (>12%)"

def load_clean():
    fx = os.path.join(SEC, "test_fixtures", "phishield_live.json")
    d = json.load(open(fx, encoding="utf-8"))
    cats = dict(d.get("categories", d))
    cats["credential_risk"] = CredentialRiskClassifier.classify(
        dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {},
        intelx=cats.get("intelx", {}) or {})
    return cats

def run(label, rev, industry, sub_industry=None, rsi_rev=None, fixture=None):
    if fixture:
        d = json.load(open(os.path.join(SEC, fixture), encoding="utf-8"))
        cats = dict(d.get("categories", d))
        cats["credential_risk"] = CredentialRiskClassifier.classify(
            dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {},
            intelx=cats.get("intelx", {}) or {})
    else:
        cats = load_clean()
    score, level, _ = RiskScorer().calculate(cats, waf_apex_status=None)
    c = dict(cats); c["_overall_score"] = score
    rsi = RansomwareIndex().calculate(cats, industry=industry,
                                      annual_revenue=(rev if rsi_rev is None else rsi_rev))
    fin = FinancialImpactCalculator().calculate(
        c, rsi, annual_revenue=0, industry=industry, annual_revenue_zar=rev, sub_industry=sub_industry)

    pb = fin["probability_drivers"]["p_breach"]
    rsi_score = rsi["rsi_score"]
    p_rw = min(1.0, rsi_score * RW_LEF)
    p_av = fin["incident_types"]["ddos_infra"]["probability"]
    tot_no_av = 1 - (1 - pb) * (1 - p_rw)
    tot_av = 1 - (1 - pb) * (1 - p_rw) * (1 - p_av)
    pml = fin["monte_carlo"]["severity_pml"]

    print("=" * 78)
    print(f"{label}   score={score}({level})  TEF={fin['probability_drivers']['tef']}")
    print("=" * 78)
    print("  PROBABILITY OUTPUTS")
    print(f"    Data-breach probability (p_breach)        {pb*100:5.2f}%   {band(pb)}")
    print(f"    Ransomware probability (rsi x {RW_LEF}, FAIR)   {p_rw*100:5.2f}%   {band(p_rw)}")
    print(f"    Availability probability (p_interruption*) {p_av*100:5.2f}%   [* warm heuristic]")
    print(f"    TOTAL cyber-incident (breach+ransomware)  {tot_no_av*100:5.2f}%   {band(tot_no_av)}")
    print(f"    TOTAL incl. availability                  {tot_av*100:5.2f}%   {band(tot_av)}")
    print("  SEVERITY-PML LADDER (posture-independent cover view)")
    print(f"    P50 typical severe   R{pml['p50']:>15,.0f}")
    print(f"    P75                  R{pml['p75']:>15,.0f}")
    print(f"    P95 bad              R{pml['p95']:>15,.0f}")
    print(f"    P99 (1-in-100 label) R{pml['p99']:>15,.0f}")
    print(f"    P99.6 (1-in-250)     R{pml['p99_6']:>15,.0f}")
    print(f"  ANNUAL EXPECTED LOSS (posture-sensitive lever, unchanged) R{fin['total']['most_likely']:>13,.0f}")
    print()

run("phishield  R10M Financial Services", 10_000_000, "Financial Services", rsi_rev=0)
run("takealot   R20BN eCommerce (bi1.5)", 20_000_000_000, "eCommerce",
    sub_industry="eCommerce", rsi_rev=20_000_000_000, fixture="test_fixtures/takealot_baseline.json")
print("Bands are posture/size-anchored from public data (Cyentia SMB <2%, BitSight")
print(">700 <1% / <500 ~3%, SecurityScorecard ladder). Industry enters via TEF only")
print("(coarse); true industry x revenue-band peer percentiles come from the peer DB.")
