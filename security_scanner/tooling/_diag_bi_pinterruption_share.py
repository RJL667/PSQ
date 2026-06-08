# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX diagnostic (read-only): what fraction of the BUSINESS-INTERRUPTION
scenario loss does p_interruption actually control? agg_bi = C3 across ALL 7
incident types; p_interruption gates ONLY the ddos_infra slice. So a change to
p_interruption moves total BI by (ddos_share x p_interruption_delta_fraction),
NOT 1:1. Reconstruct the OLD p_interruption to show the true BI delta. NOT shipped."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import RiskScorer, RansomwareIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier


def old_pint(cats):
    waf = cats.get("waf", {}).get("detected", False)
    cdn = cats.get("cloud_cdn", {}).get("cdn_detected", False)
    single = cats.get("external_ips", {}).get("unique_asns", 2) <= 1
    return min(0.5, 0.05 + (0.05 if not waf else 0) + (0.05 if not cdn else 0) + (0.05 if single else 0))


def run(fname, rev, industry):
    d = json.load(open(os.path.join(SEC, "test_fixtures", fname), encoding="utf-8"))
    cats = dict(d.get("categories", d))
    try:
        cats["credential_risk"] = CredentialRiskClassifier.classify(
            dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {},
            intelx=cats.get("intelx", {}) or {})
    except Exception:
        pass
    score, level, _ = RiskScorer().calculate(cats, waf_apex_status=None)
    c = dict(cats); c["_overall_score"] = score
    rsi = RansomwareIndex().calculate(cats, industry=industry, annual_revenue=rev)
    fin = FinancialImpactCalculator().calculate(c, rsi, annual_revenue=0, industry=industry, annual_revenue_zar=rev)
    incs = fin["incident_types"]
    ddos = incs["ddos_infra"]
    p_new = ddos["probability"]
    ddos_loss_new = ddos["expected_loss"]
    c3_ddos = (ddos_loss_new / p_new) if p_new else 0
    agg_bi_new = fin["scenarios"]["business_interruption"]["estimated_loss"]
    non_ddos_bi = agg_bi_new - ddos_loss_new
    p_old = old_pint(cats)
    ddos_loss_old = p_old * c3_ddos
    agg_bi_old = non_ddos_bi + ddos_loss_old
    print(f"\n{fname}  (rev R{rev:,}, {industry})")
    print(f"  p_interruption           old {p_old*100:5.1f}%   new {p_new*100:5.1f}%")
    print(f"  ddos_infra BI slice      old R{ddos_loss_old:,.0f}   new R{ddos_loss_new:,.0f}")
    print(f"  non-DDoS BI (untouched)      R{non_ddos_bi:,.0f}   (ransomware/breach C3, 25-day downtime etc.)")
    print(f"  TOTAL BI scenario        old R{agg_bi_old:,.0f}   new R{agg_bi_new:,.0f}")
    if agg_bi_old:
        print(f"  ddos slice = {ddos_loss_new/agg_bi_new*100:4.1f}% of total BI;  "
              f"total BI delta from p_int change = {(agg_bi_new-agg_bi_old)/agg_bi_old*100:+.1f}%")


run("phishield_R10M_finance_2026-05-15.json", 10_000_000, "Financial Services")
run("takealot_baseline.json", 20_000_000_000, "eCommerce")
print("\nReading: p_interruption only scales the ddos_infra C3 slice. The bulk of BI")
print("(ransomware-driven downtime, 25-day) is independent of p_interruption.")
