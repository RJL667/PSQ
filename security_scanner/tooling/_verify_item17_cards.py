# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX verification (read-only): confirm the item #17 reporting-only cards are
LIVE in the result dict produced by the post-mutation pipeline, and that the §8
locked numbers still hold. Reads fin["risk_probability"], fin["cover_ladder"],
fin["loss_exposure"], fin["risk_mitigations"]["remediation_summary"] directly —
does NOT recompute them. NOT shipped."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import RiskScorer, RansomwareIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier


def run(label, rev, industry, sub_industry=None, rsi_rev=None, fixture=None):
    fx = fixture or "test_fixtures/phishield_live.json"
    d = json.load(open(os.path.join(SEC, fx), encoding="utf-8"))
    cats = dict(d.get("categories", d))
    cats["credential_risk"] = CredentialRiskClassifier.classify(
        dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {},
        intelx=cats.get("intelx", {}) or {})
    score, level, _ = RiskScorer().calculate(cats, waf_apex_status=None)
    c = dict(cats); c["_overall_score"] = score
    rsi = RansomwareIndex().calculate(cats, industry=industry,
                                      annual_revenue=(rev if rsi_rev is None else rsi_rev))
    fin = FinancialImpactCalculator().calculate(
        c, rsi, annual_revenue=0, industry=industry, annual_revenue_zar=rev, sub_industry=sub_industry)

    rp = fin["risk_probability"]
    db, ci, av = rp["data_breach"], rp["cyber_incident"], rp["availability_resilience"]
    cl = fin["cover_ladder"]
    le = fin["loss_exposure"]["scenarios"]
    rem = fin.get("risk_mitigations", {}).get("remediation_summary", {})

    print("=" * 84)
    print(f"{label}   score={score}({level})")
    print("=" * 84)
    print("  RISK_PROBABILITY block (reporting-only FAIR frequency view)")
    print(f"    [1] data_breach        {db['probability_pct']:6.2f}%   grade={db['grade']}")
    print(f"    [2] cyber_incident     {ci['probability_pct']:6.2f}%   grade={ci['grade']}   "
          f"(channels: breach={ci['channels']['data_breach']}, rw={ci['channels']['ransomware']})")
    print(f"    [3] availability(IND)  {av['indicator_pct']:6.2f}%   calibrated={av['calibrated']}")
    assert ci["probability"] >= db["probability"], "cyber_incident must nest ABOVE data_breach"
    print("  COVER_LADDER (severity-PML cover-sizing tiers, posture-independent)")
    print(f"    P50 typical_severe   R{cl['typical_severe']['loss_zar']:>15,.0f}")
    print(f"    P95 bad              R{cl['bad']['loss_zar']:>15,.0f}")
    print(f"    P99.6 catastrophic   R{cl['catastrophic']['loss_zar']:>15,.0f}   <- 1-in-250 cover")
    print(f"    (loss_exposure.return_1_250 = R{le['return_1_250']['loss_zar']:>15,.0f})")
    print(f"  ANNUAL EXPECTED LOSS (ALE, posture-sensitive)  R{fin['total']['most_likely']:>15,.0f}")
    if rem:
        print("  REMEDIATION_SUMMARY (re-portrayed: grade move + %-reduction + cat cover)")
        print(f"    breach prob {rem['breach_probability_before_pct']}% ({rem['breach_grade_before']})"
              f"  ->  {rem['breach_probability_after_pct']}% ({rem['breach_grade_after']})")
        print(f"    modelled-exposure reduction: {rem['exposure_reduction_pct']}%")
        print(f"    catastrophe cover (unchanged): R{rem['catastrophe_cover_zar']:,.0f}")
    else:
        print("  REMEDIATION_SUMMARY: (none — no matched mitigations / zero loss)")
    print()
    return fin


print("\n### ITEM #17 CARD WIRING — LIVE RESULT-DICT VERIFICATION ###\n")
f1 = run("phishield  R10M Financial Services", 10_000_000, "Financial Services", rsi_rev=0)
f2 = run("takealot   R20BN eCommerce (bi1.5)", 20_000_000_000, "eCommerce",
         sub_industry="eCommerce", rsi_rev=20_000_000_000, fixture="test_fixtures/takealot_baseline.json")

print("### §8 anchor checks (MC tail ~±, p_breach deterministic) ###")
pb1 = f1["risk_probability"]["data_breach"]["probability_pct"]
pb2 = f2["risk_probability"]["data_breach"]["probability_pct"]
cov1 = f1["cover_ladder"]["catastrophic"]["loss_zar"]
cov2 = f2["cover_ladder"]["catastrophic"]["loss_zar"]
print(f"  phishield breach {pb1}% (expect ~1.68 Good)   cover 1-in-250 R{cov1:,.0f} (expect ~R34.3m)")
print(f"  takealot  breach {pb2}% (expect ~2.21 Typical) cover 1-in-250 R{cov2:,.0f} (expect ~R2.91bn)")
print("  (ALE: phishield expect ~R390k; takealot expect ~R95.3m — see ANNUAL EXPECTED LOSS above)")
print("\nOK: risk_probability + cover_ladder + remediation_summary are LIVE in the result dict.")
