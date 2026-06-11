# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX prototype (read-only, NOTHING SHIPPED): structural finding #6 (annual
expected loss runs warm). Compares the CURRENT 7-incident annualisation against a
RE-FRAMED one that puts the ransomware family on a calibrated annual frequency,
the same way vulnerability -> p_breach is calibrated, holding every severity
identical.

Mechanism of the warmth: the 3 ransomware legs use rsi_score (a 0-1 susceptibility
INDEX) x split ratios that sum to 0.70 -> an effective annual 'ransomware frequency
mass' far above the calibrated p_breach. The re-frame:
   P_rw = min(1, rsi_score x RW_LEF)            # calibrated annual ransomware prob
   leg_prob_i = P_rw x (ratio_i / 0.70)         # conditional shares sum to 1
   (breach family already coherent: p_breach x ratios that sum to 1.00 -> keep)
   (ddos availability leg kept as-is; small)
Severities are recovered from the live model (cost_i = expected_loss_i / prob_i),
so ONLY the frequency basis changes - a clean apples-to-apples comparison.

RW_LEF is the lever the colleague session would lock; 0.30 reuses the breach LEF
(one loss-event-frequency calibration for both vulnerability and susceptibility).
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import RiskScorer, RansomwareIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier

RW_RATIOS = {"double_extortion": 0.25, "ransomware_only": 0.40, "wiper_destructive": 0.05}
RW_SUM = sum(RW_RATIOS.values())  # 0.70
RW_LEFS = (0.20, 0.30, 0.40)      # gated lever; 0.30 == breach LEF


def load_clean_fixture():
    fx = os.path.join(SEC, "test_fixtures", "phishield_live.json")
    d = json.load(open(fx, encoding="utf-8"))
    cats = dict(d.get("categories", d))
    cats["credential_risk"] = CredentialRiskClassifier.classify(
        dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {},
        intelx=cats.get("intelx", {}) or {})
    return cats


def run_fic(cats, rev, industry, sub_industry=None, rsi_rev=None):
    risk_score, level, _ = RiskScorer().calculate(cats, waf_apex_status=None)
    c = dict(cats); c["_overall_score"] = risk_score
    rsi = RansomwareIndex().calculate(cats, industry=industry,
                                      annual_revenue=(rev if rsi_rev is None else rsi_rev))
    fin = FinancialImpactCalculator().calculate(
        c, rsi, annual_revenue=0, industry=industry, annual_revenue_zar=rev,
        sub_industry=sub_industry)
    return risk_score, level, rsi["rsi_score"], fin


def reframe(fin, rw_lef):
    """Return (new_total, per_incident_new_expected) using the re-based ransomware
    frequency. Severities recovered from the live model output."""
    incs = fin["incident_types"]
    rsi_mass_prob = None
    # recover rsi_score from any rw leg: prob = rsi_score * ratio -> rsi_score = prob/ratio
    for k, r in RW_RATIOS.items():
        p = incs[k]["probability"]
        if p > 0:
            rsi_mass_prob = p / r
            break
    rsi_score = rsi_mass_prob or 0.0
    P_rw = min(1.0, rsi_score * rw_lef)
    new = {}
    total = 0
    for k, inc in incs.items():
        p = inc["probability"]; el = inc["expected_loss"]
        cost = (el / p) if p else 0.0
        if k in RW_RATIOS:
            new_p = P_rw * (RW_RATIOS[k] / RW_SUM)
            new_el = new_p * cost
        else:
            new_el = el  # breach family + ddos unchanged
        new[k] = (inc["probability"], new_el)
        total += new_el
    return total, new, P_rw


def show(label, rev, industry, sub_industry=None, rsi_rev=None):
    cats = load_clean_fixture()
    score, level, rsi_score, fin = run_fic(cats, rev, industry, sub_industry, rsi_rev)
    incs = fin["incident_types"]
    cur_total = fin["total"]["most_likely"]
    pb = fin["probability_drivers"]["p_breach"]
    print("=" * 78)
    print(f"{label}   score={score}({level})  p_breach={pb:.4f}  rsi_score={rsi_score:.4f}")
    print("=" * 78)
    print(f"  {'incident':<22}{'CURRENT exp.loss':>20}", end="")
    for lef in RW_LEFS:
        print(f"{'RW_LEF='+format(lef,'.2f'):>14}", end="")
    print()
    print("  " + "-" * 74)
    reframed = {lef: reframe(fin, lef) for lef in RW_LEFS}
    for k in incs:
        cur = incs[k]["expected_loss"]
        print(f"  {k:<22}R{cur:>18,.0f}", end="")
        for lef in RW_LEFS:
            print(f"R{reframed[lef][1][k][1]:>12,.0f}", end="")
        print()
    print("  " + "-" * 74)
    print(f"  {'TOTAL annual loss':<22}R{cur_total:>18,.0f}", end="")
    for lef in RW_LEFS:
        print(f"R{reframed[lef][0]:>12,.0f}", end="")
    print()
    print(f"  {'% of revenue':<22}{cur_total/rev*100:>19.2f}%", end="")
    for lef in RW_LEFS:
        print(f"{reframed[lef][0]/rev*100:>13.2f}%", end="")
    print()
    print(f"  {'P_rw (annual ransomw.)':<22}{'rsi_score='+format(rsi_score,'.3f'):>19}", end="")
    for lef in RW_LEFS:
        print(f"{reframed[lef][2]:>13.4f}", end="")
    print("\n")


show("CLEAN  R200M Financial Services", 200_000_000, "Financial Services", rsi_rev=200_000_000)
show("phishield  R10M Financial Services", 10_000_000, "Financial Services", rsi_rev=0)
show("takealot  R20BN eCommerce(bi1.5)", 20_000_000_000, "eCommerce",
     sub_industry="eCommerce", rsi_rev=20_000_000_000)
print("Reading: the ransomware legs (rsi-driven) carry ~80% of the warmth. Re-basing")
print("them onto a calibrated annual frequency (P_rw = rsi_score x RW_LEF) cools the")
print("headline annual loss while leaving every severity, the breach legs and the cat")
print("tail untouched. RW_LEF is the colleague-gated lever (0.30 reuses the breach LEF).")
