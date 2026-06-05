# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX diagnostic (read-only): decompose the model's annual expected loss back
into canonical FAIR terms  ALE = LEF x LM  (LEF = TEF x Vulnerability; LM = expected
loss magnitude per loss event), to see what the ORIGINAL FAIR structure implies vs
what the 7-incident annualisation actually outputs.

Key question: each channel - is it built as canonical FAIR (LEF x E[LM]) or not?
  * BREACH family (silent / data_extortion / opportunistic): split ratios 0.50+0.20+
    0.30 = 1.00, driven by p_breach (= vuln x TEF x 0.3 = a real FAIR LEF). So
    breach ALE = p_breach x E[LM_breach] = canonical FAIR. <-- the FAIR part.
  * RANSOMWARE family (double / rw_only / wiper): ratios 0.25+0.40+0.05 = 0.70,
    driven by rsi_score (a 0-1 INDEX, not TEF x Vuln). So its implied 'LEF' =
    rsi_score x 0.70, which is NOT a calibrated FAIR frequency. <-- the non-FAIR part.
  * DDOS: p_interruption (heuristic 0.05-per-signal sum) x one cost.
Costs recovered from the live model (cost_i = expected_loss_i / prob_i).
NOT shipped.
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import RiskScorer, RansomwareIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier


def load_clean():
    fx = os.path.join(SEC, "test_fixtures", "phishield_live.json")
    d = json.load(open(fx, encoding="utf-8"))
    cats = dict(d.get("categories", d))
    cats["credential_risk"] = CredentialRiskClassifier.classify(
        dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {},
        intelx=cats.get("intelx", {}) or {})
    return cats


def run(cats, rev, industry, sub_industry=None, rsi_rev=None):
    score, level, _ = RiskScorer().calculate(cats, waf_apex_status=None)
    c = dict(cats); c["_overall_score"] = score
    rsi = RansomwareIndex().calculate(cats, industry=industry,
                                      annual_revenue=(rev if rsi_rev is None else rsi_rev))
    fin = FinancialImpactCalculator().calculate(
        c, rsi, annual_revenue=0, industry=industry, annual_revenue_zar=rev,
        sub_industry=sub_industry)
    return score, level, rsi["rsi_score"], fin


def cost(inc):
    p = inc["probability"]; return (inc["expected_loss"] / p) if p else 0.0


def analyse(label, rev, industry, sub_industry=None, rsi_rev=None):
    cats = load_clean()
    score, level, rsi_score, fin = run(cats, rev, industry, sub_industry, rsi_rev)
    incs = fin["incident_types"]
    pb = fin["probability_drivers"]["p_breach"]
    tef = fin["probability_drivers"]["tef"]
    vuln = fin["probability_drivers"]["vulnerability"]
    p_int = incs["ddos_infra"]["probability"]
    total = fin["total"]["most_likely"]

    # recovered per-event severities (LM components)
    c_dbl, c_rw, c_wip = cost(incs["double_extortion"]), cost(incs["ransomware_only"]), cost(incs["wiper_destructive"])
    c_sil, c_ext, c_opp = cost(incs["silent_breach"]), cost(incs["data_extortion"]), cost(incs["opportunistic_breach"])
    c_ddos = cost(incs["ddos_infra"])

    # BREACH channel = canonical FAIR: LEF=p_breach, E[LM]=share-weighted (shares sum to 1.0)
    elm_breach = 0.50 * c_sil + 0.20 * c_ext + 0.30 * c_opp
    ale_breach = pb * elm_breach
    # RANSOMWARE channel as-built: 'LEF'=rsi*0.70 (index, NOT FAIR), E[LM]=normalised
    lef_rw_now = rsi_score * 0.70
    elm_rw = (0.25 * c_dbl + 0.40 * c_rw + 0.05 * c_wip) / 0.70
    ale_rw_now = lef_rw_now * elm_rw
    # DDOS
    ale_ddos = p_int * c_ddos

    def pct(x): return f"{x/rev*100:.2f}%"

    print("=" * 80)
    print(f"{label}   score={score}({level})")
    print(f"  FAIR drivers: vulnerability={vuln:.4f}  TEF={tef}  ->  LEF(breach) p_breach={pb:.4f}")
    print(f"                rsi_score(index)={rsi_score:.4f}   p_interruption={p_int:.4f}")
    print("=" * 80)
    print(f"  {'channel':<26}{'LEF (events/yr)':>16}{'E[LM] per event':>18}{'ALE':>16}{'%rev':>9}")
    print("  " + "-" * 78)
    print(f"  {'BREACH (canonical FAIR)':<26}{pb:>16.4f}R{elm_breach:>16,.0f}R{ale_breach:>14,.0f}{pct(ale_breach):>9}")
    print(f"  {'RANSOMWARE (as-built)':<26}{lef_rw_now:>16.4f}R{elm_rw:>16,.0f}R{ale_rw_now:>14,.0f}{pct(ale_rw_now):>9}")
    print(f"  {'DDOS/availability':<26}{p_int:>16.4f}R{c_ddos:>16,.0f}R{ale_ddos:>14,.0f}{pct(ale_ddos):>9}")
    print("  " + "-" * 78)
    print(f"  {'MODEL TOTAL (as-built)':<26}{'':>16}{'':>17}R{total:>14,.0f}{pct(total):>9}")
    print()
    # What canonical FAIR implies if ransomware is ALSO LEF x E[LM] with a calibrated LEF_rw.
    print("  If ransomware were ALSO canonical FAIR (LEF_rw x E[LM_rw]) instead of rsi-index x 0.70:")
    for tag, lef_rw in (("LEF_rw = p_breach (ransomware ~ breach freq)", pb),
                        ("LEF_rw = rsi x 0.30 (reuse breach LEF const)", rsi_score * 0.30),
                        ("LEF_rw = rsi x 0.20", rsi_score * 0.20)):
        ale_rw_fair = lef_rw * elm_rw
        fair_total = ale_breach + ale_rw_fair + ale_ddos
        print(f"    {tag:<46} LEF_rw={lef_rw:.4f}  ransomware ALE R{ale_rw_fair:>13,.0f}"
              f"  ->  FAIR total R{fair_total:>13,.0f} ({pct(fair_total)})")
    print()


analyse("CLEAN R200M Financial Services", 200_000_000, "Financial Services", rsi_rev=200_000_000)
analyse("phishield R10M Financial Services", 10_000_000, "Financial Services", rsi_rev=0)
analyse("takealot R20BN eCommerce(bi1.5)", 20_000_000_000, "eCommerce",
        sub_industry="eCommerce", rsi_rev=20_000_000_000)
print("Reading: the BREACH channel as-built IS canonical FAIR (LEF x E[LM]). The")
print("warmth is the RANSOMWARE channel, whose 'LEF' is rsi_score x 0.70 - an INDEX,")
print("not a TEF x Vulnerability frequency. Recast it as proper FAIR and the headline")
print("drops to the FAIR-implied band. DDOS is a third, separately heuristic channel.")
