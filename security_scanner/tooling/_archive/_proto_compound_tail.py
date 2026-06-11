#!/usr/bin/env python3
"""SANDBOX concept demo (NOT shipped): how the cat tail responds to a posture
(score) change under three aggregations, for phishield R10m Financial Services.

  A  prob-weighted    = p x severity        (CURRENT model: every iteration is
                                              probability-scaled severity)
  B  compound         = severity if a Bernoulli(p) event occurs this year else 0
                        (realised annual loss -- the actuarial aggregate view)
  C  loss-given-breach = the severity distribution itself (posture-independent)

Severity is pulled from the REAL FinancialImpactCalculator (cost_components),
and is identical at both scores -> proves severity does not depend on posture.
Only the frequency (eff_freq = real expected / E[severity]) moves with the score.
"""
import sys, os, json, numpy as np

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

def run(score):
    c = dict(cats); c["_overall_score"] = score
    return FinancialImpactCalculator().calculate(
        c, rsi, annual_revenue=0, industry="Financial Services", annual_revenue_zar=REV)

np.random.seed(42); N = 500_000
def pert(a, m, b, n, lamb=4.0):
    a, m, b = float(a), float(m), float(b)
    if b <= a: return np.full(n, m)
    al = 1 + lamb * (m - a) / (b - a); be = 1 + lamb * (b - m) / (b - a)
    return a + np.random.beta(al, be, n) * (b - a)
def pe(x, q): return float(np.percentile(x, q))

res = {}
for score in (380, 165):
    fin = run(score)
    exp = float(fin["total"]["most_likely"]); rp = fin["return_periods"]
    sev_mode = sum(float(v) for v in fin["cost_components"].values())
    pbr = float(fin["probability_drivers"]["p_breach"])
    sev = pert(0.5 * sev_mode, sev_mode, 5.0 * sev_mode, N)
    eff = exp / sev.mean()
    occur = np.random.random(N) < eff
    A = eff * sev; B = np.where(occur, sev, 0.0); C = sev
    res[score] = dict(
        pbr=pbr, sev_mode=sev_mode, eff=eff,
        real_exp=exp, real_100=float(rp["1_in_100"]["loss_zar"]), real_250=float(rp["1_in_250"]["loss_zar"]),
        A_mean=A.mean(), A_250=pe(A, 99.6),
        B_mean=B.mean(), B_100=pe(B, 99), B_250=pe(B, 99.6),
        C_mean=C.mean(), C_100=pe(C, 99), C_250=pe(C, 99.6))

def line(name, k):
    a, b = res[380][k], res[165][k]
    ratio = (a / b) if b else float("inf")
    print(f"  {name:<34} R{a:>13,.0f}   R{b:>13,.0f}   {ratio:>5.1f}x")

print("=" * 84)
print(f"phishield  R{REV:,}  Financial Services   (severity held constant; only posture/score varies)")
print("=" * 84)
print(f"  p_breach:        score 380 -> {res[380]['pbr']:.4f}    score 165 -> {res[165]['pbr']:.4f}")
print(f"  loss-given-breach severity (mode): R{res[380]['sev_mode']:,.0f} (380) vs R{res[165]['sev_mode']:,.0f} (165)"
      f"  -> {'IDENTICAL = posture-independent' if abs(res[380]['sev_mode']-res[165]['sev_mode'])<1 else 'DIFFERS'}")
print(f"\n  {'metric':<34} {'score 380':>14}   {'score 165':>14}   drop")
print("  " + "-" * 78)
print("  EXPECTED / ANNUALISED loss (should fall with remediation -- the value-prop card):")
line("REAL model expected", "real_exp")
line("B compound mean", "B_mean")
print("  CAT TAIL  1-in-250 (the concern):")
line("REAL model 1-in-250 (current=A)", "real_250")
line("A prob-weighted 1-in-250", "A_250")
line("B compound 1-in-250", "B_250")
line("C loss-given-breach 1-in-250", "C_250")
print("\n  Reading: A (current) collapses the tail with posture. B keeps the tail a REALISED")
print("  event (drops modestly). C is a pure severity floor (posture-independent). The EXPECTED")
print("  loss (top block) falls the same under A and B -- remediation value is preserved either way.")
