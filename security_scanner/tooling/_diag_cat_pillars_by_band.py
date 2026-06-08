# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX diagnostic (read-only): decompose the catastrophe by PILLAR (C1-C5) for an
FSP across revenue bands, to inform a small->large taper. Shows, per band:
 - C1 third-party liability: CURRENT (IBM-residual, floors small cos high) vs
   RECORDS-DRIVEN (estimated_records x R90) - the gap is the over-statement.
 - C2 regulatory fines: central, POPIA statutory max, capacity-scaled cat-stack.
 - C3 BI, C4 ransom, C5 IR.
 - resulting cat P99 / 1-in-250 (% of revenue).
NOT shipped."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import RiskScorer, RansomwareIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier

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

def run(rev):
    cats = load()
    sc, lv, _ = RiskScorer().calculate(cats, waf_apex_status=None); cats["_overall_score"] = sc
    rsi = RansomwareIndex().calculate(cats, industry="Financial Services", annual_revenue=rev)
    return FinancialImpactCalculator().calculate(cats, rsi, 0, "Financial Services", annual_revenue_zar=rev)

BANDS = [10_000_000, 50_000_000, 100_000_000, 424_000_000, 2_000_000_000, 20_000_000_000]
def M(x): return f"R{x/1e6:,.1f}M" if x < 1e9 else f"R{x/1e9:,.2f}bn"

print("=" * 110)
print("FSP CATASTROPHE PILLARS BY REVENUE BAND  (central full-stack severity, then cat tail)")
print("=" * 110)
hdr = (f"{'revenue':>10} | {'C1 IBM-resid':>13} {'C1 recs-driven':>14} | {'C2 central':>11} "
       f"{'C2 statutory':>13} {'cap.factor':>10} | {'C3 BI':>10} {'C4':>9} {'C5':>9}")
print(hdr); print("-" * len(hdr))
rows = []
for rev in BANDS:
    fin = run(rev)
    de = fin["incident_types"]["double_extortion"]; p = de["probability"]
    full = {k: de["components"][k] / p for k in de["components"]}
    reg = fin["regulatory_exposure"]; cs = reg["catastrophe_stack"]
    recs = fin["scenarios"]["data_breach"]["records_assumption_disclosure"]["estimated_records"]
    c1_recs = recs * 90.0
    pml = fin["monte_carlo"]["severity_pml"]
    rows.append((rev, full, reg, cs, recs, c1_recs, pml))
    print(f"{M(rev):>10} | {M(full['C1']):>13} {M(c1_recs):>14} | {M(full['C2']):>11} "
          f"{M(cs['popia_statutory_scaled_zar']):>13} {cs['capacity_factor']:>10.2f} | "
          f"{M(full['C3']):>10} {M(full['C4']):>9} {M(full['C5']):>9}")

print("\n" + "=" * 110)
print("RESULTING CAT vs REVENUE  (and the C1 over-statement ratio = IBM-residual / records-driven)")
print("=" * 110)
hdr2 = (f"{'revenue':>10} | {'est.records':>11} | {'P99 cat':>12} {'%rev':>6} | {'1-in-250':>12} {'%rev':>6} "
        f"| {'C1 over-stmt':>12} | {'records-only cat est':>20}")
print(hdr2); print("-" * len(hdr2))
for rev, full, reg, cs, recs, c1_recs, pml in rows:
    overstmt = full['C1'] / c1_recs if c1_recs else float('inf')
    # crude records-only cat: swap C1(IBM-resid) -> C1(records) in the central, keep tail multiple
    tail_mult = pml['p99_6'] / sum(full.values())
    recs_only_full = sum(full.values()) - full['C1'] + c1_recs
    recs_only_cat = recs_only_full * tail_mult
    print(f"{M(rev):>10} | {recs:>11,.0f} | {M(pml['p99']):>12} {pml['p99']/rev*100:5.0f}% | "
          f"{M(pml['p99_6']):>12} {pml['p99_6']/rev*100:5.0f}% | {overstmt:>10.1f}x | {M(recs_only_cat):>20} ({recs_only_cat/rev*100:.0f}%)")
print("\n  C2 statutory = POPIA max (R10M) x capacity_factor. For micro FSPs the model SCALES THE FINE DOWN")
print("  by capacity_factor - which may UNDER-state a real R10M POPIA fine on a <R10M business.")
