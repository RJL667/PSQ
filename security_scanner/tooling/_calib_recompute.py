#!/usr/bin/env python3
"""SANDBOX recompute harness — FIN-9 / credential-confidence calibration pre-prep
(2026-06-03 solo dry-run). NOT production; not shipped.

Loads a saved scan fixture's `categories` dict and re-runs the REAL scoring
pipeline on the CURRENT code (RiskScorer -> _overall_score -> RSI -> DBI -> FIC)
so we can read p_breach / RSI / loss / return-periods and diff across calibration
iterations. Mirrors tooling/verify_supply_chain_financial_wiring.py::_run_pipeline.

Usage:
  py tooling/_calib_recompute.py [fixture.json] --rev 10000000 --industry "Financial Services" --label iter0
"""
import sys, os, json, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)

from scoring_analytics import (RiskScorer, RansomwareIndex, DataBreachIndex,
                               FinancialImpactCalculator)
from checkers_threats import CredentialRiskClassifier

ITER_DIR = os.path.join(HERE, "_calib_iterations")


def load_cats(path):
    d = json.load(open(path, encoding="utf-8"))
    if isinstance(d, dict) and isinstance(d.get("categories"), dict):
        return d["categories"], d
    return d, {"categories": d}


def run(cats, industry, revenue_zar, rsi_revenue, sub_industry=None):
    # Production wiring (scanner.py): RSI gets the RAW annual_revenue (phishield=0
    # -> micro-business multiplier), while FIC gets the RESOLVED annual_revenue_zar
    # (floored to R10M by resolve_effective_revenue_zar). Keep them separate so the
    # recompute reproduces the shipped fixture exactly.
    # Re-run the credential classifier on the fixture's RAW inputs so calibration
    # changes to CredentialRiskClassifier (K1-K7) flow into the score. The saved
    # fixture's `credential_risk` is stale (pre-calibration). Mirrors scanner.py
    # Phase 4e -> scoring order: fresh credential_risk lands in the SAME dict the
    # scorer and RSI read (cat_results is results["categories"] in production).
    cats = dict(cats)
    cats["credential_risk"] = CredentialRiskClassifier.classify(
        dehashed=cats.get("dehashed", {}) or {},
        hudson_rock=cats.get("hudson_rock", {}) or {},
        intelx=cats.get("intelx", {}) or {},
    )
    scorer = RiskScorer()
    risk_score, level, _recs = scorer.calculate(cats, waf_apex_status=None)
    cats2 = dict(cats)
    cats2["_overall_score"] = risk_score
    rsi = RansomwareIndex().calculate(cats, industry=industry, annual_revenue=rsi_revenue)
    dbi = DataBreachIndex().calculate(cats)
    fin = FinancialImpactCalculator().calculate(
        cats2, rsi, annual_revenue=0, industry=industry.title(),
        annual_revenue_zar=revenue_zar, sub_industry=sub_industry)
    return risk_score, level, rsi, dbi, fin, cats


def summarize(risk_score, level, rsi, dbi, fin, cats):
    pd = fin.get("probability_drivers", {})
    total = fin.get("total", {})
    rp = fin.get("return_periods", {})
    cc = fin.get("cost_components", {})
    cred = cats.get("credential_risk", {}) or {}
    factors = []
    for f in rsi.get("contributing_factors", []):
        if isinstance(f, dict):
            factors.append({k: f.get(k) for k in ("factor", "weight", "value", "contribution") if k in f})
        else:
            factors.append(f)
    return {
        "risk_score": risk_score,
        "risk_level": level,
        "vulnerability": pd.get("vulnerability"),
        "tef": pd.get("tef"),
        "p_breach": pd.get("p_breach"),
        "rsi_score": rsi.get("rsi_score"),
        "rsi_level": rsi.get("rsi_level") or rsi.get("susceptibility") or rsi.get("risk_label"),
        "rsi_factor_count": rsi.get("factor_count"),
        "rsi_factors": factors,
        "dbi_score": dbi.get("dbi_score"),
        "credential_level": cred.get("risk_level"),
        "credential_class": cred.get("credential_class"),
        "credential_pbreach_contribution": cred.get("pbreach_contribution"),
        "credential_weighted_exposure": cred.get("weighted_exposure"),
        "credential_score": cred.get("risk_score"),
        "total_min": total.get("min"),
        "total_most_likely": total.get("most_likely"),
        "total_max": total.get("max"),
        "estimated_annual_loss": fin.get("estimated_annual_loss"),
        "return_periods": rp,
        "cost_components": cc,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("fixture", nargs="?", default="test_fixtures/phishield_live.json")
    ap.add_argument("--rev", type=int, default=10_000_000, help="FIC annual_revenue_zar (resolved/floored)")
    ap.add_argument("--rsi-rev", type=int, default=0, help="RSI annual_revenue (raw; phishield=0)")
    ap.add_argument("--industry", default="Financial Services")
    ap.add_argument("--sub-industry", default=None,
                    help="exact INDUSTRY_BI_FACTOR key (e.g. 'eCommerce'); bypasses title-casing")
    ap.add_argument("--label", default="adhoc")
    args = ap.parse_args()

    cats, _full = load_cats(args.fixture)
    risk_score, level, rsi, dbi, fin, cats = run(
        cats, args.industry, args.rev, args.rsi_rev, sub_industry=args.sub_industry)
    summ = summarize(risk_score, level, rsi, dbi, fin, cats)
    summ["_meta"] = {"fixture": args.fixture, "rev_zar": args.rev,
                     "industry": args.industry, "label": args.label}

    os.makedirs(ITER_DIR, exist_ok=True)
    out = os.path.join(ITER_DIR, f"{args.label}.json")
    json.dump(summ, open(out, "w", encoding="utf-8"), indent=2, default=str)

    print(f"=== CALIB RECOMPUTE [{args.label}] {args.industry} R{args.rev:,} ===")
    print(f"  risk_score      : {summ['risk_score']}  ({summ['risk_level']})")
    print(f"  vulnerability   : {summ['vulnerability']}")
    print(f"  tef             : {summ['tef']}")
    print(f"  p_breach        : {summ['p_breach']}")
    print(f"  rsi_score       : {summ['rsi_score']}  factors={summ['rsi_factor_count']}")
    for f in summ["rsi_factors"]:
        s = json.dumps(f, ensure_ascii=True) if isinstance(f, dict) else str(f)
        print("      - " + s.encode("ascii", "replace").decode("ascii"))
    print(f"  dbi_score       : {summ['dbi_score']}")
    print(f"  credential      : level={summ['credential_level']} class={summ['credential_class']} "
          f"W={summ['credential_weighted_exposure']} pbreach_contrib={summ['credential_pbreach_contribution']} score={summ['credential_score']}")
    print(f"  total loss      : min R{(summ['total_min'] or 0):,}  ML R{(summ['total_most_likely'] or 0):,}  max R{(summ['total_max'] or 0):,}")
    eal = summ['estimated_annual_loss']
    print(f"  est annual loss : {json.dumps(eal) if isinstance(eal, dict) else ('R%s' % format(eal or 0, ','))}")
    print(f"  return_periods  : {json.dumps(summ['return_periods'])[:600]}")
    print(f"  cost_components : {json.dumps(summ['cost_components'])[:600]}")
    print(f"  -> saved {out}")


if __name__ == "__main__":
    main()
