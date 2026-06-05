# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #17, Card Verification render): render the Full Technical PDF,
Broker Summary PDF, and offline HTML for phishield (R10M FS) and takealot (R20bn
eCommerce) using the EXACT §8 invocation (matches _verify_item17_cards.py /
_diag_item15_outputs.py), so the rendered cards carry the faithful §8 numbers.
Mirrors regen_outputs_from_cache.py but adds sub_industry + the phishield rsi_rev=0
separation. Samples land in docs/calibration_prep/item17_samples/. NOT shipped."""
import sys, json
from pathlib import Path
HERE = Path(__file__).parent; ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from scoring_analytics import (RiskScorer, RansomwareIndex, DataBreachIndex,
                               FinancialImpactCalculator, RemediationSimulator)
from checkers_threats import CredentialRiskClassifier
from pdf_report import generate_pdf
from jinja2 import Environment, FileSystemLoader

OUT = ROOT / "docs" / "calibration_prep" / "item17_samples"
OUT.mkdir(parents=True, exist_ok=True)


def build_results(fixture, industry, rev_zar, sub_industry, rsi_rev):
    d = json.load(open(ROOT / fixture, encoding="utf-8"))
    results = d if (isinstance(d, dict) and "categories" in d) else {"categories": d}
    cats = results["categories"]
    cats["credential_risk"] = CredentialRiskClassifier.classify(
        dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {},
        intelx=cats.get("intelx", {}) or {})
    score, level, recs = RiskScorer().calculate(cats, waf_apex_status=None)
    results["overall_risk_score"] = score
    results["risk_level"] = level
    results["recommendations"] = recs
    cats["_overall_score"] = score
    rsi = RansomwareIndex().calculate(cats, industry=industry, annual_revenue=rsi_rev)
    results.setdefault("insurance", {})["rsi"] = rsi
    fin = FinancialImpactCalculator().calculate(
        cats, rsi, annual_revenue=0, industry=industry,
        annual_revenue_zar=rev_zar, sub_industry=sub_industry)
    results["insurance"]["financial_impact"] = fin
    results["insurance"]["dbi"] = DataBreachIndex().calculate(cats)
    try:
        results["insurance"]["remediation"] = RemediationSimulator().calculate(
            cats, rsi, fin, annual_revenue=rev_zar, industry=industry)
    except Exception as e:
        print(f"  (remediation sim skipped: {e})")
    results.setdefault("domain_scanned", fixture.split("/")[-1].split("_")[0] + ".example")
    return results


def render(tag, results):
    (OUT / f"{tag}_full.pdf").write_bytes(generate_pdf(results, report_type="full"))
    (OUT / f"{tag}_summary.pdf").write_bytes(generate_pdf(results, report_type="summary"))
    env = Environment(loader=FileSystemLoader(str(ROOT / "templates")), autoescape=True)
    t = env.get_template("results.html")
    (OUT / f"{tag}_results.html").write_text(
        t.render(results=results, domain=results.get("domain_scanned", ""), timestamp="",
                 scan_id=f"item17-{tag}", risk_score=results.get("overall_risk_score", 0),
                 risk_level=results.get("risk_level", "")), encoding="utf-8")
    fin = results["insurance"]["financial_impact"]
    rp = fin["risk_probability"]; cl = fin["cover_ladder"]
    rs = fin.get("risk_mitigations", {}).get("remediation_summary", {})
    print(f"  [{tag}] breach {rp['data_breach']['probability_pct']}% ({rp['data_breach']['grade']}) | "
          f"cyber {rp['cyber_incident']['probability_pct']}% ({rp['cyber_incident']['grade']}) | "
          f"avail {rp['availability_resilience']['indicator_pct']}% | "
          f"cover1-250 R{cl['catastrophic']['loss_zar']:,.0f} | ALE R{fin['total']['most_likely']:,.0f}")
    if rs:
        print(f"         remediation: breach {rs['breach_probability_before_pct']}% "
              f"({rs['breach_grade_before']}) -> {rs['breach_probability_after_pct']}% "
              f"({rs['breach_grade_after']}); exposure -{rs['exposure_reduction_pct']}%")


print("Rendering item #17 card samples (full PDF + summary PDF + HTML)...")
render("phishield_r10m_fs",
       build_results("test_fixtures/phishield_live.json", "Financial Services", 10_000_000, None, 0))
render("takealot_r20bn_ecom",
       build_results("test_fixtures/takealot_baseline.json", "eCommerce", 20_000_000_000, "eCommerce", 20_000_000_000))
print(f"\nSamples in: {OUT}")
for p in sorted(OUT.glob("*")):
    print(f"  {p.relative_to(ROOT)}  ({p.stat().st_size // 1024} KB)")
