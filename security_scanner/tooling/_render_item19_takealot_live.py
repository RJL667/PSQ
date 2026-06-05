# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #19): enrich the takealot sample with LIVE supply-chain data so
the exec deck shows real output instead of the stripped-baseline "Not run" wall.
Runs the passive checkers (S-2/S-3/S-4/S-5/S-10) live against takealot.com +
replicates the Phase 4f cross-correlation join (faithful to scanner.py:930-1067),
merges into the baseline (which carries hudson_rock), and re-renders all tiers.
Credit-free (no paid APIs). NOT shipped."""
import sys, json
from pathlib import Path
ROOT = Path(".").resolve(); sys.path.insert(0, str(ROOT))
from checkers_supply_chain import (ThirdPartyJSChecker, DependencyManifestChecker,
    EmailVendorSurfaceChecker, VendorBreachChecker, CMSPluginSBOMChecker)
from scoring_analytics import RiskScorer, RansomwareIndex, DataBreachIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier
from pdf_report import generate_pdf
from jinja2 import Environment, FileSystemLoader

DOM = "takealot.com"
OUT = ROOT / "docs" / "calibration_prep" / "item17_samples"

d = json.load(open(ROOT / "test_fixtures" / "takealot_baseline.json", encoding="utf-8"))
cats = dict(d.get("categories", d))

print(f"Running live passive supply-chain checkers against {DOM} ...")
cats["third_party_js"]       = ThirdPartyJSChecker().check(DOM)
cats["dependency_manifests"] = DependencyManifestChecker().check(DOM)
cats["email_vendor_surface"] = EmailVendorSurfaceChecker().check(DOM)
cats["vendor_breach"]        = VendorBreachChecker().check(DOM)
cats["cms_plugin_sbom"]      = CMSPluginSBOMChecker().check(DOM)

# --- Phase 4f cross-correlation (faithful replica of scanner.py:930-1067) ---
hr = cats.get("hudson_rock", {}); evs = cats["email_vendor_surface"]; vb = cats["vendor_breach"]
corr = {"status": "no_data",
        "hudson_rock_third_party_count": int(hr.get("third_party_exposures", 0) or 0),
        "spf_vendor_count": 0, "spf_vendors": [], "vendor_breach_match_count": 0,
        "suspected_vendors": [], "severity": "none", "critical_count": 0,
        "high_count": 0, "medium_count": 0, "score": 100, "issues": []}
hr_tp = corr["hudson_rock_third_party_count"]
if hr.get("status") == "completed" and hr_tp > 0:
    keys = [(v.get("vendor") or "").lower().strip()
            for v in (evs.get("vendors_detected") or []) if (v.get("vendor") or "").strip()]
    corr["spf_vendors"] = keys; corr["spf_vendor_count"] = len(keys)
    bbv = {}
    for m in (vb.get("matches") or []):
        vk = (m.get("vendor") or "").lower().strip()
        if vk:
            bbv.setdefault(vk, []).append({"date": m.get("date", ""), "severity": m.get("severity", "")})
    susp = [{"vendor": vk, "breaches": bbv[vk]} for vk in keys if vk in bbv]
    corr["suspected_vendors"] = susp; corr["vendor_breach_match_count"] = len(susp)
    if susp:
        rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}; wr = -1; ws = "medium"
        for s in susp:
            for b in s["breaches"]:
                bs = (b.get("severity") or "").lower().strip()
                if rank.get(bs, -1) > wr and bs in rank:
                    wr = rank[bs]; ws = bs
        corr.update(severity=ws, status="completed",
                    critical_count=1 if ws == "critical" else 0,
                    high_count=1 if ws == "high" else 0,
                    medium_count=1 if ws == "medium" else 0)
    elif keys:
        corr.update(severity="high", high_count=1, status="completed")
    else:
        corr.update(severity="medium", medium_count=1, status="completed")
cats["third_party_correlation"] = corr

print("\nLive supply-chain results:")
for k in ("third_party_js", "dependency_manifests", "email_vendor_surface",
          "vendor_breach", "cms_plugin_sbom", "third_party_correlation"):
    v = cats[k]
    print(f"  {k:24s} status={v.get('status'):10s} sev={str(v.get('severity','')):8s} "
          f"vendors={v.get('vendor_count', v.get('spf_vendor_count',''))} "
          f"matches={v.get('match_count','')} crit/high={v.get('critical_match_count', v.get('critical_count',''))}/{v.get('high_match_count', v.get('high_count',''))}")

# Save the enriched fixture for traceability.
json.dump({"categories": cats}, open(ROOT / "test_fixtures" / "takealot_sc_enriched.json", "w", encoding="utf-8"), indent=1, default=str)

# --- score + render all tiers ---
res = {"categories": cats}
cats["credential_risk"] = CredentialRiskClassifier.classify(
    dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {}, intelx=cats.get("intelx", {}) or {})
sc, lv, rc = RiskScorer().calculate(cats, waf_apex_status=None)
res["overall_risk_score"] = sc; res["risk_level"] = lv; res["recommendations"] = rc; cats["_overall_score"] = sc
rsi = RansomwareIndex().calculate(cats, industry="eCommerce", annual_revenue=20_000_000_000)
res.setdefault("insurance", {})["rsi"] = rsi
res["insurance"]["financial_impact"] = FinancialImpactCalculator().calculate(
    cats, rsi, annual_revenue=0, industry="eCommerce", annual_revenue_zar=20_000_000_000, sub_industry="eCommerce")
res["insurance"]["dbi"] = DataBreachIndex().calculate(cats); res["domain_scanned"] = "takealot.com"
tag = "takealot_r20bn_ecom"
(OUT / f"{tag}_assessment_deck.pdf").write_bytes(generate_pdf(res, report_type="assessment"))
(OUT / f"{tag}_full.pdf").write_bytes(generate_pdf(res, report_type="full"))
(OUT / f"{tag}_summary.pdf").write_bytes(generate_pdf(res, report_type="summary"))
env = Environment(loader=FileSystemLoader(str(ROOT / "templates")), autoescape=True)
(OUT / f"{tag}_results.html").write_text(
    env.get_template("results.html").render(results=res, domain="takealot.com", timestamp="",
        scan_id="item19", risk_score=sc, risk_level=lv), encoding="utf-8")
print(f"\nRe-rendered takealot (LIVE supply-chain) all tiers -> {OUT}")
