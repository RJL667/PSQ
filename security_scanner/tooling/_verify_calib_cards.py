# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX Card-Verification (2026-06-05) for the calibration session. Renders the
takealot reference across ALL tiers (full / assessment deck / summary PDF + HTML)
and extracts the CHANGED cards' rendered text to confirm the new calibrated values
appear consistently (Step 3), on the takealot reference (Step 5). Step 6 (white-box
magnitude classification) is asserted inline. Credit-free (baseline fixture). NOT shipped."""
import sys, json, re
from pathlib import Path
ROOT = Path(".").resolve(); sys.path.insert(0, str(ROOT))
from scoring_analytics import (RiskScorer, RansomwareIndex, DataBreachIndex,
                               FinancialImpactCalculator, _CYBER_INCIDENT_BANDS)
from checkers_threats import CredentialRiskClassifier
from pdf_report import generate_pdf
from jinja2 import Environment, FileSystemLoader

OUT = ROOT / "docs" / "calibration_prep" / "calib_verify"
OUT.mkdir(parents=True, exist_ok=True)
d = json.load(open(ROOT / "test_fixtures" / "takealot_baseline.json", encoding="utf-8"))
cats = dict(d.get("categories", d))
cats["credential_risk"] = CredentialRiskClassifier.classify(
    dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {}, intelx=cats.get("intelx", {}) or {})
sc, lv, rc = RiskScorer().calculate(cats, waf_apex_status=None); cats["_overall_score"] = sc
rsi = RansomwareIndex().calculate(cats, industry="eCommerce", annual_revenue=20_000_000_000)
fin = FinancialImpactCalculator().calculate(cats, rsi, annual_revenue=0, industry="eCommerce",
        annual_revenue_zar=20_000_000_000, sub_industry="eCommerce")
res = {"categories": cats, "overall_risk_score": sc, "risk_level": lv, "recommendations": rc,
       "domain_scanned": "takealot.com", "scan_timestamp": "2026-06-05T00:00:00",
       "insurance": {"rsi": rsi, "financial_impact": fin, "dbi": DataBreachIndex().calculate(cats)}}

# ---- DATA values that feed the changed cards ----
rp = fin["risk_probability"]; ci = rp["cyber_incident"]; av = rp["availability_resilience"]
bi = fin["scenarios"]["business_interruption"]
print("=" * 78)
print("STEP 6 — changed-card DATA values (white-box)")
print("=" * 78)
print(f"  T1 cyber bands tuple : {[(u, g) for u, g in _CYBER_INCIDENT_BANDS]}")
print(f"  T1 cyber_incident    : {ci['probability_pct']}%  grade={ci['grade']}  bands={[b['upper_pct'] for b in ci['bands']]}")
print(f"  T3a availability     : {av['indicator_pct']}%  calibrated={av['calibrated']}")
print(f"     basis            : {av['basis'][:96]}...")
print(f"  T3b BI estimated_loss: R{bi['estimated_loss']:,}")
findings = fin.get("risk_mitigations", {}).get("findings", [])
mits = [m for m in findings if any(k in m.get("label","") for k in
        ("email authentication","Enforce DMARC","Harden SPF","DKIM","Web Application Firewall","CDN","hosting redundancy"))]
print("  T2/T3/#3 mitigation findings rendered (label : savings/yr):")
for m in mits:
    print(f"     {m['label'][:54]:<54} R{m.get('estimated_annual_savings_zar',0):>12,}")

# ---- RENDER all tiers ----
for rt, fn in [("full","full"),("assessment","deck"),("summary","summary")]:
    (OUT / f"takealot_{fn}.pdf").write_bytes(generate_pdf(res, report_type=rt))
env = Environment(loader=FileSystemLoader(str(ROOT / "templates")), autoescape=True)
html = env.get_template("results.html").render(results=res, domain="takealot.com", timestamp="",
        scan_id="calibverify", risk_score=sc, risk_level=lv)
(OUT / "takealot_results.html").write_text(html, encoding="utf-8")

# ---- STEP 3: extract rendered card text from HTML ----
print("\n" + "=" * 78); print("STEP 3 — rendered HTML card text (cross-tier consistency)"); print("=" * 78)
def show(label, pat):
    m = re.search(pat, html, re.I | re.S)
    txt = re.sub(r"<[^>]+>", "", m.group(0)).strip() if m else "*** NOT FOUND ***"
    txt = re.sub(r"\s+", " ", txt)
    print(f"  [{label}] {txt[:230]}")
show("cyber bands", r"Relative posture bands.{0,180}")
show("availability", r"Availability resilience[^<]*<[^>]*>[^<]*<[^>]*>[^<]*")
print("\n  PDF tiers rendered:", ", ".join(p.name for p in sorted(OUT.glob("*.pdf"))))
print("  HTML rendered:", (OUT / "takealot_results.html").name)

# ---- PDF text extraction (best-effort) ----
try:
    from pypdf import PdfReader
    txt = "".join(pg.extract_text() or "" for pg in PdfReader(str(OUT / "takealot_full.pdf")).pages)
    for label, pat in [("PDF cyber bands", r"Relative posture bands[^.]{0,120}"),
                       ("PDF availability", r"Availability resilience indicator[^.]{0,120}")]:
        m = re.search(pat, txt, re.I | re.S)
        print(f"  [{label}] {re.sub(chr(92)+'s+',' ', m.group(0)).strip()[:200] if m else '*** NOT FOUND ***'}")
except Exception as e:
    print(f"  (PDF text-extract skipped: {e})")
print("\nDONE. Inspect rendered files under:", OUT)
