# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX verification (read-only) for item #18c: a soft-fail SPF finding now
yields BOTH per-finding advice (RECOMMENDATIONS) AND a modelled saving
(MITIGATIONS). NOT shipped."""
import os, re, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from scoring_analytics import RiskScorer, RansomwareIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier

SOFT = "SPF ends with '~all' (soft-fail) and no enforcing DMARC policy - does not instruct receivers to reject spoofed mail"
NEU  = "SPF ends with '?all' (neutral) and no enforcing DMARC policy - provides no spoofing protection"

# --- 1. RECOMMENDATIONS substring match (mirrors the `if key in issue` lookup) ---
recs = getattr(RiskScorer, "RECOMMENDATIONS", None) or getattr(FinancialImpactCalculator, "RECOMMENDATIONS", {})
print("=== RECOMMENDATIONS lookup (substring match) ===")
for issue in (SOFT, NEU):
    hit = [rec for key, rec in recs.items() if key in issue and rec]
    ok = "OK  " if hit else "FAIL"
    print(f"  {ok} issue '{issue[:34]}...' -> {hit[0][:70] if hit else '(NO ADVICE)'}")

# --- 2. MITIGATIONS end-to-end via _build_mitigations on the real fixture ---
d = json.load(open(os.path.join(SEC, "test_fixtures", "phishield_live.json"), encoding="utf-8"))
cats = dict(d.get("categories", d))
cats["credential_risk"] = CredentialRiskClassifier.classify(
    dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {}, intelx=cats.get("intelx", {}) or {})
# Inject the soft-fail finding into email_security issues (simulate a ~all + p=none domain).
es = dict(cats.get("email_security", {}) or {})
es["issues"] = list(es.get("issues", [])) + [SOFT]
cats["email_security"] = es
score, level, _ = RiskScorer().calculate(cats, waf_apex_status=None)
cats["_overall_score"] = score
rsi = RansomwareIndex().calculate(cats, industry="Financial Services", annual_revenue=0)
fin = FinancialImpactCalculator().calculate(cats, rsi, annual_revenue=0, industry="Financial Services", annual_revenue_zar=10_000_000)
findings = fin.get("risk_mitigations", {}).get("findings", [])
spf_fix = [f for f in findings if "Harden SPF" in f.get("recommendation", "")]
print("\n=== MITIGATIONS end-to-end (_build_mitigations on fixture + injected ~all) ===")
if spf_fix:
    f = spf_fix[0]
    print(f"  OK   finding present: '{f['recommendation']}'  [{f['severity']}]  saving R{f['estimated_annual_savings_zar']:,.0f}")
    print(f"       matched issue: {f['finding'][:60]}...")
else:
    print("  FAIL  'Harden SPF' mitigation did NOT fire")
# Confirm no spurious 'No SPF record' email-auth mitigation (SPF is present here).
absent = [f for f in findings if "Implement email authentication" in f.get("recommendation", "")]
print(f"  (sanity) absent-SPF email-auth mitigation fired? {bool(absent)}  (expect False - SPF is present)")
print("\nDONE.")
