#!/usr/bin/env python3
"""SANDBOX one-off (task #9 / LAST calibration item): risk-level band re-fit in
RiskScorer.calculate().

The four overall risk bands (Low/Medium/High/Critical on the 0-1000 score) were a
"blind even split" at 200/400/600 with no stated rationale. The calibration brief
(docs/calibration_prep/00_CALIBRATION_SUMMARY.md, row "Risk-level bands") asks to
"re-fit the cut-offs to the corrected distribution and align them to the calibrated
p(breach) tiers ... rather than a blind even split."

RE-FIT RESULT = RETAIN 200/400/600, now ANCHORED + DOCUMENTED (comment-only; no
numeric change). Reasoning (all data-anchored, validation-by-recompute):

  * Run through the CALIBRATED convex curve (vulnerability = (score/1000)**1.8;
    p_breach = vulnerability * TEF * 0.3), the existing cut-offs map to defensible
    annual loss-event tiers at the NEUTRAL threat environment (TEF=1.0):
        200 -> 1.66% | 400 -> 5.77% | 600 -> 11.96%
    FS (TEF=1.45, the core SA-FSP market): 2.40% | 8.36% | 17.34%.
    The inverse confirms: round neutral boundaries {2%,6%,12%} -> scores
    {222,409,601} ~= 200/400/600. The even split coincidentally lands on the
    p_breach tiers once the curve is convex+correctly-polarised.
  * Empirical anchors: BitSight strong <1% / weak ~3%; Cyentia IRIS SMB <2%,
    F1000 ~25%; SecurityScorecard A->F breach-likelihood ladder (steeply convex).
  * Distribution check (de-inflation worry "a High org now lands in Medium"):
    risk_score ~= avg_category_risk * 13.2 (WEIGHTS sum ~1.32 over 31 checkers).
    Clean orgs (phishield 164, example.com 145) = Low (correct). A genuinely bad
    org (avg category-risk >=45/100) still reaches >=600 = Critical, so the upper
    bands stay reachable. De-inflation removed FALSE-POSITIVE inflation that was
    concentrated on well-postured orgs (ghost checkers, polarity inversions,
    SSL/DNSBL/exposed-admin FPs); a bad org's REAL findings are untouched, so its
    score is preserved. Lowering the cut-offs to "recapture" de-inflated orgs
    would re-introduce the removed inflation -> WRONG. Hence retain.

One anchored edit; fail-safe (assert count==1); CRLF-preserving. Comment-only, so
every numeric output is byte-identical (clean documentation diff). NOT shipped
(FIN-9 calibration prep, 2026-06-03).
"""
import os

SA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

OLD = (
    "        risk_level = (\n"
    "            \"Critical\" if risk_score >= 600 else\n"
    "            \"High\"     if risk_score >= 400 else\n"
    "            \"Medium\"   if risk_score >= 200 else\n"
    "            \"Low\"\n"
    "        )\n"
)

NEW = (
    "        # Risk-level bands - anchored to annual loss-event probability tiers,\n"
    "        # NOT a blind even split (FIN-9 band re-fit, 2026-06-03). Each cut-off is\n"
    "        # the score at which the calibrated convex vulnerability curve\n"
    "        # (vulnerability = (score/1000)**1.8) crosses a defensible breach-prob\n"
    "        # boundary. p_breach = vulnerability * TEF * 0.3; the bands are stated at\n"
    "        # the NEUTRAL threat environment (TEF=1.0) so the posture label is\n"
    "        # industry-independent (per-industry TEF re-scales the ACTUAL p_breach\n"
    "        # later, in FinancialImpactCalculator). FS (TEF=1.45, core SA-FSP market)\n"
    "        # shown in brackets for reference.\n"
    "        #\n"
    "        #   Band      score      p_breach@TEF1.0   (@TEF1.45 FS)   tier anchor\n"
    "        #   Low       <200          <1.7%            (<2.4%)       BitSight strong <1% / Cyentia SMB <2%\n"
    "        #   Medium    200-399        1.7-5.8%        (2.4-8.4%)    elevated\n"
    "        #   High      400-599        5.8-12%         (8.4-17.3%)   BitSight weak ~3%+ / SecurityScorecard mid grades\n"
    "        #   Critical  >=600          >=12%           (>=17.3%)     Cyentia F1000 ~25%; weak-posture tail\n"
    "        #\n"
    "        # RE-FIT = RETAIN. Run through the calibrated curve the prior 200/400/600\n"
    "        # cut-offs already match the p_breach tiers (inverse of {2%,6%,12%} neutral\n"
    "        # = {222,409,601}); they were just undocumented. Validated on the de-inflated\n"
    "        # distribution: phishield 164 / example.com 145 = Low; a genuinely bad org\n"
    "        # (avg category-risk >=45/100 over the 31 weighted checkers, score ~= avg*13.2)\n"
    "        # still reaches >=600 = Critical, so the upper bands stay reachable. De-inflation\n"
    "        # removed false-positive inflation concentrated on clean orgs (ghost checkers,\n"
    "        # polarity inversions, SSL/DNSBL/exposed-admin FPs); lowering the cut-offs to\n"
    "        # recapture those orgs would re-introduce the removed inflation. COLLEAGUE note:\n"
    "        # tiers track the same base-rate choice as the vuln curve + the 0.3 (doc 01);\n"
    "        # re-confirm if the base rate moves. docs/calibration_prep/00_CALIBRATION_SUMMARY.md.\n"
    "        risk_level = (\n"
    "            \"Critical\" if risk_score >= 600 else\n"
    "            \"High\"     if risk_score >= 400 else\n"
    "            \"Medium\"   if risk_score >= 200 else\n"
    "            \"Low\"\n"
    "        )\n"
)

n = s.count(OLD)
assert n == 1, ("risk_level band anchor count", n)
s = s.replace(OLD, NEW, 1)

# Sanity: thresholds RETAINED (comment-only re-fit); anchoring doc present.
assert 'risk_score >= 600 else' in s, "Critical threshold changed/missing"
assert 'risk_score >= 400 else' in s, "High threshold changed/missing"
assert 'risk_score >= 200 else' in s, "Medium threshold changed/missing"
assert "anchored to annual loss-event probability tiers" in s, "band anchor comment missing"
assert "RE-FIT = RETAIN" in s, "re-fit rationale missing"
assert "\r" not in s, "unexpected CR"
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print("OK scoring_analytics.py: risk-level bands anchored + documented (retain 200/400/600; 1 edit)")
