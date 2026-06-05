# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #17, user-approved card pass): wire the reporting-only
probability cards + remediation re-portrayal into scoring_analytics.py.

REPORTING-ONLY — new VIEWS of already-scored signals (one-of-four anchoring
channel = reporting-only, no double-count). NO scoring change: no WEIGHTS / RSI /
severity / tail / p_breach edits. Adds:

  1. module-level grade helpers + segregated bands (breach / cyber-incident);
  2. p_ransomware (= rsi_score x 0.30, the 3 ransomware legs summed) and the
     total cyber-incident probability (independent union) computed before the
     output dict;
  3. a `risk_probability` result-dict block carrying the THREE distinct
     probability concepts (data-breach / total cyber-incident / availability
     resilience indicator), each with its own definition + segregated band;
  4. a `remediation_summary` block in _build_mitigations (breach-prob/grade
     movement + %-exposure reduction + posture-independent catastrophe cover).

CRLF-preserving mutator pattern (read utf-8 -> assert no CR -> assert count==1
per anchor -> replace -> write CRLF). NOT shipped."""
import ast
import os

SA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

# ---------------------------------------------------------------------------
# 1. Module-level grade helpers + segregated bands (after the import line).
# ---------------------------------------------------------------------------
OLD_IMP = "from scanner_utils import *\n"
NEW_IMP = (
    "from scanner_utils import *\n"
    "\n"
    "\n"
    "# --- Cyber-risk probability grading bands (reporting-only FAIR view; item #17) ---\n"
    "# Segregated public-anchor bands, one per probability metric. Firm breach-rate\n"
    "# anchors: Cyentia IRIS (SMB material breach <2%/yr), BitSight, SecurityScorecard.\n"
    "# The breach band is deliberately NOT reused on the multi-channel total\n"
    "# cyber-incident metric (reusing it mislabels a typical multi-channel rate as\n"
    "# 'High'). Bands are (upper_exclusive_pct, label); the last bucket is open-ended.\n"
    "_BREACH_PROB_BANDS = (\n"
    "    (1.0, \"Strong\"), (2.0, \"Good\"), (3.0, \"Typical\"),\n"
    "    (6.0, \"Elevated\"), (12.0, \"High\"), (float(\"inf\"), \"Critical\"),\n"
    ")\n"
    "# Provisional total cyber-incident bands (multi-channel: breach + ransomware).\n"
    "_CYBER_INCIDENT_BANDS = (\n"
    "    (5.0, \"Low\"), (15.0, \"Typical\"), (30.0, \"Elevated\"), (float(\"inf\"), \"High\"),\n"
    ")\n"
    "\n"
    "\n"
    "def _grade_probability(pct, bands):\n"
    "    \"\"\"Map a percentage probability to its segregated band label (reporting-only).\"\"\"\n"
    "    for upper, label in bands:\n"
    "        if pct < upper:\n"
    "            return label\n"
    "    return bands[-1][1]\n"
)
assert s.count(OLD_IMP) == 1, ("import anchor", s.count(OLD_IMP))
s = s.replace(OLD_IMP, NEW_IMP, 1)

# ---------------------------------------------------------------------------
# 2. Probability computation just before the output dict literal.
# ---------------------------------------------------------------------------
OLD_PCY = "            fin_score = 90\n\n        output = {\n"
NEW_PCY = (
    "            fin_score = 90\n"
    "\n"
    "        # --- Probability cards (reporting-only FAIR frequency view; item #17) ---\n"
    "        # Ransomware annual frequency = the three ransomware legs summed =\n"
    "        # rsi_score x RW_LEF (RW_LEF 0.30, already in the model). Total cyber-\n"
    "        # incident combines the breach + ransomware channels as an independent\n"
    "        # union. p_interruption stays the SEPARATE indicative availability\n"
    "        # indicator (NOT FAIR-treated this pass). No scoring contribution.\n"
    "        p_ransomware = min(1.0, max(0.0, rsi_score * 0.30))\n"
    "        p_cyber_incident = 1.0 - (1.0 - p_breach) * (1.0 - p_ransomware)\n"
    "        _breach_pct = p_breach * 100.0\n"
    "        _cyber_pct = p_cyber_incident * 100.0\n"
    "        _breach_grade = _grade_probability(_breach_pct, _BREACH_PROB_BANDS)\n"
    "        _cyber_grade = _grade_probability(_cyber_pct, _CYBER_INCIDENT_BANDS)\n"
    "\n"
    "        output = {\n"
)
assert s.count(OLD_PCY) == 1, ("p_cyber anchor", s.count(OLD_PCY))
s = s.replace(OLD_PCY, NEW_PCY, 1)

# ---------------------------------------------------------------------------
# 3. risk_probability result-dict block, inserted before regulatory_exposure.
# ---------------------------------------------------------------------------
OLD_RP = (
    "            \"regulatory_exposure\": {\n"
    "                \"flags\": reg_flags,\n"
)
NEW_RP = (
    "            # --- Cyber-risk probability cards (reporting-only; item #17) ---\n"
    "            # New presentation of already-scored signals; NO scoring weight\n"
    "            # (one-of-four anchoring channel = reporting-only, no double-count).\n"
    "            # THREE distinct annual-likelihood concepts, each with its own\n"
    "            # definition and segregated grading band - never conflate them.\n"
    "            \"risk_probability\": {\n"
    "                \"_note\": (\n"
    "                    \"Reporting-only FAIR loss-event-frequency view. Three \"\n"
    "                    \"distinct annual-likelihood concepts with segregated bands. \"\n"
    "                    \"No scoring weight - new view of already-scored signals.\"\n"
    "                ),\n"
    "                \"data_breach\": {\n"
    "                    \"label\": \"Data-breach probability (annual)\",\n"
    "                    \"definition\": (\n"
    "                        \"Annual likelihood of a data breach - confidentiality \"\n"
    "                        \"loss / exfiltration of sensitive records. FAIR loss-\"\n"
    "                        \"event frequency p_breach = vulnerability x TEF x 0.30.\"\n"
    "                    ),\n"
    "                    \"probability\": round(p_breach, 4),\n"
    "                    \"probability_pct\": round(_breach_pct, 2),\n"
    "                    \"grade\": _breach_grade,\n"
    "                    \"bands\": [\n"
    "                        {\"upper_pct\": 1, \"grade\": \"Strong\"},\n"
    "                        {\"upper_pct\": 2, \"grade\": \"Good\"},\n"
    "                        {\"upper_pct\": 3, \"grade\": \"Typical\"},\n"
    "                        {\"upper_pct\": 6, \"grade\": \"Elevated\"},\n"
    "                        {\"upper_pct\": 12, \"grade\": \"High\"},\n"
    "                        {\"upper_pct\": None, \"grade\": \"Critical\"},\n"
    "                    ],\n"
    "                    \"band_anchor\": (\n"
    "                        \"Firm public breach-rate anchors: Cyentia IRIS (SMB \"\n"
    "                        \"material breach <2%/yr), BitSight, SecurityScorecard.\"\n"
    "                    ),\n"
    "                },\n"
    "                \"cyber_incident\": {\n"
    "                    \"label\": \"Total cyber-incident probability (annual)\",\n"
    "                    \"definition\": (\n"
    "                        \"Annual likelihood of ANY modelled cyber incident - \"\n"
    "                        \"nested ABOVE the data-breach figure and always >= it. \"\n"
    "                        \"Independent union of the breach and ransomware channels: \"\n"
    "                        \"1 - (1 - p_breach) * (1 - rsi_score x 0.30).\"\n"
    "                    ),\n"
    "                    \"probability\": round(p_cyber_incident, 4),\n"
    "                    \"probability_pct\": round(_cyber_pct, 2),\n"
    "                    \"grade\": _cyber_grade,\n"
    "                    \"channels\": {\n"
    "                        \"data_breach\": round(p_breach, 4),\n"
    "                        \"ransomware\": round(p_ransomware, 4),\n"
    "                    },\n"
    "                    \"bands\": [\n"
    "                        {\"upper_pct\": 5, \"grade\": \"Low\"},\n"
    "                        {\"upper_pct\": 15, \"grade\": \"Typical\"},\n"
    "                        {\"upper_pct\": 30, \"grade\": \"Elevated\"},\n"
    "                        {\"upper_pct\": None, \"grade\": \"High\"},\n"
    "                    ],\n"
    "                    \"band_anchor\": (\n"
    "                        \"PROVISIONAL multi-channel bands (not yet firm-anchored). \"\n"
    "                        \"The breach band is deliberately NOT reused - that \"\n"
    "                        \"mislabels a typical multi-channel rate as 'High'.\"\n"
    "                    ),\n"
    "                },\n"
    "                \"availability_resilience\": {\n"
    "                    \"label\": \"Availability resilience indicator (INDICATIVE)\",\n"
    "                    \"definition\": (\n"
    "                        \"Indicative resilience signal for outage / availability \"\n"
    "                        \"risk spanning DDoS and system / infrastructure-failure \"\n"
    "                        \"causes. Describes the RISK only - it is NOT a coverage \"\n"
    "                        \"statement (outage / system-failure cover varies by \"\n"
    "                        \"policy and over time). Heuristic; NOT a calibrated \"\n"
    "                        \"probability.\"\n"
    "                    ),\n"
    "                    \"indicator\": round(p_interruption, 4),\n"
    "                    \"indicator_pct\": round(p_interruption * 100, 1),\n"
    "                    \"calibrated\": False,\n"
    "                    \"basis\": (\n"
    "                        \"Heuristic over WAF / CDN / single-ASN / DNSBL \"\n"
    "                        \"availability signals. Indicative-only pending FAIR \"\n"
    "                        \"re-anchoring (deferred).\"\n"
    "                    ),\n"
    "                },\n"
    "            },\n"
    "            \"regulatory_exposure\": {\n"
    "                \"flags\": reg_flags,\n"
)
assert s.count(OLD_RP) == 1, ("risk_probability anchor", s.count(OLD_RP))
s = s.replace(OLD_RP, NEW_RP, 1)

# ---------------------------------------------------------------------------
# 4. remediation_summary block in _build_mitigations (before the final return).
# ---------------------------------------------------------------------------
OLD_REM = (
    "        return {\n"
    "            \"current_annual_loss\": current_loss,\n"
    "            \"mitigated_annual_loss\": current_loss - total_savings,\n"
)
NEW_REM = (
    "        # --- Remediation re-portrayal (reporting-only; item #17) ---\n"
    "        # Lead with breach-probability/grade movement + %-exposure reduction +\n"
    "        # the (severity-driven, posture-INDEPENDENT) catastrophe cover figure.\n"
    "        # Breach-family savings reduce breach-family loss proportionally, and\n"
    "        # breach-family loss scales linearly with p_breach, so the fractional\n"
    "        # breach-loss reduction maps directly to a p_breach (frequency) movement.\n"
    "        _breach_savings = sum(f[\"estimated_annual_savings_zar\"] for f in findings\n"
    "                              if f.get(\"scenario_impact\") == \"data_breach\")\n"
    "        _breach_red_frac = (min(0.85, _breach_savings / breach_family_loss)\n"
    "                            if breach_family_loss > 0 else 0.0)\n"
    "        _breach_after = p_breach * (1.0 - _breach_red_frac)\n"
    "        _cover_ladder = fin_output.get(\"cover_ladder\", {}) or {}\n"
    "        _cat_cover = (_cover_ladder.get(\"catastrophic\", {}) or {}).get(\"loss_zar\", 0)\n"
    "        remediation_summary = {\n"
    "            \"breach_probability_before\": round(p_breach, 4),\n"
    "            \"breach_probability_after\": round(_breach_after, 4),\n"
    "            \"breach_probability_before_pct\": round(p_breach * 100, 2),\n"
    "            \"breach_probability_after_pct\": round(_breach_after * 100, 2),\n"
    "            \"breach_grade_before\": _grade_probability(p_breach * 100, _BREACH_PROB_BANDS),\n"
    "            \"breach_grade_after\": _grade_probability(_breach_after * 100, _BREACH_PROB_BANDS),\n"
    "            \"exposure_reduction_pct\":\n"
    "                round(100.0 * total_savings / current_loss, 1) if current_loss > 0 else 0.0,\n"
    "            \"catastrophe_cover_zar\": _cat_cover,\n"
    "            \"catastrophe_note\": (\n"
    "                \"The 1-in-250 catastrophe cover requirement is severity-driven \"\n"
    "                \"and posture-independent - remediation lowers the LIKELIHOOD of \"\n"
    "                \"loss, not the worst-case severity, so the cover figure is \"\n"
    "                \"unchanged.\"\n"
    "            ),\n"
    "        }\n"
    "        return {\n"
    "            \"remediation_summary\": remediation_summary,\n"
    "            \"current_annual_loss\": current_loss,\n"
    "            \"mitigated_annual_loss\": current_loss - total_savings,\n"
)
assert s.count(OLD_REM) == 1, ("remediation_summary anchor", s.count(OLD_REM))
s = s.replace(OLD_REM, NEW_REM, 1)

# ---------------------------------------------------------------------------
# Validate + write (CRLF-preserving).
# ---------------------------------------------------------------------------
assert "\r" not in s, "no CR should be present in the normalised buffer"
assert "\"risk_probability\": {" in s
assert "p_cyber_incident = 1.0 - (1.0 - p_breach)" in s
assert "\"remediation_summary\": remediation_summary," in s
assert "def _grade_probability(pct, bands):" in s
ast.parse(s)  # AST validation BEFORE writing
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))

# Re-read + AST-validate the written CRLF file.
chk = open(SA, encoding="utf-8").read()
ast.parse(chk)
print("OK scoring_analytics.py: item #17 probability cards + remediation re-portrayal wired (AST valid).")
