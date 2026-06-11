# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #17b, card pass): wire the reporting-only probability cards +
cover-sizing ladder + remediation re-portrayal into the PDF renderer
(pdf_report.py). REPORTING-ONLY presentation of already-scored signals.

Adds two flowable block functions (risk_probability_block, cover_ladder_block)
mirroring loss_exposure_scenarios_block, re-portrays cat_risk_mitigations to LEAD
with the breach-grade movement + %-exposure reduction + posture-independent
catastrophe cover (absolute Rand secondary), and hooks the two blocks into the
broker-summary and full-report tiers. Raw Table cells are ASCII-only (built-in
Helvetica glyph safety); XML entities used only inside Paragraph text.

CRLF-preserving mutator (read utf-8 -> assert no CR -> count==1 -> replace ->
write CRLF). AST-validated. NOT shipped."""
import ast
import os

PR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "pdf_report.py")
s = open(PR, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

# ---------------------------------------------------------------------------
# 1. Two new flowable block functions, inserted before records_assumption_disclosure.
# ---------------------------------------------------------------------------
NEW_FUNCS = (
    "def risk_probability_block(d, S):\n"
    "    \"\"\"Cyber-Risk Probability - reporting-only FAIR frequency view (item #17).\n"
    "\n"
    "    Surfaces fin[\"risk_probability\"]: THREE distinct, separately-graded annual-\n"
    "    likelihood concepts - (1) total cyber-incident probability (nested ABOVE the\n"
    "    breach figure), (2) data-breach probability, (3) an INDICATIVE availability\n"
    "    resilience indicator. New presentation of already-scored signals (no scoring\n"
    "    weight). Mirrors loss_exposure_scenarios_block styling.\"\"\"\n"
    "    fin = d.get(\"financial_impact\", {})\n"
    "    if not fin:\n"
    "        return []\n"
    "    rp = fin.get(\"risk_probability\", {})\n"
    "    if not rp:\n"
    "        return []\n"
    "    db = rp.get(\"data_breach\", {})\n"
    "    ci = rp.get(\"cyber_incident\", {})\n"
    "    av = rp.get(\"availability_resilience\", {})\n"
    "\n"
    "    col_widths = [98 * mm, 30 * mm, INNER_W - 98 * mm - 30 * mm]\n"
    "    table_data = [\n"
    "        [\"Annual cyber-risk probability\", \"Likelihood\", \"Grade\"],\n"
    "        [\"Total cyber-incident (breach + ransomware)\",\n"
    "         f\"{ci.get('probability_pct', 0):.1f}%\", ci.get(\"grade\", \"\")],\n"
    "        [\"   of which: data breach\",\n"
    "         f\"{db.get('probability_pct', 0):.2f}%\", db.get(\"grade\", \"\")],\n"
    "        [\"Availability resilience (indicative)\",\n"
    "         f\"{av.get('indicator_pct', 0):.0f}%\", \"Indicative\"],\n"
    "    ]\n"
    "    table = Table(table_data, colWidths=col_widths)\n"
    "    table.setStyle(TableStyle([\n"
    "        (\"FONTNAME\",      (0, 0), (-1, 0),  \"Helvetica-Bold\"),\n"
    "        (\"FONTSIZE\",      (0, 0), (-1, -1), 9),\n"
    "        (\"BACKGROUND\",    (0, 0), (-1, 0),  C_GREY_1),\n"
    "        (\"TEXTCOLOR\",     (0, 0), (-1, 0),  C_NAVY),\n"
    "        (\"LINEBELOW\",     (0, 0), (-1, 0),  1.0, C_NAVY),\n"
    "        (\"VALIGN\",        (0, 0), (-1, -1), \"MIDDLE\"),\n"
    "        (\"ALIGN\",         (1, 0), (-1, -1), \"RIGHT\"),\n"
    "        (\"ALIGN\",         (0, 0), (0, -1),  \"LEFT\"),\n"
    "        (\"ALIGN\",         (2, 0), (2, -1),  \"CENTER\"),\n"
    "        (\"LEFTPADDING\",   (0, 0), (-1, -1), 8),\n"
    "        (\"RIGHTPADDING\",  (0, 0), (-1, -1), 8),\n"
    "        (\"TOPPADDING\",    (0, 0), (-1, -1), 5),\n"
    "        (\"BOTTOMPADDING\", (0, 0), (-1, -1), 5),\n"
    "        (\"ROWBACKGROUNDS\",(0, 1), (-1, -1), [colors.white, C_GREY_1]),\n"
    "        (\"BOX\",           (0, 0), (-1, -1), 0.25, C_GREY_2),\n"
    "        (\"INNERGRID\",     (0, 1), (-1, -1), 0.25, C_GREY_2),\n"
    "        (\"FONTNAME\",      (0, 1), (-1, 1),  \"Helvetica-Bold\"),\n"
    "    ]))\n"
    "\n"
    "    blocks = [\n"
    "        Spacer(1, 3 * mm),\n"
    "        Paragraph(\"<b>Cyber-Risk Probability</b>\", S[\"cat_title\"]),\n"
    "        Spacer(1, 2 * mm),\n"
    "        Paragraph(\n"
    "            \"Modelled annual likelihood of a cyber loss event, shown as three \"\n"
    "            \"distinct and separately-graded measures. This is a frequency view of \"\n"
    "            \"externally-observable signals already scored elsewhere in this report \"\n"
    "            \"and carries no additional scoring weight.\",\n"
    "            S[\"body\"]),\n"
    "        Spacer(1, 2 * mm),\n"
    "        table,\n"
    "        Spacer(1, 2 * mm),\n"
    "        Paragraph(\n"
    "            \"<b>Total cyber-incident probability</b> - the likelihood of ANY \"\n"
    "            \"modelled cyber incident in the year, combining the data-breach and \"\n"
    "            \"ransomware channels. It nests ABOVE the data-breach figure and is \"\n"
    "            \"always greater than or equal to it. Provisional bands: &lt;5% Low, \"\n"
    "            \"5-15% Typical, 15-30% Elevated, &gt;30% High.\",\n"
    "            S[\"body_muted\"]),\n"
    "        Paragraph(\n"
    "            \"<b>Data-breach probability</b> - the likelihood specifically of a \"\n"
    "            \"data breach (confidentiality loss / record exfiltration). Graded on \"\n"
    "            \"firm public breach-rate bands (Cyentia IRIS SMB &lt;2%/yr, BitSight, \"\n"
    "            \"SecurityScorecard): &lt;1% Strong, 1-2% Good, 2-3% Typical, 3-6% \"\n"
    "            \"Elevated, 6-12% High, &gt;12% Critical.\",\n"
    "            S[\"body_muted\"]),\n"
    "        Paragraph(\n"
    "            \"<b>Availability resilience indicator</b> - an INDICATIVE signal of \"\n"
    "            \"outage / availability risk (DDoS and system / infrastructure-failure \"\n"
    "            \"causes). It describes the risk only; it is not a calibrated \"\n"
    "            \"probability and not a statement of policy coverage.\",\n"
    "            S[\"body_muted\"]),\n"
    "        Spacer(1, 3 * mm),\n"
    "    ]\n"
    "    return blocks\n"
    "\n"
    "\n"
    "def cover_ladder_block(d, S):\n"
    "    \"\"\"Cover-Sizing Ladder - severity-PML tiers (P50/P95/P99.6), posture-\n"
    "    independent (item #17). Surfaces fin[\"cover_ladder\"]: the SEVERITY (LM) axis\n"
    "    of the FAIR split, the simplified client-facing companion to the Loss\n"
    "    Exposure Scenarios table. New presentation of already-scored signals.\"\"\"\n"
    "    fin = d.get(\"financial_impact\", {})\n"
    "    if not fin:\n"
    "        return []\n"
    "    cl = fin.get(\"cover_ladder\", {})\n"
    "    if not cl:\n"
    "        return []\n"
    "    cur = \"R \" if fin.get(\"currency\") == \"ZAR\" else \"$\"\n"
    "    ts = cl.get(\"typical_severe\", {})\n"
    "    bad = cl.get(\"bad\", {})\n"
    "    cat = cl.get(\"catastrophic\", {})\n"
    "\n"
    "    col_widths = [65 * mm, 55 * mm, INNER_W - 65 * mm - 55 * mm]\n"
    "    table_data = [\n"
    "        [\"Cover tier\", \"Modelled severity\", \"Reference\"],\n"
    "        [\"Typical severe breach\", f\"{cur}{ts.get('loss_zar', 0):,.0f}\", \"P50 severity\"],\n"
    "        [\"Bad breach\",            f\"{cur}{bad.get('loss_zar', 0):,.0f}\", \"P95 severity\"],\n"
    "        [\"Catastrophic breach\",   f\"{cur}{cat.get('loss_zar', 0):,.0f}\", \"1-in-250 / P99.6\"],\n"
    "    ]\n"
    "    table = Table(table_data, colWidths=col_widths)\n"
    "    table.setStyle(TableStyle([\n"
    "        (\"FONTNAME\",      (0, 0), (-1, 0),  \"Helvetica-Bold\"),\n"
    "        (\"FONTSIZE\",      (0, 0), (-1, -1), 9),\n"
    "        (\"BACKGROUND\",    (0, 0), (-1, 0),  C_GREY_1),\n"
    "        (\"TEXTCOLOR\",     (0, 0), (-1, 0),  C_NAVY),\n"
    "        (\"LINEBELOW\",     (0, 0), (-1, 0),  1.0, C_NAVY),\n"
    "        (\"VALIGN\",        (0, 0), (-1, -1), \"MIDDLE\"),\n"
    "        (\"ALIGN\",         (1, 0), (-1, -1), \"RIGHT\"),\n"
    "        (\"ALIGN\",         (0, 0), (0, -1),  \"LEFT\"),\n"
    "        (\"LEFTPADDING\",   (0, 0), (-1, -1), 8),\n"
    "        (\"RIGHTPADDING\",  (0, 0), (-1, -1), 8),\n"
    "        (\"TOPPADDING\",    (0, 0), (-1, -1), 5),\n"
    "        (\"BOTTOMPADDING\", (0, 0), (-1, -1), 5),\n"
    "        (\"ROWBACKGROUNDS\",(0, 1), (-1, -1), [colors.white, C_GREY_1]),\n"
    "        (\"BOX\",           (0, 0), (-1, -1), 0.25, C_GREY_2),\n"
    "        (\"INNERGRID\",     (0, 1), (-1, -1), 0.25, C_GREY_2),\n"
    "        (\"FONTNAME\",      (0, 3), (-1, 3),  \"Helvetica-Bold\"),\n"
    "    ]))\n"
    "\n"
    "    blocks = [\n"
    "        Spacer(1, 3 * mm),\n"
    "        Paragraph(\"<b>Cover-Sizing Ladder</b>\", S[\"cat_title\"]),\n"
    "        Spacer(1, 2 * mm),\n"
    "        Paragraph(\n"
    "            \"The modelled severity of a single severe cyber event across three \"\n"
    "            \"cover tiers - the simplified client-facing companion to the Loss \"\n"
    "            \"Exposure Scenarios above. These figures are the magnitude of a \"\n"
    "            \"realised event and are independent of how likely it is, so they do \"\n"
    "            \"not move with security posture. Cover sizing remains the insured's \"\n"
    "            \"decision in consultation with the broker; Phishield does not \"\n"
    "            \"recommend a specific cover amount.\",\n"
    "            S[\"body\"]),\n"
    "        Spacer(1, 2 * mm),\n"
    "        table,\n"
    "        Spacer(1, 3 * mm),\n"
    "    ]\n"
    "    return blocks\n"
    "\n"
    "\n"
)
OLD_ANCHOR = "def records_assumption_disclosure(d, S):\n"
assert s.count(OLD_ANCHOR) == 1, ("records_assumption anchor", s.count(OLD_ANCHOR))
s = s.replace(OLD_ANCHOR, NEW_FUNCS + OLD_ANCHOR, 1)

# ---------------------------------------------------------------------------
# 2. Re-portray cat_risk_mitigations: LEAD with grade movement + %-reduction +
#    posture-independent catastrophe cover. Absolute Rand savings stay (secondary).
# ---------------------------------------------------------------------------
OLD_REM = (
    "    rows = [\n"
    "        (\"Current Annual Loss\",    f\"{cur}&nbsp;{current:,.0f}\"),\n"
    "        (\"Mitigated Annual Loss\",  f\"{cur}&nbsp;{mitigated:,.0f}\"),\n"
    "        (\"Total Potential Savings\", f\"{cur}&nbsp;{total_savings:,.0f} ({reduction_pct}%)\"),\n"
    "        (\"\", \"\"),\n"
    "    ]\n"
)
NEW_REM = (
    "    # Re-portrayed (item #17): LEAD with the breach-probability/grade movement\n"
    "    # + %-reduction in modelled exposure + the posture-INDEPENDENT catastrophe\n"
    "    # cover (1-in-250). Absolute Rand savings are demoted to secondary detail.\n"
    "    rs = mit.get(\"remediation_summary\", {})\n"
    "    rows = []\n"
    "    if rs:\n"
    "        rows.extend([\n"
    "            (\"Data-breach likelihood\",\n"
    "             f\"{rs.get('breach_probability_before_pct', 0)}% \"\n"
    "             f\"({rs.get('breach_grade_before', '')})&nbsp;&rarr;&nbsp;\"\n"
    "             f\"{rs.get('breach_probability_after_pct', 0)}% \"\n"
    "             f\"({rs.get('breach_grade_after', '')})\"),\n"
    "            (\"Reduction in modelled exposure\", f\"{rs.get('exposure_reduction_pct', 0)}%\"),\n"
    "            (\"Catastrophe cover (1-in-250, unchanged)\",\n"
    "             f\"{cur}&nbsp;{rs.get('catastrophe_cover_zar', 0):,.0f}\"),\n"
    "            (\"\", \"\"),\n"
    "        ])\n"
    "    rows.extend([\n"
    "        (\"Current Annual Loss\",    f\"{cur}&nbsp;{current:,.0f}\"),\n"
    "        (\"Mitigated Annual Loss\",  f\"{cur}&nbsp;{mitigated:,.0f}\"),\n"
    "        (\"Total Potential Savings\", f\"{cur}&nbsp;{total_savings:,.0f} ({reduction_pct}%)\"),\n"
    "        (\"\", \"\"),\n"
    "    ])\n"
)
assert s.count(OLD_REM) == 1, ("cat_risk_mitigations anchor", s.count(OLD_REM))
s = s.replace(OLD_REM, NEW_REM, 1)

# ---------------------------------------------------------------------------
# 3. Hook the two new blocks into the broker-SUMMARY tier (ins_data).
# ---------------------------------------------------------------------------
OLD_SUM = "            story += loss_exposure_scenarios_block(ins_data, S)\n"
NEW_SUM = (
    "            # Cyber-risk probability cards (FAIR frequency view) + cover-sizing\n"
    "            # ladder, surfaced alongside the loss exposure scenarios. Item #17.\n"
    "            story += risk_probability_block(ins_data, S)\n"
    "            story += loss_exposure_scenarios_block(ins_data, S)\n"
    "            story += cover_ladder_block(ins_data, S)\n"
)
assert s.count(OLD_SUM) == 1, ("summary hook anchor", s.count(OLD_SUM))
s = s.replace(OLD_SUM, NEW_SUM, 1)

# ---------------------------------------------------------------------------
# 4. Hook the two new blocks into the FULL-REPORT tier (results.get("insurance")).
# ---------------------------------------------------------------------------
OLD_FULL = "            story += loss_exposure_scenarios_block(results.get(\"insurance\", {}), S)\n"
NEW_FULL = (
    "            story += risk_probability_block(results.get(\"insurance\", {}), S)\n"
    "            story += loss_exposure_scenarios_block(results.get(\"insurance\", {}), S)\n"
    "            story += cover_ladder_block(results.get(\"insurance\", {}), S)\n"
)
assert s.count(OLD_FULL) == 1, ("full-report hook anchor", s.count(OLD_FULL))
s = s.replace(OLD_FULL, NEW_FULL, 1)

# ---------------------------------------------------------------------------
# Validate + write (CRLF-preserving).
# ---------------------------------------------------------------------------
assert "\r" not in s
assert "def risk_probability_block(d, S):" in s
assert "def cover_ladder_block(d, S):" in s
assert "story += cover_ladder_block(ins_data, S)" in s
assert "story += cover_ladder_block(results.get(\"insurance\", {}), S)" in s
assert "remediation_summary" in s
ast.parse(s)
with open(PR, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
chk = open(PR, encoding="utf-8").read()
ast.parse(chk)
print("OK pdf_report.py: item #17b renderers wired (2 blocks + remediation re-portrayal + 2 tier hooks; AST valid).")
