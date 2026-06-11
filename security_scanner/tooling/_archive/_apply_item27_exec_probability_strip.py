# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #27): add the FAIR FREQUENCY view to the exec-deck financial slide
(_assessment_slide_financial_impact) - a compact "ANNUAL LIKELIHOOD" strip of three
tiles (total cyber-incident / data breach / availability-indicative) under the cost
body, so the slide carries both axes (how likely + how much). Reads the existing
fin["risk_probability"] (item #17) - reporting-only, no scoring change. Kaizen
styling (serif/navy, grade-coloured %). CRLF-safe + AST-validated. NOT shipped."""
import ast
import os

PR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "pdf_report.py")
s = open(PR, encoding="utf-8").read()
assert "\r" not in s

OLD = (
    "    caveat_st = ParagraphStyle(\"cv\", fontSize=9, fontName=ASX_SANS,\n"
    "                                 textColor=ASX_GREY_MUTED, leading=12,\n"
    "                                 backColor=ASX_TILE_BG, borderPadding=8)\n"
    "    return [\n"
    "        Paragraph(\"FINANCIAL IMPACT\", _style_section_label()),\n"
    "        Paragraph(\"What a Breach Could Cost\", _style_slide_title(30)),\n"
    "        Paragraph(\"Modelled annual cyber loss across a range of severity scenarios, from the most likely outcome to a rare catastrophe.\",\n"
    "                   _style_intro()),\n"
    "        body,\n"
    "        Spacer(1, 10),\n"
    "        Paragraph(\"Figures are statistical model output. Selecting the appropriate cover limit is a decision for the insured in consultation with the broker.\",\n"
    "                   caveat_st),\n"
    "    ]\n"
)
NEW = (
    "    caveat_st = ParagraphStyle(\"cv\", fontSize=9, fontName=ASX_SANS,\n"
    "                                 textColor=ASX_GREY_MUTED, leading=12,\n"
    "                                 backColor=ASX_TILE_BG, borderPadding=8)\n"
    "\n"
    "    # --- FAIR frequency view: compact ANNUAL LIKELIHOOD strip ---\n"
    "    # New view of already-scored signals (fin['risk_probability'], item #17) -\n"
    "    # reporting-only. Three tiles: total cyber-incident (nested), data breach,\n"
    "    # availability (indicative). Grade-coloured % for at-a-glance reading.\n"
    "    rp = fin.get(\"risk_probability\", {}) or {}\n"
    "    prob_strip = []\n"
    "    if rp:\n"
    "        _db = rp.get(\"data_breach\", {}) or {}\n"
    "        _ci = rp.get(\"cyber_incident\", {}) or {}\n"
    "        _av = rp.get(\"availability_resilience\", {}) or {}\n"
    "        _ghex = {\"Strong\": \"#166534\", \"Good\": \"#166534\", \"Low\": \"#166534\",\n"
    "                 \"Typical\": \"#92400e\", \"Elevated\": \"#b45309\",\n"
    "                 \"High\": \"#dc2626\", \"Critical\": \"#991b1b\"}\n"
    "        def _ptile(pct, lab, sub, hexc):\n"
    "            return [\n"
    "                Paragraph(pct, ParagraphStyle(\"ptv\", fontSize=23, fontName=ASX_SANS_BOLD,\n"
    "                          textColor=colors.HexColor(hexc), leading=26)),\n"
    "                Spacer(1, 2),\n"
    "                Paragraph(\"<b>\" + lab + \"</b>\", ParagraphStyle(\"ptl\", fontSize=9.5,\n"
    "                          fontName=ASX_SANS_BOLD, textColor=ASX_NAVY, leading=12)),\n"
    "                Paragraph(sub, ParagraphStyle(\"pts\", fontSize=8.5, fontName=ASX_SANS,\n"
    "                          textColor=ASX_GREY_BODY, leading=11)),\n"
    "            ]\n"
    "        _tiles = [\n"
    "            _ptile(f\"{_ci.get('probability_pct', 0):.1f}%\", \"Total cyber-incident\",\n"
    "                   (_ci.get('grade', '') + \" - breach + ransomware\"),\n"
    "                   _ghex.get(_ci.get('grade', ''), \"#0f2744\")),\n"
    "            _ptile(f\"{_db.get('probability_pct', 0):.2f}%\", \"Data breach\",\n"
    "                   _db.get('grade', ''), _ghex.get(_db.get('grade', ''), \"#0f2744\")),\n"
    "            _ptile(f\"{_av.get('indicator_pct', 0):.0f}%\", \"Availability resilience\",\n"
    "                   \"Indicative - outage risk\", \"#475569\"),\n"
    "        ]\n"
    "        _strip = Table([_tiles], colWidths=[ASX_INNER_W / 3] * 3)\n"
    "        _strip.setStyle(TableStyle([\n"
    "            (\"VALIGN\", (0, 0), (-1, -1), \"TOP\"),\n"
    "            (\"LEFTPADDING\", (0, 0), (0, 0), 0),\n"
    "            (\"LEFTPADDING\", (1, 0), (-1, -1), 18),\n"
    "            (\"RIGHTPADDING\", (0, 0), (-1, -1), 8),\n"
    "            (\"TOPPADDING\", (0, 0), (-1, -1), 10),\n"
    "            (\"BOTTOMPADDING\", (0, 0), (-1, -1), 0),\n"
    "            (\"LINEABOVE\", (0, 0), (-1, 0), 0.6, colors.HexColor(\"#cbd5e1\")),\n"
    "        ]))\n"
    "        prob_strip = [\n"
    "            Spacer(1, 12),\n"
    "            Paragraph(\"ANNUAL LIKELIHOOD\", _style_section_label()),\n"
    "            Spacer(1, 2),\n"
    "            Paragraph(\"How often a loss event is expected - the frequency view that \"\n"
    "                      \"pairs with the cost figures above (nested: the data-breach \"\n"
    "                      \"rate is part of the total).\", _style_intro()),\n"
    "            Spacer(1, 2),\n"
    "            _strip,\n"
    "        ]\n"
    "\n"
    "    out = [\n"
    "        Paragraph(\"FINANCIAL IMPACT\", _style_section_label()),\n"
    "        Paragraph(\"What a Breach Could Cost\", _style_slide_title(30)),\n"
    "        Paragraph(\"Modelled annual cyber loss across a range of severity scenarios, from the most likely outcome to a rare catastrophe.\",\n"
    "                   _style_intro()),\n"
    "        body,\n"
    "    ]\n"
    "    out += prob_strip\n"
    "    out += [\n"
    "        Spacer(1, 10),\n"
    "        Paragraph(\"Figures are statistical model output. Selecting the appropriate cover limit is a decision for the insured in consultation with the broker.\",\n"
    "                   caveat_st),\n"
    "    ]\n"
    "    return out\n"
)
assert s.count(OLD) == 1, ("exec financial return anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1)

assert "\r" not in s
assert "ANNUAL LIKELIHOOD" in s
assert "prob_strip = [" in s
ast.parse(s)
with open(PR, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(PR, encoding="utf-8").read())
print("OK pdf_report.py: item #27 exec-deck ANNUAL LIKELIHOOD probability strip wired (AST valid).")
