# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #27e): the stacked-tile ANNUAL LIKELIHOOD strip is too tall for the
assessment-slide usable height (kept overflowing to a 2nd page). Replace it with a
compact single inline likelihood line (grade-coloured % + label + grade, pipe-
separated) - a fraction of the height, reliably one page. Presentation-only.
CRLF-safe + AST-validated. NOT shipped."""
import ast
import os

PR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "pdf_report.py")
s = open(PR, encoding="utf-8").read()
assert "\r" not in s

OLD = (
    "        def _ptile(pct, lab, sub, hexc):\n"
    "            return [\n"
    "                Paragraph(pct, ParagraphStyle(\"ptv\", fontSize=20, fontName=ASX_SANS_BOLD,\n"
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
    "            (\"TOPPADDING\", (0, 0), (-1, -1), 6),\n"
    "            (\"BOTTOMPADDING\", (0, 0), (-1, -1), 0),\n"
    "            (\"LINEABOVE\", (0, 0), (-1, 0), 0.6, colors.HexColor(\"#cbd5e1\")),\n"
    "        ]))\n"
    "        prob_strip = [\n"
    "            Spacer(1, 8),\n"
    "            Paragraph(\"ANNUAL LIKELIHOOD \"\n"
    "                      \"<font size=9 color='#94a3b8'>(how often a loss event is \"\n"
    "                      \"expected - pairs with the cost above)</font>\", _style_section_label()),\n"
    "            Spacer(1, 3),\n"
    "            _strip,\n"
    "        ]\n"
)
NEW = (
    "        def _chip(pct, lab, grade, hexc):\n"
    "            return (\"<font name='Helvetica-Bold' size='16' color='\" + hexc + \"'>\" + pct + \"</font>\"\n"
    "                    \" <font size='10' color='#0f2744'><b>\" + lab + \"</b></font>\"\n"
    "                    \" <font size='9' color='#64748b'>\" + grade + \"</font>\")\n"
    "        _sep = \" &nbsp;&nbsp; <font color='#cbd5e1'>|</font> &nbsp;&nbsp; \"\n"
    "        _line = _sep.join([\n"
    "            _chip(\"%.1f%%\" % _ci.get('probability_pct', 0), \"Total cyber-incident\",\n"
    "                  _ci.get('grade', ''), _ghex.get(_ci.get('grade', ''), \"#0f2744\")),\n"
    "            _chip(\"%.2f%%\" % _db.get('probability_pct', 0), \"Data breach\",\n"
    "                  _db.get('grade', ''), _ghex.get(_db.get('grade', ''), \"#0f2744\")),\n"
    "            _chip(\"%.0f%%\" % _av.get('indicator_pct', 0), \"Availability\",\n"
    "                  \"indicative\", \"#475569\"),\n"
    "        ])\n"
    "        prob_strip = [\n"
    "            Spacer(1, 10),\n"
    "            Paragraph(\"ANNUAL LIKELIHOOD \"\n"
    "                      \"<font size=9 color='#94a3b8'>(how often a loss event is \"\n"
    "                      \"expected - pairs with the cost above; data breach is nested \"\n"
    "                      \"in the total)</font>\", _style_section_label()),\n"
    "            Spacer(1, 5),\n"
    "            Paragraph(_line, ParagraphStyle(\"plk\", fontSize=11, leading=20)),\n"
    "        ]\n"
)
assert s.count(OLD) == 1, ("strip block anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1)

assert "\r" not in s
assert "_sep.join([" in s
assert "_ptile" not in s
ast.parse(s)
with open(PR, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(PR, encoding="utf-8").read())
print("OK pdf_report.py: item #27e exec likelihood strip -> compact inline line (AST valid).")
