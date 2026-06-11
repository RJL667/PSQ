# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #27d): get the financial slide back to ONE page after adding the
ANNUAL LIKELIHOOD strip. The tall element is the BAR CHART (5 bars w/ inter-bar
spacing + wrapping severity labels), not the navy card. Cut the inter-bar spacing
12->5, restore navy to 285 (balanced with the now-shorter bars), and tighten the
strip (tile 23->20, toppadding 10->6). Presentation-only. CRLF-safe. NOT shipped."""
import ast
import os

PR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "pdf_report.py")
s = open(PR, encoding="utf-8").read()
assert "\r" not in s

reps = [
    # bar inter-bar spacing
    ("        bar_chart_rows.append([Spacer(1, 12)])\n",
     "        bar_chart_rows.append([Spacer(1, 5)])\n"),
    # navy card height (balance with shorter bars)
    ("                       colWidths=[290], rowHeights=[250])\n",
     "                       colWidths=[290], rowHeights=[285])\n"),
    # strip tile % font
    ("                Paragraph(pct, ParagraphStyle(\"ptv\", fontSize=23, fontName=ASX_SANS_BOLD,\n",
     "                Paragraph(pct, ParagraphStyle(\"ptv\", fontSize=20, fontName=ASX_SANS_BOLD,\n"),
    # strip table top padding
    ("            (\"TOPPADDING\", (0, 0), (-1, -1), 10),\n"
     "            (\"BOTTOMPADDING\", (0, 0), (-1, -1), 0),\n"
     "            (\"LINEABOVE\", (0, 0), (-1, 0), 0.6, colors.HexColor(\"#cbd5e1\")),\n",
     "            (\"TOPPADDING\", (0, 0), (-1, -1), 6),\n"
     "            (\"BOTTOMPADDING\", (0, 0), (-1, -1), 0),\n"
     "            (\"LINEABOVE\", (0, 0), (-1, 0), 0.6, colors.HexColor(\"#cbd5e1\")),\n"),
]
for old, new in reps:
    assert s.count(old) == 1, ("anchor", repr(old[:50]), s.count(old))
    s = s.replace(old, new, 1)

assert "\r" not in s
assert "Spacer(1, 5)])" in s
ast.parse(s)
with open(PR, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(PR, encoding="utf-8").read())
print("OK pdf_report.py: item #27d financial-slide spacing tightened for one-page fit.")
