# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #27b): the #27 ANNUAL LIKELIHOOD strip pushed the financial slide
to a 2nd page (10-page deck -> breaks the navy-page painter). Compact it back to one
page: drop the strip's intro paragraph (the tiles' sub-labels already explain it) and
trim the navy loss-card height 330->300 (it was mostly whitespace). Presentation-only.
CRLF-safe. NOT shipped."""
import ast
import os

PR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "pdf_report.py")
s = open(PR, encoding="utf-8").read()
assert "\r" not in s

# 1. Drop the strip intro paragraph + tighten leading spacer.
OLD1 = (
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
)
NEW1 = (
    "        prob_strip = [\n"
    "            Spacer(1, 8),\n"
    "            Paragraph(\"ANNUAL LIKELIHOOD \"\n"
    "                      \"<font size=9 color='#94a3b8'>(how often a loss event is \"\n"
    "                      \"expected - pairs with the cost above)</font>\", _style_section_label()),\n"
    "            Spacer(1, 3),\n"
    "            _strip,\n"
    "        ]\n"
)
assert s.count(OLD1) == 1, ("strip intro anchor", s.count(OLD1))
s = s.replace(OLD1, NEW1, 1)

# 2. Trim the navy loss-card height 330 -> 300.
OLD2 = (
    "    navy_card = Table([[navy_inner]],\n"
    "                       colWidths=[290], rowHeights=[330])\n"
)
NEW2 = (
    "    navy_card = Table([[navy_inner]],\n"
    "                       colWidths=[290], rowHeights=[300])\n"
)
assert s.count(OLD2) == 1, ("navy card height anchor", s.count(OLD2))
s = s.replace(OLD2, NEW2, 1)

assert "\r" not in s
assert "rowHeights=[300]" in s
ast.parse(s)
with open(PR, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(PR, encoding="utf-8").read())
print("OK pdf_report.py: item #27b exec strip compacted (intro folded into label + navy 330->300).")
