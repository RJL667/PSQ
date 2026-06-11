# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #20): darken the assessment-slide intro/subtitle text for
readability. _style_intro used ASX_GREY_MUTED (#94a3b8, ~2.8:1 on white - fails
WCAG AA); switch to the palette's readable body grey ASX_GREY_BODY (#475569,
~7.5:1, AAA). One change fixes every assessment-slide subtitle (financial,
supply-chain, attacker's-view, etc.). Presentation-only. CRLF-safe. NOT shipped."""
import ast
import os

PR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "pdf_report.py")
s = open(PR, encoding="utf-8").read()
assert "\r" not in s

OLD = (
    "def _style_intro():\n"
    "    return ParagraphStyle(\"asx_intro\", fontSize=11, fontName=ASX_SANS,\n"
    "                           textColor=ASX_GREY_MUTED, leading=15, alignment=TA_LEFT,\n"
    "                           spaceAfter=10)\n"
)
NEW = (
    "def _style_intro():\n"
    "    # Darkened from ASX_GREY_MUTED (#94a3b8, fails WCAG AA) to the readable\n"
    "    # body grey ASX_GREY_BODY (#475569, AAA) - slide subtitles were hard to read.\n"
    "    return ParagraphStyle(\"asx_intro\", fontSize=11, fontName=ASX_SANS,\n"
    "                           textColor=ASX_GREY_BODY, leading=15, alignment=TA_LEFT,\n"
    "                           spaceAfter=10)\n"
)
assert s.count(OLD) == 1, ("_style_intro anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1)

assert "\r" not in s
assert "textColor=ASX_GREY_BODY, leading=15" in s
ast.parse(s)
with open(PR, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(PR, encoding="utf-8").read())
print("OK pdf_report.py: item #20 intro subtitle darkened to ASX_GREY_BODY (AST valid).")
