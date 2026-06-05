# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #21): three exec-deck readability/format fixes.

1. PAGE-PAINTER OFF-BY-ONE (root cause of the unreadable dark slide). The painter
   paints physical page 7 navy, but the slide order is now cover..disclosures = 9
   pages with Next Steps on page 8 - so the navy landed on the LIGHT plain-language
   slide (dark text -> invisible) while Next Steps (white text) rendered on white
   (also invisible). Fix 7->8: plain-language renders on white (readable) and Next
   Steps on navy (readable). Both slides fixed by the one change.
2. KPI sub-labels on the "Why This Matters" slide used ASX_GREY_MUTED (#94a3b8,
   fails WCAG AA on the light tiles) -> ASX_GREY_BODY (#475569, AAA).
3. Billions formatting: amounts >= R1bn showed as millions ("R 2721.71m");
   now "R 2.72bn". Fixed in the financial-slide fmt() and the attacker's-view
   "Est. impact" line.

Presentation-only. CRLF-safe + AST-validated. NOT shipped."""
import ast
import os

PR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "pdf_report.py")
s = open(PR, encoding="utf-8").read()
assert "\r" not in s

# --- 1a. Painter docstring (Slide 7 -> Slide 8 + fragility note) ---
OLD_1A = "    Slide 7 (Next Steps) is full-bleed navy; everything else is white.\n"
NEW_1A = (
    "    Slide 8 (Next Steps) is full-bleed navy; everything else is white.\n"
    "    NOTE: hardcoded physical page number. The deck is cover..disclosures = 9\n"
    "    pages and Next Steps is the 8th; if the slide order/pagination changes,\n"
    "    update this (a PageTemplate would make it robust).\n"
)
assert s.count(OLD_1A) == 1, ("painter docstring anchor", s.count(OLD_1A))
s = s.replace(OLD_1A, NEW_1A, 1)

# --- 1b. Painter condition (page 7 -> page 8) ---
OLD_1B = "    if page == 7:\n        canvas.setFillColor(ASX_NAVY_DEEP)\n"
NEW_1B = "    if page == 8:\n        canvas.setFillColor(ASX_NAVY_DEEP)\n"
assert s.count(OLD_1B) == 1, ("painter condition anchor", s.count(OLD_1B))
s = s.replace(OLD_1B, NEW_1B, 1)

# --- 2. KPI sub-label grey -> readable body grey ---
OLD_2 = (
    "    desc_st = ParagraphStyle(\"st_d\", fontSize=10, fontName=ASX_SANS,\n"
    "                               textColor=ASX_GREY_MUTED, leading=13)\n"
)
NEW_2 = (
    "    desc_st = ParagraphStyle(\"st_d\", fontSize=10, fontName=ASX_SANS,\n"
    "                               textColor=ASX_GREY_BODY, leading=13)\n"
)
assert s.count(OLD_2) == 1, ("desc_st anchor", s.count(OLD_2))
s = s.replace(OLD_2, NEW_2, 1)

# --- 3a. Billions in the financial-slide fmt() ---
OLD_3A = (
    "    def fmt(v):\n"
    "        if not v or v == 0: return \"&mdash;\"\n"
    "        if v >= 1_000_000:\n"
    "            return f\"{cur_sym}&nbsp;{v / 1_000_000:.2f}m\"\n"
    "        return f\"{cur_sym}&nbsp;{v:,.0f}\"\n"
)
NEW_3A = (
    "    def fmt(v):\n"
    "        if not v or v == 0: return \"&mdash;\"\n"
    "        if v >= 1_000_000_000:\n"
    "            return f\"{cur_sym}&nbsp;{v / 1_000_000_000:.2f}bn\"\n"
    "        if v >= 1_000_000:\n"
    "            return f\"{cur_sym}&nbsp;{v / 1_000_000:.2f}m\"\n"
    "        return f\"{cur_sym}&nbsp;{v:,.0f}\"\n"
)
assert s.count(OLD_3A) == 1, ("fmt anchor", s.count(OLD_3A))
s = s.replace(OLD_3A, NEW_3A, 1)

# --- 3b. Billions in the attacker's-view "Est. impact" line ---
OLD_3B = "    if fin_mc_p50: p4f.append(f\"Est. impact: {cur_sym} {fin_mc_p50/1_000_000:.2f}m (median)\")\n"
NEW_3B = (
    "    if fin_mc_p50: p4f.append(\"Est. impact: \" + cur_sym + \" \" + (\n"
    "        f\"{fin_mc_p50/1_000_000_000:.2f}bn\" if fin_mc_p50 >= 1_000_000_000\n"
    "        else f\"{fin_mc_p50/1_000_000:.2f}m\") + \" (median)\")\n"
)
assert s.count(OLD_3B) == 1, ("Est. impact anchor", s.count(OLD_3B))
s = s.replace(OLD_3B, NEW_3B, 1)

assert "\r" not in s
assert "if page == 8:" in s
assert "{v / 1_000_000_000:.2f}bn" in s
ast.parse(s)
with open(PR, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(PR, encoding="utf-8").read())
print("OK pdf_report.py: item #21 painter page-fix + KPI grey + billions (AST valid).")
