# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX FIX (2026-06-08): the Next Steps slide's full-bleed navy background was
painted on a HARDCODED physical page (page == 8). The deck page count is content-
dependent - on data-heavy scans (e.g. mamamoney) an earlier slide overflows to a 2nd
page, pushing the light Plain-Language slide onto page 8, where it got navy-filled and
its dark title/headings became unreadable. Fix: discover the navy page at render time
via a zero-size marker (_AsxNavyAnchor) placed at the END of the slide before Next
Steps; the painter navy-fills the FOLLOWING page. Robust to pagination drift. CRLF-safe.
NOT shipped by this script."""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = os.path.join(ROOT, "pdf_report.py")
s = open(P, encoding="utf-8").read()
assert "\r" not in s
n = 0

# 1. Marker infra + class, before the painter section.
OLD = "# --- Per-page background painter (called by SimpleDocTemplate) ----------\n"
NEW = (
    "# The Next Steps slide is full-bleed navy. Its physical page number is\n"
    "# content-dependent (an earlier slide can overflow to a 2nd page on data-heavy\n"
    "# scans), so it is discovered at RENDER time: _AsxNavyAnchor - a zero-size\n"
    "# marker placed at the END of the slide before Next Steps - records its page;\n"
    "# the painter then navy-fills the FOLLOWING page. Robust to pagination drift.\n"
    "from reportlab.platypus import Flowable as _Flowable\n"
    "_ASX_NAVY_PREV_PAGE = [None]\n"
    "\n"
    "\n"
    "class _AsxNavyAnchor(_Flowable):\n"
    "    \"\"\"Zero-size render-time marker: records the page it lands on so the page\n"
    "    painter can navy-fill the next page (the Next Steps slide).\"\"\"\n"
    "    width = 0\n"
    "    height = 0\n"
    "\n"
    "    def wrap(self, availWidth, availHeight):\n"
    "        return (0, 0)\n"
    "\n"
    "    def draw(self):\n"
    "        _ASX_NAVY_PREV_PAGE[0] = self.canv.getPageNumber()\n"
    "\n"
    "\n"
    "# --- Per-page background painter (called by SimpleDocTemplate) ----------\n"
)
assert s.count(OLD) == 1, ("painter section anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 2. Update the painter docstring (stale hardcoded-page note).
OLD = (
    "    Slide 8 (Next Steps) is full-bleed navy; everything else is white.\n"
    "    NOTE: hardcoded physical page number. The deck is cover..disclosures = 9\n"
    "    pages and Next Steps is the 8th; if the slide order/pagination changes,\n"
    "    update this (a PageTemplate would make it robust).\n"
)
NEW = (
    "    The Next Steps slide is full-bleed navy; everything else is white. The\n"
    "    navy page is found at render time via _AsxNavyAnchor (records the page of\n"
    "    the slide before Next Steps); we navy-fill the FOLLOWING page - robust to\n"
    "    content-driven pagination drift. (Was hardcoded page == 8, which broke\n"
    "    when an earlier slide overflowed and pushed a light slide onto page 8.)\n"
)
assert s.count(OLD) == 1, ("painter docstring", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 3. Painter logic: hardcoded page == 8 -> marker-driven.
OLD = (
    "    if page == 8:\n"
    "        canvas.setFillColor(ASX_NAVY_DEEP)\n"
    "        canvas.rect(0, 0, ASX_PAGE_W, ASX_PAGE_H, stroke=0, fill=1)\n"
    "        _asx_draw_corner_mark(canvas, brand, ASX_PAGE_W - ASX_MARGIN,\n"
    "                              ASX_PAGE_H - 40, light=True)\n"
    "    else:\n"
    "        _asx_draw_corner_mark(canvas, brand, ASX_PAGE_W - ASX_MARGIN,\n"
    "                              22, light=False)\n"
)
NEW = (
    "    navy_page = (_ASX_NAVY_PREV_PAGE[0] + 1) if _ASX_NAVY_PREV_PAGE[0] is not None else None\n"
    "    if navy_page is not None and page == navy_page:\n"
    "        canvas.setFillColor(ASX_NAVY_DEEP)\n"
    "        canvas.rect(0, 0, ASX_PAGE_W, ASX_PAGE_H, stroke=0, fill=1)\n"
    "        _asx_draw_corner_mark(canvas, brand, ASX_PAGE_W - ASX_MARGIN,\n"
    "                              ASX_PAGE_H - 40, light=True)\n"
    "    else:\n"
    "        _asx_draw_corner_mark(canvas, brand, ASX_PAGE_W - ASX_MARGIN,\n"
    "                              22, light=False)\n"
)
assert s.count(OLD) == 1, ("painter logic", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 4. Insert the marker at the end of the Plain-Language slide (before its PageBreak).
OLD = "    story += _assessment_slide_plain_language(results);                     story.append(PageBreak())\n"
NEW = "    story += _assessment_slide_plain_language(results);                     story.append(_AsxNavyAnchor()); story.append(PageBreak())\n"
assert s.count(OLD) == 1, ("story plain_language", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 5. Reset the marker at build start.
OLD = (
    "    story = []\n"
    "    story += _assessment_slide_cover(domain, timestamp, brand);             story.append(PageBreak())\n"
)
NEW = (
    "    _ASX_NAVY_PREV_PAGE[0] = None\n"
    "    story = []\n"
    "    story += _assessment_slide_cover(domain, timestamp, brand);             story.append(PageBreak())\n"
)
assert s.count(OLD) == 1, ("build reset", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

ast.parse(s)
with open(P, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P, encoding="utf-8").read())
print(f"OK pdf_report.py: {n} edits (navy page now marker-driven, not hardcoded page==8).")
