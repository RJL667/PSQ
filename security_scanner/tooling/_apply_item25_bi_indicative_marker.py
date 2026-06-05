# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #25): the cost-category breakdown presented the business-
interruption probability (= p_interruption, the INDICATIVE outage heuristic) as a
bald probability, while the dedicated Availability Resilience Indicator card
(item #17) correctly fences it as indicative. Align the cost breakdown so the same
number is never read as a calibrated rate: replace the bald "(P=...)" on the BI
cost rows with "(indicative outage risk)", and mark the USD-path BI probability
cell "(indicative)". The data-breach P (= the calibrated p_breach) is untouched.
Presentation-only. CRLF-safe + AST/Jinja validated. NOT shipped."""
import ast
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PR = os.path.join(ROOT, "pdf_report.py")
HTML = os.path.join(ROOT, "templates", "results.html")

# --- 1. PDF ZAR cost breakdown BI row ---
s = open(PR, encoding="utf-8").read()
assert "\r" not in s
OLD_PDF = (
    "            (\"Bus. Interruption\",     f\"{cur}&nbsp;{sc.get('business_interruption', {})"
    ".get('estimated_loss', 0):,.0f}  (P={sc.get('business_interruption', {}).get('probability', 0)})\"),\n"
)
NEW_PDF = (
    "            (\"Bus. Interruption\",     f\"{cur}&nbsp;{sc.get('business_interruption', {})"
    ".get('estimated_loss', 0):,.0f}  (indicative outage risk)\"),\n"
)
assert s.count(OLD_PDF) == 1, ("PDF BI row anchor", s.count(OLD_PDF))
s = s.replace(OLD_PDF, NEW_PDF, 1)
assert "\r" not in s
ast.parse(s)
with open(PR, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(PR, encoding="utf-8").read())

# --- 2 + 3. HTML cost-row span + USD-path probability cell ---
h = open(HTML, encoding="utf-8").read()
assert "\r" not in h
OLD_H1 = (
    "            <td>R&nbsp;{{ '{:,.0f}'.format(bi.estimated_loss | default(0)) }} "
    "<span style=\"color:var(--muted);\">(P={{ '%.1f'|format((bi.probability | default(0)) * 100) }}%)</span></td>\n"
)
NEW_H1 = (
    "            <td>R&nbsp;{{ '{:,.0f}'.format(bi.estimated_loss | default(0)) }} "
    "<span style=\"color:var(--muted);\">(indicative outage risk)</span></td>\n"
)
assert h.count(OLD_H1) == 1, ("HTML BI cost row anchor", h.count(OLD_H1))
h = h.replace(OLD_H1, NEW_H1, 1)

OLD_H2 = (
    "            <tr><td>Business Interruption</td><td>{{ '%.1f'|format((bi.probability | default(0)) * 100) }}%</td>"
)
NEW_H2 = (
    "            <tr><td>Business Interruption</td><td>{{ '%.1f'|format((bi.probability | default(0)) * 100) }}% "
    "<span style=\"color:var(--muted);font-size:.85em;\">(indicative)</span></td>"
)
assert h.count(OLD_H2) == 1, ("HTML USD BI row anchor", h.count(OLD_H2))
h = h.replace(OLD_H2, NEW_H2, 1)

assert "\r" not in h
try:
    from jinja2 import Environment
    Environment().parse(h)
    jok = "Jinja2 OK"
except ImportError:
    jok = "jinja2 not importable"
with open(HTML, "wb") as f:
    f.write(h.replace("\n", "\r\n").encode("utf-8"))

print(f"OK item #25: BI probability marked indicative in cost breakdowns (PDF AST + HTML {jok}).")
