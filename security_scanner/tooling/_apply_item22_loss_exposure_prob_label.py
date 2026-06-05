# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #22): stop the Loss Exposure Scenarios table repeating
"Most likely (peak)" on every catastrophe row.

Post-#15 (severity-PML), the catastrophe rows (return_1_100/200/250) are SEVERITY
percentiles CONDITIONAL on a severe event - not annual frequencies - so their
`annual_prob` is None. The renderer defaulted any None -> "Most likely (peak)",
which is both repetitive AND wrong on those rows (only the mode row is the
most-likely peak). Fix: keep "Most likely (peak)" for the mode row only; show a
dash on the severity rows (an annual probability does not apply to them).

Both the PDF block (loss_exposure_scenarios_block) and the HTML table. Presentation-
only. CRLF-safe + AST/Jinja validated. NOT shipped."""
import ast
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PR = os.path.join(ROOT, "pdf_report.py")
HTML = os.path.join(ROOT, "templates", "results.html")

# --- 1. PDF: loss_exposure_scenarios_block prob column ---
s = open(PR, encoding="utf-8").read()
assert "\r" not in s
OLD_PDF = (
    "        prob = sc.get(\"annual_prob\")\n"
    "        if prob is None:\n"
    "            prob_text = \"Most likely (peak)\"\n"
    "        else:\n"
)
NEW_PDF = (
    "        prob = sc.get(\"annual_prob\")\n"
    "        if prob is None:\n"
    "            # Only the mode row is the actual most-likely peak. The catastrophe\n"
    "            # rows (return_1_*) are SEVERITY percentiles conditional on a severe\n"
    "            # event (post-#15 severity-PML), not annual frequencies - an annual\n"
    "            # probability does not apply, so show a dash rather than repeating\n"
    "            # \"Most likely (peak)\" on every catastrophe row.\n"
    "            prob_text = \"Most likely (peak)\" if key == \"most_likely\" else \"\\u2014\"\n"
    "        else:\n"
)
assert s.count(OLD_PDF) == 1, ("PDF prob anchor", s.count(OLD_PDF))
s = s.replace(OLD_PDF, NEW_PDF, 1)
assert "\r" not in s
ast.parse(s)
with open(PR, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(PR, encoding="utf-8").read())

# --- 2. HTML: loss exposure scenarios table prob cell ---
h = open(HTML, encoding="utf-8").read()
assert "\r" not in h
OLD_HTML = (
    "                  {% if sc_row.annual_prob is none %}Most likely (peak)"
    "{% else %}{{ '%.1f'|format(sc_row.annual_prob * 100) if sc_row.annual_prob < 0.01 "
    "else '%.0f'|format(sc_row.annual_prob * 100) }}%{% endif %}\n"
)
NEW_HTML = (
    "                  {% if sc_row.annual_prob is none %}"
    "{% if key == 'most_likely' %}Most likely (peak){% else %}&mdash;{% endif %}"
    "{% else %}{{ '%.1f'|format(sc_row.annual_prob * 100) if sc_row.annual_prob < 0.01 "
    "else '%.0f'|format(sc_row.annual_prob * 100) }}%{% endif %}\n"
)
assert h.count(OLD_HTML) == 1, ("HTML prob anchor", h.count(OLD_HTML))
h = h.replace(OLD_HTML, NEW_HTML, 1)
assert "\r" not in h
try:
    from jinja2 import Environment
    Environment().parse(h)
    jinja_ok = "Jinja2 parse OK"
except ImportError:
    jinja_ok = "jinja2 not importable - validate on render"
with open(HTML, "wb") as f:
    f.write(h.replace("\n", "\r\n").encode("utf-8"))

print(f"OK item #22: catastrophe rows no longer repeat 'Most likely (peak)' (PDF AST + HTML {jinja_ok}).")
