# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #24): make the broker-summary "Why This Matters" prose pull its
CATASTROPHE figures from the severity-PML distribution (single severe event) -
the SAME source as the cover ladder / loss-exposure table / exec-deck bars - not
the prob-weighted annual `monte_carlo.total`. Without this, item #23 relabelled
the prose's catastrophe numbers as "P99 severity / 1-in-250 severity" while they
were actually the annual-total tail (e.g. takealot R308m), contradicting the cover
ladder's 1-in-250 of R2.91bn. The median stays the annual median (total.p50), which
is correct for "estimated annual cyber loss". Falls back to total.* if severity_pml
is absent (USD path / older data). Presentation-only. CRLF-safe. NOT shipped."""
import ast
import os

PR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "pdf_report.py")
s = open(PR, encoding="utf-8").read()
assert "\r" not in s

OLD = (
    "        mc_data = fin.get(\"monte_carlo\", {}).get(\"total\", {}) if fin else {}\n"
    "        mc_p50 = mc_data.get(\"p50\", total_likely)\n"
    "        mc_p99 = mc_data.get(\"p99\", 0)\n"
    "        mc_p99_6 = mc_data.get(\"p99_6\", 0)\n"
)
NEW = (
    "        mc_data = fin.get(\"monte_carlo\", {}).get(\"total\", {}) if fin else {}\n"
    "        # Catastrophe figures use the severity-PML distribution (single severe\n"
    "        # event), matching the cover ladder / loss-exposure table / exec-deck\n"
    "        # bars - NOT the prob-weighted annual total - so every surface agrees on\n"
    "        # the 1-in-250. The median stays the annual median (correct for the\n"
    "        # 'estimated annual cyber loss' figure). Falls back to total.* if absent.\n"
    "        mc_pml = fin.get(\"monte_carlo\", {}).get(\"severity_pml\", {}) if fin else {}\n"
    "        mc_p50 = mc_data.get(\"p50\", total_likely)\n"
    "        mc_p99 = mc_pml.get(\"p99\", mc_data.get(\"p99\", 0))\n"
    "        mc_p99_6 = mc_pml.get(\"p99_6\", mc_data.get(\"p99_6\", 0))\n"
)
assert s.count(OLD) == 1, ("mc_data summary anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1)

assert "\r" not in s
assert "mc_pml = fin.get(\"monte_carlo\", {}).get(\"severity_pml\"" in s
ast.parse(s)
with open(PR, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(PR, encoding="utf-8").read())
print("OK pdf_report.py: item #24 summary prose catastrophe figures -> severity_pml (AST valid).")
