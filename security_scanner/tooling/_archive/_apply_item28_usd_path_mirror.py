# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #28): the HTML USD-path fallback still labelled the catastrophe
rows "1-in-100 / 1-in-200 / 1-in-250 event" off monte_carlo.total (annual),
inconsistent with the ZAR path (severity-PML, items #22/#23/#24). Mirror the ZAR
framing: the catastrophe rows become "Severe / Extreme / Catastrophic event
(P99/P99.5/P99.6 severity)" off monte_carlo.severity_pml (fallback to total). Mode/
median stay annual (correct). Doc/presentation-only. CRLF-safe + Jinja-validated."""
import os

HTML = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "templates", "results.html")
h = open(HTML, encoding="utf-8").read()
assert "\r" not in h

OLD = (
    "        {% set mc = fin.monte_carlo if fin.monte_carlo is defined else {} %}\n"
    "        {% set mc_t = mc.total if mc.total is defined else {} %}\n"
    "        <table class=\"kv-table\" style=\"margin-top:6px;margin-bottom:8px;\">\n"
    "          <tr><td style=\"width:220px;\">Most Likely (mode)</td><td><strong>{{ cur }}{{ '{:,.0f}'.format(mc_t.mode | default(mc_t.p50 | default(0))) }}</strong></td></tr>\n"
    "          <tr><td>Median (P50)</td><td><strong>{{ cur }}{{ '{:,.0f}'.format(mc_t.p50 | default(0)) }}</strong></td></tr>\n"
    "          <tr><td>1-in-100 event (P99)</td><td><strong>{{ cur }}{{ '{:,.0f}'.format(mc_t.p99 | default(0)) }}</strong></td></tr>\n"
    "          <tr><td>1-in-200 event (P99.5)</td><td><strong>{{ cur }}{{ '{:,.0f}'.format(mc_t.p99_5 | default(0)) }}</strong></td></tr>\n"
    "          <tr><td>1-in-250 event (P99.6)</td><td><strong>{{ cur }}{{ '{:,.0f}'.format(mc_t.p99_6 | default(0)) }}</strong></td></tr>\n"
)
NEW = (
    "        {% set mc = fin.monte_carlo if fin.monte_carlo is defined else {} %}\n"
    "        {% set mc_t = mc.total if mc.total is defined else {} %}\n"
    "        {# Catastrophe rows use severity-PML (single severe event), mirroring the ZAR path. #}\n"
    "        {% set mc_pml = mc.severity_pml if mc.severity_pml is defined else mc_t %}\n"
    "        <table class=\"kv-table\" style=\"margin-top:6px;margin-bottom:8px;\">\n"
    "          <tr><td style=\"width:220px;\">Most Likely (mode)</td><td><strong>{{ cur }}{{ '{:,.0f}'.format(mc_t.mode | default(mc_t.p50 | default(0))) }}</strong></td></tr>\n"
    "          <tr><td>Median (P50)</td><td><strong>{{ cur }}{{ '{:,.0f}'.format(mc_t.p50 | default(0)) }}</strong></td></tr>\n"
    "          <tr><td>Severe event (P99 severity)</td><td><strong>{{ cur }}{{ '{:,.0f}'.format(mc_pml.p99 | default(0)) }}</strong></td></tr>\n"
    "          <tr><td>Extreme event (P99.5 severity)</td><td><strong>{{ cur }}{{ '{:,.0f}'.format(mc_pml.p99_5 | default(0)) }}</strong></td></tr>\n"
    "          <tr><td>Catastrophic event (P99.6 severity, 1-in-250)</td><td><strong>{{ cur }}{{ '{:,.0f}'.format(mc_pml.p99_6 | default(0)) }}</strong></td></tr>\n"
)
assert h.count(OLD) == 1, ("USD path anchor", h.count(OLD))
h = h.replace(OLD, NEW, 1)

assert "\r" not in h
assert "Severe event (P99 severity)" in h
try:
    from jinja2 import Environment
    Environment().parse(h)
    jok = "Jinja2 OK"
except ImportError:
    jok = "jinja2 not importable"
with open(HTML, "wb") as f:
    f.write(h.replace("\n", "\r\n").encode("utf-8"))
print(f"OK results.html: item #28 USD path mirrors ZAR severity framing ({jok}).")
