# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (2026-06-05): align the availability MITIGATIONS bi_reduction values
with the T3 p_interruption increments. bi_reduction is frequency-scaled in the
savings calc (savings += ddos_loss * bi_reduction / p_int), so each control's
bi_reduction should equal its p_interruption increment. The old set inverted WAF
and CDN (WAF 0.05 > CDN 0.03) - WAF is L7-flood only, CDN is the primary
availability control. Fix: WAF 0.05->0.015, CDN 0.03->0.035, single-ASN
0.05->0.025. WAF's rsi_reduction (0.05, web-exploit ransomware entry) is untouched.
CRLF-safe. NOT shipped by this script."""
import ast, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA = os.path.join(ROOT, "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s
n = 0
for tag, old, new in [
    ("WAF bi_reduction",
     "\"rsi_reduction\": 0.05, \"bi_reduction\": 0.05, \"label\": \"Deploy a Web Application Firewall (WAF)\"}",
     "\"rsi_reduction\": 0.05, \"bi_reduction\": 0.015, \"label\": \"Deploy a Web Application Firewall (WAF)\"}"),
    ("single-ASN bi_reduction",
     "\"bi_reduction\": 0.05, \"label\": \"Add hosting redundancy across multiple providers\"}",
     "\"bi_reduction\": 0.025, \"label\": \"Add hosting redundancy across multiple providers\"}"),
    ("CDN bi_reduction",
     "\"bi_reduction\": 0.03, \"label\": \"Deploy a CDN for DDoS resilience and availability\"}",
     "\"bi_reduction\": 0.035, \"label\": \"Deploy a CDN for DDoS resilience and availability\"}"),
]:
    assert s.count(old) == 1, (tag, s.count(old))
    s = s.replace(old, new, 1); n += 1

ast.parse(s)
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(SA, encoding="utf-8").read())
print(f"OK scoring_analytics.py: {n} bi_reduction edits (WAF 0.015, ASN 0.025, CDN 0.035 - "
      f"mirror p_interruption increments; WAF/CDN inversion fixed).")
