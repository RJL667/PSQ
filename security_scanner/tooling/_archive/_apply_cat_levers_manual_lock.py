# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (2026-06-08): manual lock for the cat-model levers (Curve A: taper MIN=0.30
/ HI=R2bn; fine floor 0.60). Documents Lever 1 (C1-residual small->large taper) and
Lever 2 (statutory-fine capacity floor) in the part5 methodology bullets. CRLF-safe.
NOT shipped by this script."""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P5 = os.path.join(ROOT, "manual_parts", "part5_tech_compliance_insurance.py")
s = open(P5, encoding="utf-8").read()
assert "\r" not in s
n = 0

# Lever 1 — C1 residual taper (append to the C1 bullet).
OLD = (
    "        \"smaller organisations the residual floor dominates; for large \"\n"
    "        \"consumer record-holders the records-driven term dominates.\"\n"
)
NEW = (
    "        \"smaller organisations the residual floor dominates; for large \"\n"
    "        \"consumer record-holders the records-driven term dominates. Because \"\n"
    "        \"the IBM SA figure is an all-sizes AVERAGE (skewed upward by large-\"\n"
    "        \"organisation breaches), that residual floor is tapered down for sub-\"\n"
    "        \"large-cap entities - from about 30 percent of the modelled residual at \"\n"
    "        \"R10 million of revenue, rising smoothly to the full residual by about \"\n"
    "        \"R2 billion - so a smaller organisation's catastrophe is not over-stated \"\n"
    "        \"by an average that does not fit its size. There is no cap: a small \"\n"
    "        \"entity's modelled catastrophe can still exceed its annual revenue. The \"\n"
    "        \"taper bounds are calibration parameters, configurable without redeployment.\"\n"
)
assert s.count(OLD) == 1, ("C1 taper bullet", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# Lever 2 — statutory-fine capacity floor (extend the C2 bullet).
OLD = (
    "        \"private-commercial fines. The catastrophe view uses the full \"\n"
    "        \"R10 million Section 109 statutory ceiling. GDPR exposure (4% of \"\n"
)
NEW = (
    "        \"private-commercial fines. The catastrophe view uses the full \"\n"
    "        \"R10 million Section 109 statutory ceiling, scaled by the enterprise \"\n"
    "        \"capacity factor - but that factor is floored (at 0.60) for the fixed-\"\n"
    "        \"cap statutory fines, because a serious breach at even a small qualifying \"\n"
    "        \"entity can attract most of the statutory ceiling, so the fine is not \"\n"
    "        \"discounted away by company size. GDPR exposure (4% of \"\n"
)
assert s.count(OLD) == 1, ("C2 fine-floor bullet", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

ast.parse(s)
with open(P5, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P5, encoding="utf-8").read())
print(f"OK part5: {n} manual-lock edits (Lever 1 taper + Lever 2 fine floor documented).")
