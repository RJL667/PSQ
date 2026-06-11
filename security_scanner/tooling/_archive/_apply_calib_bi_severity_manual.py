# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX manual lock (2026-06-05) for the duration-graded BI impact factor.
Adds a bullet after the C3 description in part5 documenting that the daily
revenue-impact fraction is graded by outage length (short acute events ~0.83-
0.90; 25-day rebuild 0.50). CRLF-safe. NOT shipped by this script."""
import ast, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P5 = os.path.join(ROOT, "manual_parts", "part5_tech_compliance_insurance.py")
s = open(P5, encoding="utf-8").read()
assert "\r" not in s

OLD = (
    "        \"figure retains a 25-day point estimate, equal to the new \"\n"
    "        \"distribution mean.\"\n"
    "    )\n"
)
NEW = (
    "        \"figure retains a 25-day point estimate, equal to the new \"\n"
    "        \"distribution mean.\"\n"
    "    )\n"
    "    add_bullet(doc,\n"
    "        \"C3 revenue impact is duration-graded. The daily revenue-loss \"\n"
    "        \"fraction follows the recovery curve - roughly 90 percent on day one \"\n"
    "        \"easing to about 10 percent by the 25-day mark - so its average over \"\n"
    "        \"an outage depends on the outage length. A long 25-day ransomware \"\n"
    "        \"rebuild averages to 50 percent (the long-standing figure), but short \"\n"
    "        \"acute events lose near their full daily revenue throughout: a one-day \"\n"
    "        \"opportunistic outage uses about 90 percent, a five-day denial-of-\"\n"
    "        \"service outage about 83 percent. This was corrected on 5 June 2026, \"\n"
    "        \"replacing a single flat 50 percent that had under-counted the \"\n"
    "        \"severity of short, sharp outages.\"\n"
    "    )\n"
)
assert s.count(OLD) == 1, ("C3 bullet anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1)
ast.parse(s)
with open(P5, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P5, encoding="utf-8").read())
print("OK part5: duration-graded BI impact-factor manual lock added (AST valid, CRLF).")
