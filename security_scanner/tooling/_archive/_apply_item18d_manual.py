# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #18d): extend the item #18 manual bullet to note the remediation
recommendation (the lock for the #18c savings/advice entry). CRLF-safe. NOT shipped."""
import ast
import os

P3 = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "manual_parts", "part3_email_network.py")
s = open(P3, encoding="utf-8").read()
assert "\r" not in s

OLD = (
    "        \"conservative and calibration-gated.\"\n"
    "    )\n"
)
NEW = (
    "        \"conservative and calibration-gated. Where a non-enforcing soft-fail \"\n"
    "        \"or neutral SPF is found, the report's remediation recommends \"\n"
    "        \"hardening the policy to a terminal -all and includes it in the \"\n"
    "        \"expected-loss mitigation estimate.\"\n"
    "    )\n"
)
assert s.count(OLD) == 1, ("manual bullet tail anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1)

assert "\r" not in s
assert "remediation recommends" in s
ast.parse(s)
with open(P3, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P3, encoding="utf-8").read())
print("OK part3: item #18d manual bullet extended with remediation recommendation (AST valid).")
