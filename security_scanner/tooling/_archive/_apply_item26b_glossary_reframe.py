# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #26b): reframe the part6 glossary "Return Period" entry. It still
defined the report's 1-in-100/200/250 figures purely as annual-exceedance
probabilities; post-#15 those are SEVERITY tiers (conditional on a severe event,
posture-independent), labelled with the return-period names by convention. Keep
the classical actuarial definition (a glossary should) but clarify the report's
usage. Doc-only. CRLF-safe + AST-validated. NOT shipped."""
import ast
import os

P6 = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "manual_parts", "part6_reports_scoring_glossary.py")
s = open(P6, encoding="utf-8").read()
assert "\r" not in s

OLD = (
    "            \"An actuarial / reinsurance term denoting the average \"\n"
    "            \"interval between events of a given severity. A 1-in-100 \"\n"
    "            \"year event has a 1% annual exceedance probability \"\n"
    "            \"(P99 percentile of the loss distribution); 1-in-200 = \"\n"
    "            \"0.5% (P99.5); 1-in-250 = 0.4% (P99.6). These figures \"\n"
    "            \"are surfaced as Loss Exposure Scenarios for catastrophe \"\n"
    "            \"cover-sizing discussion.\",\n"
)
NEW = (
    "            \"An actuarial / reinsurance term denoting the average \"\n"
    "            \"interval between events of a given severity (a 1-in-100 \"\n"
    "            \"year event classically carries a 1% annual exceedance \"\n"
    "            \"probability). In this report the 1-in-100 / 1-in-200 / \"\n"
    "            \"1-in-250 names are used for the P99 / P99.5 / P99.6 \"\n"
    "            \"SEVERITY tiers - the severity of a single severe event, \"\n"
    "            \"conditional on it occurring and therefore posture-\"\n"
    "            \"independent - NOT literal annual frequencies. They are \"\n"
    "            \"surfaced as the Loss Exposure Scenarios and Cover-Sizing \"\n"
    "            \"Ladder for catastrophe cover-sizing discussion.\",\n"
)
assert s.count(OLD) == 1, ("glossary Return Period anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1)

assert "\r" not in s
assert "names are used for the P99 / P99.5 / P99.6" in s
ast.parse(s)
with open(P6, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P6, encoding="utf-8").read())
print("OK part6: item #26b glossary Return Period reframed to severity-tier usage (AST valid).")
