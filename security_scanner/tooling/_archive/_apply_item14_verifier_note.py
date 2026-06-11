# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX one-off (task #14, step H): document the compound-tail re-baseline in
verify_supply_chain_financial_wiring.py. The verifier asserts RELATIVE movement
(directional / min-delta), not hardcoded absolute losses, so switching the
return periods to the compound distribution required no numeric baseline change;
the thresholds were re-confirmed under compound (31/31 PASS). This adds a one-
time note at the fin_p99 extraction so a future reader knows. CRLF-preserving."""
import os

V = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "tooling", "verify_supply_chain_financial_wiring.py")
s = open(V, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

OLD = (
    '        "fin_p99": ((fin.get("return_periods", {}) or {})\n'
    '                     .get("1_in_100", {}) or {}).get("loss_zar", 0),\n'
)
NEW = (
    "        # NOTE (item #14, 2026-06-04): return_periods now read the COMPOUND\n"
    "        # (loss-given-event) distribution, not the prob-weighted one. These\n"
    "        # assertions are RELATIVE (directional / min-delta), so no numeric\n"
    "        # baseline changed - the thresholds were re-confirmed under compound\n"
    "        # (31/31 PASS). A 1-in-100/250 that holds with posture is expected.\n"
    '        "fin_p99": ((fin.get("return_periods", {}) or {})\n'
    '                     .get("1_in_100", {}) or {}).get("loss_zar", 0),\n'
)
n = s.count(OLD)
assert n == 1, ("fin_p99 anchor count", n)
s = s.replace(OLD, NEW, 1)
assert "return_periods now read the COMPOUND" in s
assert "\r" not in s
with open(V, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print("OK verify_supply_chain_financial_wiring.py: compound re-baseline note added.")
