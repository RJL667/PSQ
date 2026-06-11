# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #15a, user-approved): add a cover-sizing ladder using the
SPREAD part of the severity-PML distribution (P50/P95/P99) instead of the
compressed top-percentile cluster (P99/P99.5/P99.6, which sit within ~7%).
Additive + non-breaking: return_periods stays for audit/verifier; the new
cover_ladder is the client-facing presentation. CRLF-preserving. NOT shipped."""
import os

SA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

OLD = (
    "                \"basis\": \"severity-PML (single severe event); posture-independent; conditional on a severe breach, not an annual frequency\",\n"
    "            },\n"
)
NEW = (
    "                \"basis\": \"severity-PML (single severe event); posture-independent; conditional on a severe breach, not an annual frequency\",\n"
    "            },\n"
    "            # Cover-sizing ladder - the USEFUL spread of the severity-PML\n"
    "            # (P50/P95/P99). The top percentiles (P99/P99.5/P99.6 in\n"
    "            # return_periods) compress to within ~7%, so the laddered tiers\n"
    "            # below give meaningful cover bands. Posture-independent.\n"
    "            \"cover_ladder\": {\n"
    "                \"typical_severe\": {\"loss_zar\": mc_pml_stats[\"p50\"], \"label\": \"Typical severe breach (P50 severity)\"},\n"
    "                \"bad\":            {\"loss_zar\": mc_pml_stats[\"p95\"], \"label\": \"Bad breach (P95 severity)\"},\n"
    "                \"catastrophic\":   {\"loss_zar\": mc_pml_stats[\"p99\"], \"label\": \"Catastrophic breach (P99 severity)\"},\n"
    "                \"basis\": \"single-severe-event severity percentiles; cover-sizing tiers; posture-independent\",\n"
    "            },\n"
)
n = s.count(OLD)
assert n == 1, ("cover_ladder anchor", n)
s = s.replace(OLD, NEW, 1)
assert "\"cover_ladder\": {" in s
assert "\r" not in s
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print("OK scoring_analytics.py: cover_ladder (P50/P95/P99 severity tiers) added.")
