# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #15a follow-up): cover-ladder upper tier P99 -> P99.6 (1-in-250),
the standard reinsurance / FSCA-SAM catastrophe benchmark. Keeps the P50/P95
spread below it. CRLF-preserving. NOT shipped."""
import os

SA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

OLD = ("                \"catastrophic\":   {\"loss_zar\": mc_pml_stats[\"p99\"], "
       "\"label\": \"Catastrophic breach (P99 severity)\"},\n")
NEW = ("                \"catastrophic\":   {\"loss_zar\": mc_pml_stats[\"p99_6\"], "
       "\"label\": \"Catastrophic breach (1-in-250 / P99.6 severity)\"},\n")
n = s.count(OLD)
assert n == 1, ("ladder upper anchor", n)
s = s.replace(OLD, NEW, 1)
assert "mc_pml_stats[\"p99_6\"], \"label\": \"Catastrophic breach (1-in-250" in s
assert "\r" not in s
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print("OK scoring_analytics.py: cover_ladder upper tier -> P99.6 (1-in-250).")
