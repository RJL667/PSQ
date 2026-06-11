# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #23): align the return-period LABELS to the post-#15 severity
framing on the exec deck + full report (the loss-exposure TABLE was already fixed
in #22). Post-#15 the return_1_* rows are SEVERITY percentiles conditional on a
severe event - NOT annual frequencies - so "1-in-100 year event" / "1% annual
probability" mis-states them as annual rates.

  1. Exec-deck financial-slide bar chart (label_map + sub_map): "1-in-100 year
     event"/"1% annual probability" -> "Severe event"/"P99 severity", etc. The
     mode/median rows stay annual (they ARE annual and correct).
  2. Full-report "Why This Matters" prose: "In a 1-in-100 year event ... 1-in-250
     year event" -> severity framing.

The mode ("Most likely (peak)") + median ("50% annual probability") are unchanged
(genuinely annual). "1-in-250" is retained as the recognised reinsurance/SAM tier
NAME, reframed as severity (not a year-event frequency). Presentation-only.
CRLF-safe + AST-validated. NOT shipped."""
import ast
import os

PR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "pdf_report.py")
s = open(PR, encoding="utf-8").read()
assert "\r" not in s

# --- 1a. Exec bar-chart label_map (return periods -> severity event names) ---
OLD_LBL = (
    "                \"return_1_100\": \"1-in-100 year event\",\n"
    "                \"return_1_200\": \"1-in-200 year event\",\n"
    "                \"return_1_250\": \"1-in-250 year event\",\n"
)
NEW_LBL = (
    "                \"return_1_100\": \"Severe event\",\n"
    "                \"return_1_200\": \"Extreme event\",\n"
    "                \"return_1_250\": \"Catastrophic event\",\n"
)
assert s.count(OLD_LBL) == 1, ("label_map anchor", s.count(OLD_LBL))
s = s.replace(OLD_LBL, NEW_LBL, 1)

# --- 1b. Exec bar-chart sub_map (annual probability -> severity tier) ---
OLD_SUB = (
    "                \"return_1_100\": \"1% annual probability\",\n"
    "                \"return_1_200\": \"0.5% annual probability\",\n"
    "                \"return_1_250\": \"0.4% annual probability\",\n"
)
NEW_SUB = (
    "                \"return_1_100\": \"P99 severity\",\n"
    "                \"return_1_200\": \"P99.5 severity\",\n"
    "                \"return_1_250\": \"P99.6 severity (1-in-250)\",\n"
)
assert s.count(OLD_SUB) == 1, ("sub_map anchor", s.count(OLD_SUB))
s = s.replace(OLD_SUB, NEW_SUB, 1)

# --- 2. Full-report "Why This Matters" prose ---
OLD_PROSE = (
    "                f\"<b>{cur_cta} {mc_p50:,.0f}</b> (median scenario). In a 1-in-100 year event, losses could reach \"\n"
    "                f\"<b>{cur_cta} {mc_p99:,.0f}</b>; in a 1-in-250 year event, \"\n"
    "                f\"<b>{cur_cta} {mc_p99_6:,.0f}</b>. These figures are derived from a Monte Carlo simulation of \"\n"
)
NEW_PROSE = (
    "                f\"<b>{cur_cta} {mc_p50:,.0f}</b> (median scenario). The severity of a single severe \"\n"
    "                f\"event could reach <b>{cur_cta} {mc_p99:,.0f}</b> (P99 severity); a catastrophic event \"\n"
    "                f\"(the 1-in-250 severity benchmark) could reach <b>{cur_cta} {mc_p99_6:,.0f}</b>. These severity \"\n"
    "                f\"figures are conditional on a severe event occurring and are derived from a Monte Carlo simulation of \"\n"
)
assert s.count(OLD_PROSE) == 1, ("prose anchor", s.count(OLD_PROSE))
s = s.replace(OLD_PROSE, NEW_PROSE, 1)

assert "\r" not in s
assert "\"return_1_100\": \"Severe event\"," in s
assert "P99.6 severity (1-in-250)" in s
assert "the 1-in-250 severity benchmark" in s
ast.parse(s)
with open(PR, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(PR, encoding="utf-8").read())
print("OK pdf_report.py: item #23 return-period severity labels (exec bar chart + full-report prose) (AST valid).")
