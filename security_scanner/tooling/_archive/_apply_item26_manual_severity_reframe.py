# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #26): reframe the part5 catastrophe / loss-exposure methodology
from the pre-#15 ANNUAL-frequency framing to the shipped #15 SEVERITY-PML framing,
so the manual matches the code + the reports (#22/#23/#24) + the #17 reporting-views
section. Three stale spots:
  - the MC percentile line ("P99 = 1-in-100 year");
  - the "Compound aggregation" section ("return periods are taken from the compound
    distribution") - #15 moved them to severity-PML, compound retained for audit;
  - the Loss Exposure Scenarios bullets ("exceeded once in 100 years / 1% annual
    exceedance probability") - now conditional severity tiers.
Mode/median stay annual (correct). Doc-only. CRLF-safe + AST-validated. NOT shipped."""
import ast
import os

P5 = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "manual_parts", "part5_tech_compliance_insurance.py")
s = open(P5, encoding="utf-8").read()
assert "\r" not in s

# --- A. MC percentile line ---
OLD_A = (
    "        \"P50, P75, P95) plus three return-period percentiles (P99 = 1-in-\"\n"
    "        \"100 year, P99.5 = 1-in-200, P99.6 = 1-in-250). A pure-numpy \"\n"
)
NEW_A = (
    "        \"P50, P75, P95) plus three catastrophe-severity tiers (P99, P99.5, \"\n"
    "        \"P99.6, reported as the 1-in-100 / 1-in-200 / 1-in-250 cover tiers). A pure-numpy \"\n"
)
assert s.count(OLD_A) == 1, ("MC line anchor", s.count(OLD_A))
s = s.replace(OLD_A, NEW_A, 1)

# --- B. Compound aggregation section: retitle + rewrite to severity-PML ---
OLD_B = (
    "    add_h2(doc, \"Compound aggregation for the catastrophe tail\")\n"
    "\n"
    "    add_body(doc,\n"
    "        \"The expected-loss and most-likely figures are computed by \"\n"
    "        \"probability-weighting each incident type (probability multiplied \"\n"
    "        \"by severity). For the return-period tail this construction is \"\n"
    "        \"replaced by a compound, loss-given-event aggregation: in each \"\n"
    "        \"simulated year every incident type either occurs (a Bernoulli \"\n"
    "        \"draw against its annual probability) or does not, and when it \"\n"
    "        \"occurs the full incident severity is realised rather than a \"\n"
    "        \"probability-scaled fraction. A catastrophe is a realised severe \"\n"
    "        \"year, and the severity of that year is independent of security \"\n"
    "        \"posture; posture changes the frequency of loss events, not the \"\n"
    "        \"size of a realised one. The compound mean equals the probability-\"\n"
    "        \"weighted expected loss, so the expected-loss and remediation \"\n"
    "        \"figures are unchanged; only the 1-in-100, 1-in-200 and 1-in-250 \"\n"
    "        \"return periods are taken from the compound distribution. This \"\n"
    "        \"prevents the catastrophe view from collapsing toward zero as an \"\n"
    "        \"organisation improves its posture: a realised data-breach or \"\n"
    "        \"ransomware event remains expensive even for a well-defended firm.\"\n"
    "    )\n"
)
NEW_B = (
    "    add_h2(doc, \"Catastrophe tail: severity of a single severe event\")\n"
    "\n"
    "    add_body(doc,\n"
    "        \"The expected-loss and most-likely figures are computed by \"\n"
    "        \"probability-weighting each incident type (annual probability \"\n"
    "        \"multiplied by severity) - the expected annual loss. The catastrophe \"\n"
    "        \"and cover-sizing figures are constructed differently: they report the \"\n"
    "        \"SEVERITY of a single severe event - a full-stack double-extortion \"\n"
    "        \"breach - at increasing percentiles of a severity distribution. They \"\n"
    "        \"answer the question 'if a severe event occurs, how large would it \"\n"
    "        \"be?', and are therefore CONDITIONAL on a severe event occurring and \"\n"
    "        \"INDEPENDENT of security posture: posture changes the frequency of \"\n"
    "        \"loss events, not the size of a realised one. A compound, loss-given-\"\n"
    "        \"event annual distribution (each incident type drawn as a Bernoulli \"\n"
    "        \"occurrence, full severity on occurrence) is also computed and \"\n"
    "        \"retained in the JSON output for audit; its mean equals the \"\n"
    "        \"probability-weighted expected loss, so the expected-loss and \"\n"
    "        \"remediation figures are unchanged. Reporting the catastrophe tail as \"\n"
    "        \"conditional severity prevents the cover view from collapsing toward \"\n"
    "        \"zero as an organisation improves its posture: a realised data-breach \"\n"
    "        \"or ransomware event remains expensive even for a well-defended firm.\"\n"
    "    )\n"
)
assert s.count(OLD_B) == 1, ("compound section anchor", s.count(OLD_B))
s = s.replace(OLD_B, NEW_B, 1)

# --- C. Loss-exposure intro: set up annual-vs-severity split ---
OLD_C = (
    "        \"that decision on behalf of the insured. The output therefore presents \"\n"
    "        \"a Loss Exposure Scenarios table with five named figures:\"\n"
)
NEW_C = (
    "        \"that decision on behalf of the insured. The output therefore presents \"\n"
    "        \"a Loss Exposure Scenarios table with five named figures - the first \"\n"
    "        \"two are annual-loss scenarios; the last three are the SEVERITY of a \"\n"
    "        \"single severe event, conditional on it occurring and therefore \"\n"
    "        \"posture-independent:\"\n"
)
assert s.count(OLD_C) == 1, ("loss-exposure intro anchor", s.count(OLD_C))
s = s.replace(OLD_C, NEW_C, 1)

# --- D. The three catastrophe bullets: annual frequency -> conditional severity ---
OLD_D = (
    "    add_bullet(doc,\n"
    "        \"1-in-100 event (P99) — the loss level expected to be exceeded once in \"\n"
    "        \"100 years (1% annual exceedance probability). Standard reinsurance / \"\n"
    "        \"underwriting convention for cover sizing.\"\n"
    "    )\n"
    "    add_bullet(doc,\n"
    "        \"1-in-200 event (P99.5) — aligned with the FSCA SAM (Solvency Assessment \"\n"
    "        \"and Management) regime's catastrophe scenario.\"\n"
    "    )\n"
    "    add_bullet(doc,\n"
    "        \"1-in-250 event (P99.6) — extreme tail view requested for catastrophe-\"\n"
    "        \"cover discussions. GPD-fitted from the right tail of the simulation.\"\n"
    "    )\n"
)
NEW_D = (
    "    add_bullet(doc,\n"
    "        \"Severe event (P99 severity) — the severity of a single severe event at \"\n"
    "        \"the 99th percentile of the severity distribution, conditional on a \"\n"
    "        \"severe event occurring. A cover-sizing figure (how large a severe loss \"\n"
    "        \"could be), NOT an annual frequency. Standard reinsurance / underwriting \"\n"
    "        \"convention; reported under the 1-in-100 cover tier.\"\n"
    "    )\n"
    "    add_bullet(doc,\n"
    "        \"Extreme event (P99.5 severity) — the next severity tier, aligned with \"\n"
    "        \"the FSCA SAM (Solvency Assessment and Management) regime's catastrophe \"\n"
    "        \"benchmark; reported under the 1-in-200 cover tier.\"\n"
    "    )\n"
    "    add_bullet(doc,\n"
    "        \"Catastrophic event (P99.6 severity) — the extreme severity tier and the \"\n"
    "        \"standard SAM / reinsurance catastrophe benchmark (reported as 1-in-250), \"\n"
    "        \"GPD-fitted from the right tail of the severity distribution.\"\n"
    "    )\n"
)
assert s.count(OLD_D) == 1, ("catastrophe bullets anchor", s.count(OLD_D))
s = s.replace(OLD_D, NEW_D, 1)

assert "\r" not in s
assert "Catastrophe tail: severity of a single severe event" in s
assert "Severe event (P99 severity)" in s
assert "exceeded once in" not in s  # the stale annual framing is gone
ast.parse(s)
with open(P5, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P5, encoding="utf-8").read())
print("OK part5: item #26 catastrophe/loss-exposure reframed to severity-PML (AST valid).")
