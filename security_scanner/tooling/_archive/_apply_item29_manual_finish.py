# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #29): finish the manual - the two items left after #26.
  (A) #16 FAIR-ALE: make the ransomware loss-event frequency explicit in the
      probability-model section (RSI x 0.30, reusing the breach LEF).
  (B) #19: document the executive-deck supply-chain ROLL-UP presentation +
      the "ran-and-clean != not run" reporting semantics.
Doc-only. CRLF-safe + AST-validated. NOT shipped."""
import ast
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P5 = os.path.join(ROOT, "manual_parts", "part5_tech_compliance_insurance.py")
P4 = os.path.join(ROOT, "manual_parts", "part4_exposure.py")

# --- A. part5 #16 FAIR-ALE sentence (before the Monte Carlo h2) ---
s5 = open(P5, encoding="utf-8").read()
assert "\r" not in s5
OLD_A = (
    "        \"secondary indicators like missing headers or weak DNS.\"\n"
    "    )\n"
    "\n"
    "    add_h2(doc, \"Monte Carlo simulation\")\n"
)
NEW_A = (
    "        \"secondary indicators like missing headers or weak DNS.\"\n"
    "    )\n"
    "\n"
    "    add_body(doc,\n"
    "        \"Ransomware enters the expected annual loss as a FAIR loss-event \"\n"
    "        \"frequency: the RSI score is multiplied by the same 0.30 loss-event-\"\n"
    "        \"frequency scalar used for the data-breach leg, then partitioned across \"\n"
    "        \"the ransomware incident types by their conditional shares. Reusing the \"\n"
    "        \"breach scalar - rather than adding a separate threat-frequency term - \"\n"
    "        \"keeps the ransomware and breach legs on a common FAIR basis and the \"\n"
    "        \"expected annual loss internally consistent with the reported breach \"\n"
    "        \"probability.\"\n"
    "    )\n"
    "\n"
    "    add_h2(doc, \"Monte Carlo simulation\")\n"
)
assert s5.count(OLD_A) == 1, ("part5 RSI/Monte-Carlo anchor", s5.count(OLD_A))
s5 = s5.replace(OLD_A, NEW_A, 1)
ast.parse(s5)
with open(P5, "wb") as f:
    f.write(s5.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P5, encoding="utf-8").read())

# --- B. part4 #19 supply-chain roll-up + clean-semantics note ---
s4 = open(P4, encoding="utf-8").read()
assert "\r" not in s4
OLD_B = (
    "        \".env, exposed database dumps) are flagged separately and feed \"\n"
    "        \"into the catastrophe-tail inflation in the FAIR Monte Carlo.\"\n"
    "    )\n"
)
NEW_B = (
    "        \".env, exposed database dumps) are flagged separately and feed \"\n"
    "        \"into the catastrophe-tail inflation in the FAIR Monte Carlo.\"\n"
    "    )\n"
    "\n"
    "    add_body(doc,\n"
    "        \"Presentation: across all supply-chain signals (related domains, \"\n"
    "        \"third-party scripts, dependency manifests, the email-vendor surface, \"\n"
    "        \"vendor-breach correlation, CMS plugins and the cross-correlation), the \"\n"
    "        \"executive deck presents a single rolled-up supply-chain verdict and \"\n"
    "        \"only the signals carrying a material finding; the full per-signal \"\n"
    "        \"detail appears in the technical report and the HTML view. A checker \"\n"
    "        \"that runs and finds nothing is reported as clean - a positive due-\"\n"
    "        \"diligence result - which is distinct from a checker that did not run \"\n"
    "        \"or is not applicable (for example, the CMS-plugin checker on a non-\"\n"
    "        \"WordPress site).\"\n"
    "    )\n"
)
assert s4.count(OLD_B) == 1, ("part4 S-1 anchor", s4.count(OLD_B))
s4 = s4.replace(OLD_B, NEW_B, 1)
ast.parse(s4)
with open(P4, "wb") as f:
    f.write(s4.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P4, encoding="utf-8").read())

print("OK manual: item #29 #16 FAIR-ALE (part5) + #19 SC roll-up note (part4) added (AST valid).")
