# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #18e): close the matching DMARC gap. DMARC `p=none` (published
but monitor-only / non-enforcing) is already scored (-2) and already has per-finding
advice in RECOMMENDATIONS ("DMARC policy is 'none'"), but had NO expected-loss
MITIGATIONS entry (only ABSENT DMARC did). Add it.

  1. scoring_analytics.py MITIGATIONS: + DMARC-p=none -> enforce entry.
  2. part3 manual: append a remediation-inclusion sentence to the DMARC warning.

probability_reduction = 0.04: CONSERVATIVE + CALIBRATION-GATED - half the full
email-auth-absence rung (0.08), double the SPF soft-qualifier rung (0.02); DMARC
enforcement is the primary anti-spoofing lever (CISA BOD 18-01 / NIST SP 800-177 /
M3AAWG target p=reject). Unconditional (nothing above DMARC moots it). CRLF-safe.
NOT shipped."""
import ast
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA = os.path.join(ROOT, "scoring_analytics.py")
P3 = os.path.join(ROOT, "manual_parts", "part3_email_network.py")

# --- 1. MITIGATIONS entry (scoring_analytics.py) ---
s = open(SA, encoding="utf-8").read()
assert "\r" not in s
OLD1 = "\"label\": \"Implement email authentication (SPF/DMARC/DKIM)\"},\n"
NEW1 = (
    "\"label\": \"Implement email authentication (SPF/DMARC/DKIM)\"},\n"
    "        # DMARC published but NOT enforcing (p=none): the primary anti-spoofing\n"
    "        # control is in monitor-only mode (BEC vector). probability_reduction\n"
    "        # CONSERVATIVE + CALIBRATION-GATED - half the full-absence rung (0.08),\n"
    "        # double the SPF-qualifier rung (0.02); CISA BOD 18-01 / NIST SP 800-177\n"
    "        # / M3AAWG target p=reject. Unconditional (nothing above DMARC moots it).\n"
    "        {\"pattern\": r\"DMARC policy is 'none'\",                \"severity\": \"High\",     \"scenario\": \"data_breach\",            \"probability_reduction\": 0.04, \"label\": \"Enforce DMARC (move policy from p=none to quarantine or reject)\"},\n"
)
assert s.count(OLD1) == 1, ("MITIGATIONS email-auth anchor", s.count(OLD1))
s = s.replace(OLD1, NEW1, 1)
assert "Enforce DMARC (move policy from p=none" in s
ast.parse(s)
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(SA, encoding="utf-8").read())

# --- 2. Manual lock (part3 DMARC warning) ---
m = open(P3, encoding="utf-8").read()
assert "\r" not in m
OLD2 = (
    "        \"compromise attacks that exploit missing DMARC are among the most \"\n"
    "        \"financially damaging cyber incidents.\"\n"
    "    )\n"
)
NEW2 = (
    "        \"compromise attacks that exploit missing DMARC are among the most \"\n"
    "        \"financially damaging cyber incidents. The scanner scores a 'none' \"\n"
    "        \"policy as non-enforcing and includes moving it to quarantine or \"\n"
    "        \"reject in the expected-loss remediation estimate.\"\n"
    "    )\n"
)
assert m.count(OLD2) == 1, ("DMARC warning anchor", m.count(OLD2))
m = m.replace(OLD2, NEW2, 1)
ast.parse(m)
with open(P3, "wb") as f:
    f.write(m.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P3, encoding="utf-8").read())

print("OK item #18e: DMARC p=none MITIGATIONS entry + manual lock wired (AST valid, both files).")
