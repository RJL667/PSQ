# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #18c): wire the SPF soft-fail / neutral finding into BOTH
remediation surfaces so a `~all`/`?all` (non-enforcing) domain gets actionable
advice + a modelled saving (previously only ABSENT SPF/DMARC did).

  1. RECOMMENDATIONS dict (per-finding advice text; substring-matched at
     `if key in issue`) -> '-all' hardening advice for `~all` and `?all`.
  2. MITIGATIONS list (financial saving) -> one entry (pattern catches both
     qualifiers) routed to the data_breach family.

Anchoring: same Channel-1 signal as item #18 (email posture -> p_breach), now
expressed as its remediation upside (the standard finding<->mitigation pairing;
not a double-count). The MITIGATIONS probability_reduction (0.02) is CONSERVATIVE
and CALIBRATION-GATED - anchored to the existing secondary email-hardening rung
(Enable DKIM = 0.02), smaller than full email-auth absence (0.08); tune at the
calibration session. RECOMMENDATIONS text carries no scoring weight (advice only).

CRLF-preserving mutator + AST validation. NOT shipped."""
import ast
import os

SA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

# ---------------------------------------------------------------------------
# 1. RECOMMENDATIONS: per-finding advice for ~all / ?all (after the +all entry).
#    Anchored on the ASCII tail of the '+all' line (avoids its em-dash).
# ---------------------------------------------------------------------------
OLD1 = "'+all' is extremely dangerous.\",\n"
NEW1 = (
    "'+all' is extremely dangerous.\",\n"
    "        \"SPF ends with '~all'\": \"Change SPF to a hard-fail policy ending in "
    "'-all' so receivers reject mail from unauthorised servers; '~all' (soft-fail) "
    "only marks it. Lower priority if DMARC is already at quarantine or reject, "
    "which enforces regardless of the SPF qualifier.\",\n"
    "        \"SPF ends with '?all'\": \"Change SPF from '?all' (neutral, which "
    "asserts nothing) to a hard-fail '-all' so receivers reject spoofed mail.\",\n"
)
assert s.count(OLD1) == 1, ("RECOMMENDATIONS +all anchor", s.count(OLD1))
s = s.replace(OLD1, NEW1, 1)

# ---------------------------------------------------------------------------
# 2. MITIGATIONS: one entry for the soft/neutral qualifier (after the DKIM rung).
# ---------------------------------------------------------------------------
OLD2 = "\"label\": \"Enable DKIM signing on your mail server\"},\n"
NEW2 = (
    "\"label\": \"Enable DKIM signing on your mail server\"},\n"
    "        # SPF present but non-enforcing (~all/?all) with no enforcing DMARC -\n"
    "        # harden to -all. probability_reduction CONSERVATIVE + CALIBRATION-GATED\n"
    "        # (anchored to the secondary email-hardening rung; tune at calibration).\n"
    "        {\"pattern\": r\"SPF ends with '[~?]all'\",          \"severity\": \"Medium\",   \"scenario\": \"data_breach\",            \"probability_reduction\": 0.02, \"label\": \"Harden SPF to a hard-fail policy ('-all')\"},\n"
)
assert s.count(OLD2) == 1, ("MITIGATIONS DKIM anchor", s.count(OLD2))
s = s.replace(OLD2, NEW2, 1)

# ---------------------------------------------------------------------------
# Validate + write (CRLF-preserving).
# ---------------------------------------------------------------------------
assert "\r" not in s
assert "\"SPF ends with '~all'\":" in s
assert "Harden SPF to a hard-fail policy ('-all')" in s
ast.parse(s)
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(SA, encoding="utf-8").read())
print("OK scoring_analytics.py: item #18c SPF soft-fail remediation (RECOMMENDATIONS + MITIGATIONS) wired (AST valid).")
