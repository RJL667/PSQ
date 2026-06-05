# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #18b): MANUAL LOCK for the SPF-qualifier scoring change. Adds an
anchored bullet to the part3 Email Authentication section (the paragraph IS the
lock, per the anchoring mechanism). Third-person, anchored (RFC 7208 / NIST SP
800-177 / M3AAWG), documents the DMARC-enforcement guard + calibration-gating.
CRLF-preserving mutator + AST validation. NOT shipped."""
import ast
import os

P3 = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "manual_parts", "part3_email_network.py")
s = open(P3, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

OLD = (
    "    add_bullet(doc, \"Overly broad SPF records (such as including large cloud provider IP ranges) weaken protection.\")\n"
    "\n"
    "    # DKIM\n"
)
NEW = (
    "    add_bullet(doc, \"Overly broad SPF records (such as including large cloud provider IP ranges) weaken protection.\")\n"
    "    add_bullet(\n"
    "        doc,\n"
    "        \"The scanner scores the SPF qualifier, not merely the record's \"\n"
    "        \"presence. A terminal -all (fail) is the secure target; ~all (soft-\"\n"
    "        \"fail) and ?all (neutral) do not instruct receivers to reject spoofed \"\n"
    "        \"mail (RFC 7208; NIST SP 800-177 Trustworthy Email; M3AAWG). Because a \"\n"
    "        \"DMARC policy of quarantine or reject governs the disposition of \"\n"
    "        \"failing mail regardless of the SPF qualifier, the soft-qualifier \"\n"
    "        \"penalty is applied only when DMARC is not at enforcement - so a \"\n"
    "        \"deliberate ~all paired with an enforcing DMARC policy, a common and \"\n"
    "        \"valid configuration for large senders, is not penalised. A bare all \"\n"
    "        \"is treated as +all (Pass) per RFC 7208. The penalty magnitudes are \"\n"
    "        \"conservative and calibration-gated.\"\n"
    "    )\n"
    "\n"
    "    # DKIM\n"
)
assert s.count(OLD) == 1, ("part3 SPF bullet anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1)

assert "\r" not in s
assert "The scanner scores the SPF qualifier" in s
ast.parse(s)
with open(P3, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P3, encoding="utf-8").read())
print("OK part3_email_network.py: item #18b manual-lock bullet added (AST valid).")
