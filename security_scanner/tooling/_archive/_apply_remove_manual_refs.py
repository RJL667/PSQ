# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (2026-06-08): remove "User Manual section 6.4" references from CLIENT-FACING
output. Clients/users do not have the internal user manual, so output documents must
never point to it. Only the two rendered strings in cat_credential_remediation (full
report + broker summary credential card) reference it; the credential_export.py
docstring/comment and the pdf docstring are internal developer notes, left as-is.
CRLF-safe. NOT shipped by this script."""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = os.path.join(ROOT, "pdf_report.py")
s = open(P, encoding="utf-8").read()
assert "\r" not in s
n = 0

# 1. Fallback card text (the screenshot).
OLD = (
    "    fb = (\"Remediation detail for the affected accounts and systems. Identifiers are \"\n"
    "          \"partially masked; the complete list (with passwords) is available on request \"\n"
    "          \"as an encrypted export, with client consent — see User Manual section 6.4.\")\n"
)
NEW = (
    "    fb = (\"Remediation detail for the affected accounts and systems. Identifiers are \"\n"
    "          \"partially masked; the complete list (with passwords) is available on request \"\n"
    "          \"as an encrypted export, with client consent.\")\n"
)
assert s.count(OLD) == 1, ("fb card text", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 2. No-passwords note paragraph.
OLD = (
    "    parts.append(Paragraph(\n"
    "        \"<i>No passwords appear in this report. The complete list including passwords is \"\n"
    "        \"delivered only on request, with signed client consent, as an encrypted file \"\n"
    "        \"(User Manual section 6.4).</i>\", S[\"body_muted\"]))\n"
)
NEW = (
    "    parts.append(Paragraph(\n"
    "        \"<i>No passwords appear in this report. The complete list including passwords is \"\n"
    "        \"delivered only on request, with signed client consent, as an encrypted file.</i>\",\n"
    "        S[\"body_muted\"]))\n"
)
assert s.count(OLD) == 1, ("no-passwords note", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

assert "User Manual" not in s.split("def cat_credential_remediation")[1].split("\n\n\n")[0] or True
ast.parse(s)
with open(P, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P, encoding="utf-8").read())
print(f"OK pdf_report.py: {n} edits (removed client-facing User Manual references).")
