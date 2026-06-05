# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (item #18, checker accuracy fix): SPF presence != SPF protection.

Today EmailSecurityChecker._calculate_score penalises only absent SPF and `+all`;
`~all` (soft-fail) and `?all` (neutral) score identically to the secure `-all`
(fail) terminal. This wires the SPF *qualifier* into the score, GATED on DMARC not
being at enforcement (a `~all` + DMARC quarantine/reject is a valid mature-sender
config and is NOT penalised — DMARC governs disposition regardless of the SPF
qualifier).

Anchoring channel = PROBABILITY (channel 1): email_security score -> email_risk ->
weight 0.06 -> overall risk score -> vulnerability -> p_breach. One signal, one
channel. Data anchors: RFC 7208 sec 4.6.2 / 4.7 (`-all` Fail is the enforcing
terminal; bare `all` == `+all` Pass); NIST SP 800-177 (Trustworthy Email); M3AAWG.
The two magnitudes (~all -1, ?all -2) are CONSERVATIVE and CALIBRATION-GATED (they
move p_breach) — anchored between the existing `invalid` (-1) and `absent/+all`
(-3) rungs by qualifier strength; tune in the formal calibration session.

Also fixes a latent bug: `dangerous` was `"+all" in txt`, which MISSED a bare `all`
(implicit Pass per RFC 7208) — now `all_qualifier == "+"` catches both.

CRLF-preserving mutator + AST validation. NOT shipped."""
import ast
import os

CC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "checkers_core.py")
s = open(CC, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

# ---------------------------------------------------------------------------
# 1. _check_spf: extract + store the `all` qualifier; make `dangerous` catch a
#    bare `all` too (implicit Pass). ASCII-only anchor (no regex line, no em-dash).
# ---------------------------------------------------------------------------
OLD1 = (
    "                    dns_lookups = self._count_spf_lookups(txt, depth=0)\n"
    "                    return {\n"
    "                        \"present\": True, \"valid\": valid, \"record\": txt,\n"
    "                        \"dangerous\": \"+all\" in txt,\n"
    "                        \"has_redirect\": has_redirect,\n"
    "                        \"dns_lookups\": dns_lookups,\n"
    "                        \"exceeds_lookup_limit\": dns_lookups > 10,\n"
    "                    }\n"
)
NEW1 = (
    "                    dns_lookups = self._count_spf_lookups(txt, depth=0)\n"
    "                    # Capture the `all` qualifier (-/~/?/+). RFC 7208 sec 4.6.2:\n"
    "                    # a bare `all` carries the implicit `+` (Pass) qualifier, i.e.\n"
    "                    # it is equivalent to `+all` and equally dangerous - map it so\n"
    "                    # it is not read as benign.\n"
    "                    _allm = re.search(r\"(?:^|\\s)([-~?+]?)all(?:\\s|$)\", txt)\n"
    "                    all_qualifier = (_allm.group(1) or \"+\") if _allm else None\n"
    "                    return {\n"
    "                        \"present\": True, \"valid\": valid, \"record\": txt,\n"
    "                        \"all_qualifier\": all_qualifier,\n"
    "                        \"dangerous\": all_qualifier == \"+\",\n"
    "                        \"has_redirect\": has_redirect,\n"
    "                        \"dns_lookups\": dns_lookups,\n"
    "                        \"exceeds_lookup_limit\": dns_lookups > 10,\n"
    "                    }\n"
)
assert s.count(OLD1) == 1, ("_check_spf return anchor", s.count(OLD1))
s = s.replace(OLD1, NEW1, 1)

# ---------------------------------------------------------------------------
# 2. _check_spf fallback return: carry all_qualifier=None for shape consistency.
# ---------------------------------------------------------------------------
OLD2 = (
    "        return {\"present\": False, \"valid\": False, \"record\": None, \"dangerous\": False,\n"
    "                \"has_redirect\": False, \"dns_lookups\": 0, \"exceeds_lookup_limit\": False}\n"
)
NEW2 = (
    "        return {\"present\": False, \"valid\": False, \"record\": None, \"all_qualifier\": None,\n"
    "                \"dangerous\": False, \"has_redirect\": False, \"dns_lookups\": 0,\n"
    "                \"exceeds_lookup_limit\": False}\n"
)
assert s.count(OLD2) == 1, ("_check_spf fallback anchor", s.count(OLD2))
s = s.replace(OLD2, NEW2, 1)

# ---------------------------------------------------------------------------
# 3. _calculate_score: add the DMARC-gated soft-qualifier penalty as an `else`
#    on the existing SPF if/elif chain. ASCII-only anchor (bridge to the lookup
#    check); does NOT touch the existing em-dash issue strings.
# ---------------------------------------------------------------------------
OLD3 = (
    "            score -= 1; issues.append(\"SPF record may be invalid (no 'all' or 'redirect=' mechanism)\")\n"
    "        if spf.get(\"exceeds_lookup_limit\"):\n"
)
NEW3 = (
    "            score -= 1; issues.append(\"SPF record may be invalid (no 'all' or 'redirect=' mechanism)\")\n"
    "        else:\n"
    "            # Present + valid + not '+all': the `all` qualifier sets the\n"
    "            # enforcement strength. `-all` (fail) is the secure terminal (RFC 7208;\n"
    "            # NIST SP 800-177; M3AAWG); `~all` (soft-fail) and `?all` (neutral) do\n"
    "            # NOT instruct receivers to reject spoofed mail. A DMARC quarantine/\n"
    "            # reject policy governs failing-mail disposition REGARDLESS of the SPF\n"
    "            # qualifier, so the soft-qualifier penalty is gated on DMARC NOT being\n"
    "            # at enforcement (a deliberate `~all` + enforcing DMARC, common for\n"
    "            # large senders, is correct and is not penalised). Magnitudes are\n"
    "            # conservative + calibration-gated (they move p_breach).\n"
    "            _dmarc_enforcing = dmarc.get(\"present\") and dmarc.get(\"policy\") in (\"quarantine\", \"reject\")\n"
    "            _qual = spf.get(\"all_qualifier\")\n"
    "            if not _dmarc_enforcing and _qual == \"?\":\n"
    "                score -= 2; issues.append(\"SPF ends with '?all' (neutral) and no enforcing DMARC policy - provides no spoofing protection\")\n"
    "            elif not _dmarc_enforcing and _qual == \"~\":\n"
    "                score -= 1; issues.append(\"SPF ends with '~all' (soft-fail) and no enforcing DMARC policy - does not instruct receivers to reject spoofed mail\")\n"
    "        if spf.get(\"exceeds_lookup_limit\"):\n"
)
assert s.count(OLD3) == 1, ("_calculate_score SPF branch anchor", s.count(OLD3))
s = s.replace(OLD3, NEW3, 1)

# ---------------------------------------------------------------------------
# Validate + write (CRLF-preserving).
# ---------------------------------------------------------------------------
assert "\r" not in s
assert "\"all_qualifier\": all_qualifier," in s
assert "_dmarc_enforcing = dmarc.get(\"present\")" in s
ast.parse(s)
with open(CC, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
chk = open(CC, encoding="utf-8").read()
ast.parse(chk)
print("OK checkers_core.py: item #18 SPF qualifier scoring (DMARC-gated) wired (AST valid).")
