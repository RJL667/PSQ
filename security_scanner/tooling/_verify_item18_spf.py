# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX verification (read-only) for item #18 SPF-qualifier scoring. Tests the
qualifier extraction regex + EmailSecurityChecker._calculate_score truth table
directly (no DNS needed). NOT shipped."""
import os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
from checkers_core import EmailSecurityChecker

# --- 1. qualifier extraction (mirrors _check_spf) ---
def qual(txt):
    m = re.search(r"(?:^|\s)([-~?+]?)all(?:\s|$)", txt)
    return (m.group(1) or "+") if m else None

print("=== SPF qualifier extraction (RFC 7208: bare all == +) ===")
for rec, exp in [("v=spf1 include:_spf.google.com ~all", "~"),
                 ("v=spf1 mx -all", "-"),
                 ("v=spf1 a ?all", "?"),
                 ("v=spf1 include:x.com +all", "+"),
                 ("v=spf1 include:x.com all", "+"),       # bare all == Pass
                 ("v=spf1 redirect=_spf.x.com", None),     # redirect, no all
                 ("v=spf1 ip4:1.2.3.0/24 -all", "-")]:
    got = qual(rec); ok = "OK " if got == exp else "FAIL"
    print(f"  {ok} qual={str(got):4s} (exp {str(exp):4s})  <- {rec}")

# --- 2. _calculate_score truth table ---
chk = EmailSecurityChecker()
def spf(present=True, valid=True, q="-", dangerous=False, lookups=0):
    return {"present": present, "valid": valid, "all_qualifier": q,
            "dangerous": dangerous, "has_redirect": False,
            "dns_lookups": lookups, "exceeds_lookup_limit": lookups > 10}
def dmarc(present=True, policy="reject", pct=100):
    return {"present": present, "policy": policy, "pct": pct,
            "partial_enforcement": pct < 100, "subdomain_policy": policy, "has_reporting": True}
DK_YES = {"selectors_found": ["google"]}; DK_NO = {"selectors_found": []}

print("\n=== _calculate_score truth table (start 10/10; DKIM present unless noted) ===")
cases = [
    ("SECURE: -all + p=reject",            spf(q="-"), dmarc(policy="reject"),     DK_YES, 10),
    ("GMAIL-style: ~all + p=none",         spf(q="~"), dmarc(policy="none"),       DK_YES, 7),   # -2 dmarc none, -1 ~all
    ("GUARD: ~all + p=reject (mature)",    spf(q="~"), dmarc(policy="reject"),     DK_YES, 10),  # NOT penalised
    ("GUARD: ~all + p=quarantine",         spf(q="~"), dmarc(policy="quarantine"), DK_YES, 9),   # -1 quarantine, ~all NOT penalised
    ("NEUTRAL: ?all + no DMARC",           spf(q="?"), dmarc(present=False, policy=None), DK_YES, 4),  # -4 dmarc absent, -2 ?all
    ("~all + no DMARC",                    spf(q="~"), dmarc(present=False, policy=None), DK_YES, 5),  # -4, -1
    ("DANGEROUS: +all (bare-all path)",    spf(q="+", dangerous=True), dmarc(policy="reject"), DK_YES, 7),  # -3 dangerous
    ("ABSENT SPF + p=reject",              spf(present=False, valid=False, q=None), dmarc(policy="reject"), DK_YES, 7),  # -3 absent
    ("?all + p=none + no DKIM",            spf(q="?"), dmarc(policy="none"),       DK_NO, 4),   # -2 none, -2 ?all, -2 dkim
]
allok = True
for label, sp, dm, dk, exp in cases:
    score, issues = chk._calculate_score(sp, dm, dk)
    ok = "OK  " if score == exp else "FAIL"
    if score != exp: allok = False
    print(f"  {ok} score={score:2d} (exp {exp:2d})  {label}")
    for i in issues:
        if "SPF" in i: print(f"          - {i}")

print("\n" + ("ALL PASS" if allok else "*** FAILURES ***"))
