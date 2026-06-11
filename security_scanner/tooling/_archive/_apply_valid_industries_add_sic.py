# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SHIP (2026-06-09): add Mining / Construction / Wholesale Trade to app.py
VALID_INDUSTRIES. Without this, an incoming industry not in the list is silently
coerced to "Other" (app.py ~L834), so adding them to the form select alone would
not take effect. CRLF-safe. Run from security_scanner/: py tooling/_apply_valid_industries_add_sic.py
"""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app.py")
s = open(APP, encoding="utf-8").read()
assert "\r" not in s, "expected universal-newline read to strip CR"

OLD = '    "Agriculture", "Communications", "Consumer", "Education", "Energy",\n'
NEW = ('    "Agriculture", "Mining", "Construction", "Wholesale Trade",\n'
       '    "Communications", "Consumer", "Education", "Energy",\n')
assert s.count(OLD) == 1, ("VALID_INDUSTRIES first row", s.count(OLD))
s = s.replace(OLD, NEW, 1)

ast.parse(s)
with open(APP, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(APP, encoding="utf-8").read())
print("OK app.py: added Mining / Construction / Wholesale Trade to VALID_INDUSTRIES.")
