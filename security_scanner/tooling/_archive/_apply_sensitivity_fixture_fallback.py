# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (2026-06-08): make sensitivity_analysis_v2.py reproducible when scans.db
has no cached phishield scan (fresh checkout / CI) by falling back to the committed
fixture. CRLF-safe. NOT shipped by this script."""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = os.path.join(ROOT, "sensitivity_analysis_v2.py")
s = open(P, encoding="utf-8").read()
assert "\r" not in s
OLD = (
    "row = conn.execute(\n"
    "    \"SELECT results FROM scans WHERE domain LIKE '%phishield%' ORDER BY created_at DESC LIMIT 1\"\n"
    ").fetchone()\n"
    "results = json.loads(row['results'])\n"
    "cats = results.get('categories', {})\n"
)
NEW = (
    "row = conn.execute(\n"
    "    \"SELECT results FROM scans WHERE domain LIKE '%phishield%' ORDER BY created_at DESC LIMIT 1\"\n"
    ").fetchone()\n"
    "if row and row['results']:\n"
    "    results = json.loads(row['results'])\n"
    "else:\n"
    "    # Fallback: committed fixture (DB not populated, e.g. fresh checkout / CI).\n"
    "    _fx = os.path.join(os.path.dirname(os.path.abspath(__file__)),\n"
    "                       'test_fixtures', 'phishield_R10M_finance_2026-05-15.json')\n"
    "    with open(_fx, encoding='utf-8') as _f:\n"
    "        results = json.load(_f)\n"
    "cats = results.get('categories', {})\n"
)
assert s.count(OLD) == 1, ("anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1)
ast.parse(s)
with open(P, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P, encoding="utf-8").read())
print("OK sensitivity_analysis_v2.py: fixture fallback added (AST valid, CRLF).")
