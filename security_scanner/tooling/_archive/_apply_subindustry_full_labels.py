# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SHIP (2026-06-09): show the FULL canonical SIC labels in the scan-form
sub-industry dropdown (user request). Collapses the short-label + canonical-`key`
indirection from 699f0d0: each entry becomes {label: <canonical SIC>, bi: <value>}
so the option text the broker sees IS the server-side lookup key. Reverts the JS
submit line to use s.label (which is now canonical). CRLF-safe + self-verifying:
every label must exist in INDUSTRY_BI_FACTOR with a matching BI.
Run from security_scanner/: py tooling/_apply_subindustry_full_labels.py
"""
import os, re, json, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from scoring_analytics import FinancialImpactCalculator as F
BI = F.INDUSTRY_BI_FACTOR

HTML = os.path.join(ROOT, "templates", "index.html")
s = open(HTML, encoding="utf-8").read()
assert "\r" not in s, "expected universal-newline read to strip CR"

# --- 1. Rebuild SUB_INDUSTRIES: label := canonical key; drop the redundant key. ---
m = re.search(r"(const SUB_INDUSTRIES = )(\{.*?\})(;)", s, re.S)
assert m, "SUB_INDUSTRIES literal not found"
SUB = json.loads(m.group(2))
n = 0
for industry, subs in SUB.items():
    rebuilt = []
    for e in subs:
        canonical = e.get("key") or e.get("label")
        bi = e["bi"]
        assert canonical in BI, f"{industry}/{canonical!r} not in INDUSTRY_BI_FACTOR"
        assert abs(BI[canonical] - bi) < 1e-9, f"BI mismatch {canonical!r}: table {BI[canonical]} vs {bi}"
        rebuilt.append({"label": canonical, "bi": bi})
        n += 1
    subs[:] = rebuilt
new_literal = json.dumps(SUB, ensure_ascii=False, separators=(",", ":"))
s = s[:m.start()] + m.group(1) + new_literal + m.group(3) + s[m.end():]

# --- 2. Submit s.label (now the canonical SIC key); display it too. ---
OLD_JS = ("        hiddenInput.value = s.key || s.label;  // submit canonical SIC key (1:1 with server lookups)\n"
          "        searchInput.value = s.label;                  // display the short label\n")
NEW_JS = ("        hiddenInput.value = s.label;  // label IS the canonical SIC key (1:1 with server lookups)\n"
          "        searchInput.value = s.label;  // display the full canonical label\n")
assert s.count(OLD_JS) == 1, ("dropdown click handler", s.count(OLD_JS))
s = s.replace(OLD_JS, NEW_JS, 1)

with open(HTML, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print(f"OK index.html: {n} sub-industry entries now display full canonical SIC labels "
      f"(label == lookup key); dropdown submits s.label.")
