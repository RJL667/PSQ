# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SHIP (2026-06-09): complete the scan-form industry taxonomy (user: "full
selection list, no aliases", keep calibration).
  1. Add 3 missing SIC divisions to the industry <select>: Construction, Mining,
     Wholesale Trade (alphabetical). They have calibrated RSI/BI (+ SA_INDUSTRY_COSTS
     added in the sibling mutator) and existing sub-industry groups.
  2. SUB_INDUSTRIES:
     - give "Industrial / Manufacturing" the FULL canonical manufacturing sub-list
       (it only carried 4 of 20); source = the previously-unreachable "Manufacturing"
       group. Manufacturers can now pick any manufacturing sub-industry.
     - delete the dead/unreachable duplicate groups "Manufacturing", "Finance"
       (subset of Financial Services), "Tech" (== Technology).
CRLF-safe + self-verifying: after the change every SUB_INDUSTRIES entry resolves
1:1 in INDUSTRY_BI_FACTOR and the SUB_INDUSTRIES keys exactly match the industry
<select> options that have a sub-list.
Run from security_scanner/: py tooling/_apply_index_sic_industries.py
"""
import os, re, json, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from scoring_analytics import FinancialImpactCalculator as F
BI = F.INDUSTRY_BI_FACTOR

HTML = os.path.join(ROOT, "templates", "index.html")
s = open(HTML, encoding="utf-8").read()
assert "\r" not in s, "expected universal-newline read to strip CR"

# --- 1. Insert the 3 missing <option>s alphabetically. ---
INSERTS = [
    ('            <option value="Communications">Communications</option>\n',
     '            <option value="Communications">Communications</option>\n'
     '            <option value="Construction">Construction</option>\n'),
    ('            <option value="Media">Media</option>\n',
     '            <option value="Media">Media</option>\n'
     '            <option value="Mining">Mining</option>\n'),
    ('            <option value="Transportation">Transportation</option>\n',
     '            <option value="Transportation">Transportation</option>\n'
     '            <option value="Wholesale Trade">Wholesale Trade</option>\n'),
]
for old, new in INSERTS:
    assert s.count(old) == 1, ("option anchor", old.strip(), s.count(old))
    s = s.replace(old, new, 1)

# Collect the final <select> option values (excluding the blank "Other").
sel_block = re.search(r'<select[^>]*id="industry"[^>]*>(.*?)</select>', s, re.S).group(1)
sel_opts = set(re.findall(r'<option[^>]*value="([^"]*)"', sel_block)) - {""}

# --- 2. Reconcile SUB_INDUSTRIES. ---
m = re.search(r"(const SUB_INDUSTRIES = )(\{.*?\})(;)", s, re.S)
assert m, "SUB_INDUSTRIES literal not found"
SUB = json.loads(m.group(2))

# Give Industrial / Manufacturing the full manufacturing sub-list.
assert "Manufacturing" in SUB and "Industrial / Manufacturing" in SUB
SUB["Industrial / Manufacturing"] = SUB["Manufacturing"]
# Delete dead / duplicate groups.
for dead in ("Manufacturing", "Finance", "Tech"):
    SUB.pop(dead, None)

# Verify: every entry resolves 1:1, and SUB keys == select options (minus Other).
for industry, subs in SUB.items():
    for e in subs:
        lbl = e["label"]
        assert lbl in BI, f"{industry}/{lbl!r} not in INDUSTRY_BI_FACTOR"
        assert abs(BI[lbl] - e["bi"]) < 1e-9, f"BI mismatch {lbl!r}: {BI[lbl]} vs {e['bi']}"
sub_keys = set(SUB.keys())
only_sub = sub_keys - (sel_opts - {"Other"})
only_sel = (sel_opts - {"Other"}) - sub_keys
assert not only_sub, f"SUB_INDUSTRIES groups with no matching <option>: {sorted(only_sub)}"
assert not only_sel, f"<option>s with no sub-industry group: {sorted(only_sel)}"

new_literal = json.dumps(SUB, ensure_ascii=False, separators=(",", ":"))
s = s[:m.start()] + m.group(1) + new_literal + m.group(3) + s[m.end():]

with open(HTML, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print(f"OK index.html: +3 industry options; Industrial/Manufacturing now has "
      f"{len(SUB['Industrial / Manufacturing'])} sub-industries; dropped dead groups; "
      f"{len(sub_keys)} SUB groups == {len(sel_opts)-1} non-Other options.")
