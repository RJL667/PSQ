# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SHIP (2026-06-09): fix the scan-form sub-industry taxonomy so it maps 1:1 to the
server-side canonical SIC labels (memory ACTION, flagged 2026-06-04).

The searchable dropdown (templates/index.html SUB_INDUSTRIES) used SHORT display
labels that did not exact-match the server keys. Everything server-side keys on the
FULL SIC label by exact string:
  - INDUSTRY_BI_FACTOR (BI factor, scoring_analytics.py:2415) -> silent fallback to
    the coarse industry factor (41/110 entries fell back; 6 materially, worst Media
    "Printing And Publishing" 0.5 -> 1.0);
  - SECTOR_FRAMEWORKS / _sector_cat_stack (cat regulatory stack);
  - flag_inference B2C_SUB_INDUSTRY_LABELS + ACCOUNTABLE_INSTITUTION_LABELS
    (b2c / FIC accountable-institution auto-detection).
So the abbreviations silently degraded BI, the cat stack, AND pre-flight inference.

Fix WITHOUT changing the visible UI: carry a canonical `key` per dropdown entry and
submit THAT (display `label` unchanged). CRLF-safe. Self-verifying: every resulting
key must exist in INDUSTRY_BI_FACTOR with a BI value equal to the dropdown's `bi`.

Run from security_scanner/: py tooling/_apply_subindustry_canonical_keys.py
"""
import ast, os, re, json, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from scoring_analytics import FinancialImpactCalculator as F
BI = F.INDUSTRY_BI_FACTOR

# Canonical key for each SHORT dropdown label that is not already a BI key.
# Derived by inspection of the SIC taxonomy; the asserts below prove correctness.
OVERRIDE = {
    "Fishing hunting and trapping": "Agriculture, Forestry, And Fishing- Fishing hunting and trapping",
    "Mining And Quarrying Of Nonmetallic Minerals": "Mining And Quarrying Of Nonmetallic Minerals, Except Fuels",
    "Building Construction General Contractors": "Building Construction General Contractors And Operative Builders",
    "Heavy Construction Contractors": "Heavy Construction Other Than Building Construction Contractors",
    "Apparel And Finished Products": "Apparel And Other Finished Products Made From Fabrics And Similar Materials",
    "Lumber And Wood Products": "Lumber And Wood Products, Except Furniture",
    "Petroleum Refining": "Petroleum Refining And Related Industries",
    "Rubber And Plastics Products": "Rubber And Miscellaneous Plastics Products",
    "Leather Products": "Leather And Leather Products",
    "Stone, Clay, Glass, And Concrete": "Stone, Clay, Glass, And Concrete Products",
    "Fabricated Metal Products": "Fabricated Metal Products, Except Machinery And Transportation Equipment",
    "Industrial And Commercial Machinery": "Industrial And Commercial Machinery And Computer Equipment",
    "Electronic And Electrical Equipment": "Electronic And Other Electrical Equipment And Components, Except Computer Equipment",
    "Measuring And Controlling Instruments": "Measuring, Analyzing, And Controlling Instruments; Photographic, Medical And Optical Goods; Watches And Clocks",
    "Miscellaneous Manufacturing": "Miscellaneous Manufacturing Industries",
    "Industrial Machinery": "Industrial And Commercial Machinery And Computer Equipment",
    "Local And Suburban Transit": "Local And Suburban Transit And Interurban Highway Passenger Transportation",
    "Motor Freight And Warehousing": "Motor Freight Transportation And Warehousing",
    "Pipelines": "Pipelines, Except Natural Gas",
    "Wholesale Trade - Durable Goods": "Wholesale Trade-durable Goods",
    "Wholesale Trade - Non-durable Goods": "Wholesale Trade-non-durable Goods",
    "Building Materials And Hardware": "Building Materials, Hardware, Garden Supply, And Mobile Home Dealers",
    "Automotive Dealers And Service Stations": "Automotive Dealers And Gasoline Service Stations",
    "Home Furniture And Equipment Stores": "Home Furniture, Furnishings, And Equipment Stores",
    "Security And Commodity Brokers": "Security And Commodity Brokers, Dealers, Exchanges, And Services",
    "Hotels And Lodging": "Hotels, Rooming Houses, Camps, And Other Lodging Places",
    "Automotive Repair And Parking": "Automotive Repair, Services, And Parking",
    "Amusement And Recreation": "Amusement And Recreation Services",
    "Museums And Galleries": "Museums, Art Galleries, And Botanical And Zoological Gardens",
    "Engineering And Research Services": "Engineering, Accounting, Research, Management, And Related Services",
    "Printing And Publishing": "Printing, Publishing, And Allied Industries",
    "Executive And General Government": "Executive, Legislative, And General Government, Except Finance",
    "Public Finance And Monetary Policy": "Public Finance, Taxation, And Monetary Policy",
    "Administration Of Human Resources": "Administration Of Human Resource Programs",
    "Environmental Quality Programs": "Administration Of Environmental Quality And Housing Programs",
    "Economic Programs": "Administration Of Economic Programs",
}

HTML = os.path.join(ROOT, "templates", "index.html")
s = open(HTML, encoding="utf-8").read()
assert "\r" not in s, "expected universal-newline read to strip CR"

# --- 1. Rebuild SUB_INDUSTRIES with a canonical `key` per entry. ---
m = re.search(r"(const SUB_INDUSTRIES = )(\{.*?\})(;)", s, re.S)
assert m, "SUB_INDUSTRIES literal not found"
SUB = json.loads(m.group(2))
n_entries = n_keyed = 0
for industry, subs in SUB.items():
    for e in subs:
        n_entries += 1
        label, bi = e["label"], e["bi"]
        key = label if label in BI else OVERRIDE.get(label)
        assert key is not None, f"no canonical key for {industry!r}/{label!r}"
        assert key in BI, f"key {key!r} not in INDUSTRY_BI_FACTOR ({industry}/{label})"
        assert abs(BI[key] - bi) < 1e-9, f"BI mismatch {label!r}->{key!r}: table {BI[key]} vs dropdown {bi}"
        # rebuild in label/key/bi order
        e.clear(); e["label"] = label; e["key"] = key; e["bi"] = bi
        n_keyed += 1
new_literal = json.dumps(SUB, ensure_ascii=False, separators=(",", ":"))
s = s[:m.start()] + m.group(1) + new_literal + m.group(3) + s[m.end():]

# --- 2. Submit the canonical key (display label is unchanged). ---
OLD_JS = "        hiddenInput.value = s.label;\n        searchInput.value = s.label;\n"
NEW_JS = "        hiddenInput.value = s.key || s.label;  // submit canonical SIC key (1:1 with server lookups)\n        searchInput.value = s.label;                  // display the short label\n"
assert s.count(OLD_JS) == 1, ("dropdown click handler", s.count(OLD_JS))
s = s.replace(OLD_JS, NEW_JS, 1)

with open(HTML, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print(f"OK index.html: keyed {n_keyed}/{n_entries} sub-industry entries (all verified 1:1 "
      f"with INDUSTRY_BI_FACTOR) + dropdown now submits the canonical key.")
