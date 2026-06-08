# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (2026-06-08): update generate_gap_analysis.cjs for the 2026-06 calibration
session - add a change-log row (CAL-001) and fix the stale GAP-005 downtime (22 -> 25
days). CRLF-safe (text-mode read normalises; binary write restores). NOT shipped."""
import os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = os.path.join(ROOT, "generate_gap_analysis.cjs")
s = open(P, encoding="utf-8").read()
assert "\r" not in s
n = 0

# 1. Add changeLogRow2 after changeLogRow1.
OLD = (
    "  \"Implemented\"\n"
    "];\n"
    "\n"
    "function makeChangeLogTable() {\n"
)
NEW = (
    "  \"Implemented\"\n"
    "];\n"
    "\n"
    "const changeLogRow2 = [\n"
    "  \"2026-06-05\",\n"
    "  \"CAL-001\",\n"
    "  \"Calibration session: cyber-incident bands re-fit, SPF/DMARC remediation magnitudes, availability frequency and severity, plus an HTML-report security fix.\",\n"
    "  \"Tightened the provisional values shipped on 2026-06-05 against empirical anchors (Coalition 2025 claims frequency, Verizon DBIR 2025, Uptime Institute outage analysis, CISA BOD 18-01). Availability p_interruption was FAIR-anchored (previously indicative / not calibrated); the BI revenue-impact factor was separated into a duration-independent 50% recovery average for rebuilds and an 85% acute factor for DDoS / short outages, decoupled from the drifting recovery-period figure.\",\n"
    "  \"Cyber-incident bands 5/15/30 to 8/18/28 (relative-posture relabel). SPF/DMARC remediation credits trimmed about 25% (4:2:1 retained). Availability range re-anchored to roughly 3-17% (was 5-20%) with the WAF mis-attribution fixed. BI net approximately flat but correctly decomposed. Separately fixed a script-tag breakout in the HTML report (raw-JSON dump and stored-XSS vector).\",\n"
    "  \"Implemented\"\n"
    "];\n"
    "\n"
    "function makeChangeLogTable() {\n"
)
assert s.count(OLD) == 1, ("changeLogRow1 close", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 2. Build a second data row and include it in the table.
OLD = (
    "  const dataRow = new TableRow({\n"
    "    children: changeLogRow1.map((val, i) => dataCell(val, changeLogCols[i], false))\n"
    "  });\n"
)
NEW = (
    "  const dataRow = new TableRow({\n"
    "    children: changeLogRow1.map((val, i) => dataCell(val, changeLogCols[i], false))\n"
    "  });\n"
    "  const dataRow2 = new TableRow({\n"
    "    children: changeLogRow2.map((val, i) => dataCell(val, changeLogCols[i], true))\n"
    "  });\n"
)
assert s.count(OLD) == 1, ("dataRow build", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

OLD = "    rows: [headerRow, dataRow]\n"
NEW = "    rows: [headerRow, dataRow, dataRow2]\n"
assert s.count(OLD) == 1, ("changelog rows array", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 3. Fix the stale GAP-005 downtime (22 -> 25 days).
OLD = "Global average downtime days used (22 for ransomware)"
NEW = "Global average downtime days used (25 for ransomware)"
assert s.count(OLD) == 1, ("GAP-005 downtime", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

with open(P, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print(f"OK generate_gap_analysis.cjs: {n} edits (CAL-001 change-log row + GAP-005 22->25).")
