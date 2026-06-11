#!/usr/bin/env python3
"""SANDBOX one-off (task #6): RSI factor rebalance in RansomwareIndex.calculate().

Rebalances the ransomware-susceptibility factor weights to the SA-prioritised
evidence (Sophos SA 2025: credentials 34% #1 > vuln 28% #2 > email 22% #3;
CISA: RDP is a SURFACE breached via creds/brute/vuln, not an independent root
cause). Six anchored edits (fail-safe; assert count==1; CRLF-preserving):

  RDP exposed           +0.25  -> +0.20   (surface, trim; keep observ. premium)
  Exposed DB port (ea)  +0.10  -> +0.08   cap 0.20 -> 0.16  (surface, overlaps RDP)
  Credential CRITICAL   +0.20  -> +0.22   (#1 SA root cause >= RDP surface)
  Credential HIGH       +0.15  -> +0.18   (input bug fixed by K1-K7 model, task #5)
  CISA KEV CVE (ea)     +0.08  -> +0.10   cap 0.20 -> 0.24  (vuln co-dominant)
  No WAF                +0.05  -> +0.04   (hygiene proxy + buggy input)
  Weak SSL              +0.05  -> +0.03   (rarely entry vector + sslyze bug)

HOLD: base 0.05, diminishing knee 0.50, band map, MEDIUM credential (the K-model
redefined MEDIUM as a genuine medium-confidence signal, not email-only), EPSS,
other-CVE, DMARC, supply-chain cap. See docs/calibration_prep/03_rsi_factors.md.
NOT shipped (FIN-9 calibration prep, 2026-06-03).
"""
import os

SA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

EDITS = []

# --- A) RDP +0.25 -> +0.20 (and rewrite the now-wrong "strongest" comment) ---
EDITS.append((
    "        # RDP exposed: +0.25 (strongest single signal — #1 ransomware vector)\n"
    "        if categories.get(\"vpn_remote\", {}).get(\"rdp_exposed\"):\n"
    "            base += 0.25\n"
    "            factors.append({\"factor\": \"RDP (port 3389) exposed to internet\", \"impact\": 0.25, \"priority\": 1})\n",
    "        # RDP exposed: +0.20. A strong CONFIRMED-OBSERVABLE signal but a remote-\n"
    "        # access SURFACE, not an independent root cause - CISA #StopRansomware\n"
    "        # shows RDP is breached *via* stolen creds / brute-force / VPN-software\n"
    "        # exploit, overlapping the credential + vuln channels. Trimmed from +0.25\n"
    "        # (FIN-9) so the dominant SA root cause (credentials 34%, Sophos SA 2025)\n"
    "        # is >= the RDP surface, while keeping an observability premium over the\n"
    "        # probabilistic credential signal. Range 0.18-0.22.\n"
    "        if categories.get(\"vpn_remote\", {}).get(\"rdp_exposed\"):\n"
    "            base += 0.20\n"
    "            factors.append({\"factor\": \"RDP (port 3389) exposed to internet\", \"impact\": 0.20, \"priority\": 1})\n",
))

# --- B) DB port +0.10/cap0.20 -> +0.08/cap0.16 -----------------------------
EDITS.append((
    "        # Exposed database/service ports: +0.10 each, cap 0.20\n"
    "        exposed = categories.get(\"high_risk_protocols\", {}).get(\"exposed_services\", [])\n"
    "        db_ports = [s for s in exposed if s.get(\"port\") in (27017, 6379, 9200, 5432, 1433, 5984, 3306)]\n"
    "        db_impact = min(0.20, len(db_ports) * 0.10)\n",
    "        # Exposed database/service ports: +0.08 each, cap 0.16. Trimmed from\n"
    "        # +0.10/0.20 (FIN-9): a DB port is an exposure SURFACE that overlaps the\n"
    "        # RDP/remote-access narrative, not a named ransomware root cause, and it\n"
    "        # is better weighted in DBI (data-breach) than here. Range 0.06-0.08.\n"
    "        exposed = categories.get(\"high_risk_protocols\", {}).get(\"exposed_services\", [])\n"
    "        db_ports = [s for s in exposed if s.get(\"port\") in (27017, 6379, 9200, 5432, 1433, 5984, 3306)]\n"
    "        db_impact = min(0.16, len(db_ports) * 0.08)\n",
))

# --- C) Credential CRITICAL +0.20 -> +0.22, HIGH +0.15 -> +0.18 (MEDIUM held) ---
EDITS.append((
    "        if cred_level == \"CRITICAL\":\n"
    "            # Active infostealer or real-time credential exfiltration\n"
    "            base += 0.20\n"
    "            factors.append({\"factor\": \"CRITICAL credential risk — active compromise detected (infostealer/dark web)\", \"impact\": 0.20, \"priority\": 1})\n"
    "        elif cred_level == \"HIGH\":\n"
    "            # Recent breaches with passwords, dark web mentions, or high volume leaks\n"
    "            base += 0.15\n"
    "            factors.append({\"factor\": \"HIGH credential risk — recent breaches with password exposure or dark web trading\", \"impact\": 0.15, \"priority\": 1})\n",
    "        if cred_level == \"CRITICAL\":\n"
    "            # Active infostealer / fresh high-confidence capture. CRITICAL is now\n"
    "            # gated by the K1-K7 confidence model (W>=4 or a confirmed live HR\n"
    "            # infection), so the tier is genuinely active. +0.20 -> +0.22 (FIN-9)\n"
    "            # so the #1 SA root cause (credentials 34%) >= the RDP surface (0.20).\n"
    "            base += 0.22\n"
    "            factors.append({\"factor\": \"CRITICAL credential risk — active compromise detected (infostealer/dark web)\", \"impact\": 0.22, \"priority\": 1})\n"
    "        elif cred_level == \"HIGH\":\n"
    "            # Confirmed credential exposure (passwords/hashes) or a stale HR\n"
    "            # infection, per the K1-K7 model. +0.15 -> +0.18 (FIN-9): the model\n"
    "            # fixes the count-vs-boolean input bug that used to over-set HIGH, so\n"
    "            # the weight can now safely match the SA evidence (creds #1 at 34%).\n"
    "            base += 0.18\n"
    "            factors.append({\"factor\": \"HIGH credential risk — recent breaches with password exposure or dark web trading\", \"impact\": 0.18, \"priority\": 1})\n",
))

# --- D) KEV +0.08/cap0.20 -> +0.10/cap0.24 ---------------------------------
EDITS.append((
    "        # KEV CVEs: +0.08 each, cap 0.20 (confirmed actively exploited)\n"
    "        cves = categories.get(\"shodan_vulns\", {}).get(\"cves\", [])\n"
    "        kev_count = sum(1 for c in cves if c.get(\"in_kev\"))\n"
    "        kev_impact = min(0.20, kev_count * 0.08)\n",
    "        # KEV CVEs: +0.10 each, cap 0.24. Lifted from +0.08/0.20 (FIN-9): vuln-\n"
    "        # exploitation is co-dominant with credentials in ransomware intrusions\n"
    "        # (Sophos SA 28% #2; M-Trends 21% tied; DBIR +34% YoY on edge/VPN), and a\n"
    "        # CISA KEV is a CONFIRMED-exploited CVE. Cap keeps the vuln channel from\n"
    "        # dominating. Range per-CVE 0.08-0.10, cap 0.20-0.24.\n"
    "        cves = categories.get(\"shodan_vulns\", {}).get(\"cves\", [])\n"
    "        kev_count = sum(1 for c in cves if c.get(\"in_kev\"))\n"
    "        kev_impact = min(0.24, kev_count * 0.10)\n",
))

# --- E) No WAF +0.05 -> +0.04 ----------------------------------------------
EDITS.append((
    "        # No WAF: +0.05\n"
    "        if not categories.get(\"waf\", {}).get(\"detected\"):\n"
    "            base += 0.05\n"
    "            factors.append({\"factor\": \"No WAF detected\", \"impact\": 0.05, \"priority\": 3})\n",
    "        # No WAF: +0.04. Trimmed from +0.05 (FIN-9): WAF absence is a hygiene\n"
    "        # proxy, not a named ransomware vector, and WAF *detection* itself has\n"
    "        # known false-positives (back-test Theme-1) - don't over-weight a noisy\n"
    "        # input. Range 0.03-0.05.\n"
    "        if not categories.get(\"waf\", {}).get(\"detected\"):\n"
    "            base += 0.04\n"
    "            factors.append({\"factor\": \"No WAF detected\", \"impact\": 0.04, \"priority\": 3})\n",
))

# --- F) Weak SSL +0.05 -> +0.03 --------------------------------------------
EDITS.append((
    "        # Weak SSL: +0.05\n"
    "        ssl_grade = categories.get(\"ssl\", {}).get(\"grade\", \"F\")\n"
    "        if ssl_grade in (\"D\", \"E\", \"F\"):\n"
    "            base += 0.05\n"
    "            factors.append({\"factor\": f\"Weak SSL (grade {ssl_grade})\", \"impact\": 0.05, \"priority\": 3})\n",
    "        # Weak SSL: +0.03. Trimmed from +0.05 (FIN-9): weak TLS is rarely the\n"
    "        # ransomware ENTRY vector (mostly hygiene/MITM), and SSL grading has a\n"
    "        # known sslyze-6.x scoring bug (back-test) - keep it light here and let\n"
    "        # posture/DBI carry it. Range 0.02-0.03.\n"
    "        ssl_grade = categories.get(\"ssl\", {}).get(\"grade\", \"F\")\n"
    "        if ssl_grade in (\"D\", \"E\", \"F\"):\n"
    "            base += 0.03\n"
    "            factors.append({\"factor\": f\"Weak SSL (grade {ssl_grade})\", \"impact\": 0.03, \"priority\": 3})\n",
))

for i, (old, new) in enumerate(EDITS):
    n = s.count(old)
    assert n == 1, (f"edit {i} anchor count", n)
    s = s.replace(old, new, 1)

# Sanity: old single-largest RDP weight gone; new weights present.
assert "base += 0.25" not in s, "old RDP +0.25 still present"
assert "min(0.20, len(db_ports) * 0.10)" not in s, "old DB-port cap still present"
assert "base += 0.22" in s and "base += 0.18" in s, "new credential weights missing"
assert "min(0.24, kev_count * 0.10)" in s, "new KEV weight missing"
assert "\r" not in s, "unexpected CR"
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print(f"OK scoring_analytics.py: RSI rebalance applied ({len(EDITS)} factor edits)")
