#!/usr/bin/env python3
"""SANDBOX one-off (task #7): SA cost / fine / TEF calibration in scoring_analytics.py.

Three groups, all anchored to docs/calibration_prep/04_sa_cost_fine_tef.md:

  T1) TEF SA-telemetry tilt (Check Point SA 2025 sector attack-volume):
        Public Sector / Government  1.35 -> 1.45  (Gov #1 @ 3,480/wk; TIE FS, not above)
        Communications              1.05 -> 1.25  (Comms #2 @ 1,062/wk)
        Consumer                    0.95 -> 1.10  (SA top-3 consumer goods)
      HELD: FS 1.45 (in 1.30-1.45 band; trimming couples into phishield headline),
            Healthcare 1.40 (thin SA attack data - colleague to confirm trim).

  T2) C2 POPIA EXPECTED fine: replace the unsourced 2%-of-turnover with the
      enforcement-anchored expected value E[fine] = P(fine|breach) x E[fine|fine]
      = 0.03 x R5M = R150k. COLLEAGUE-GATED: P(fine|breach) (private-SME, ~0.02-0.05).
      Fixes the high-revenue artefact (rev x 0.02 sent a R500M org to the R10M
      statutory ceiling on the *expected* line). Catastrophe tier R10M unchanged.

  T3) SA_INDUSTRY_COSTS: VALUES HELD (IBM-2025-SA, high confidence); add a dated
      sourcing/refresh stamp (cost_per_record = breach_cost_zar / 23,445).

Fail-safe: assert each anchor count==1; atomic (write only after all replaces);
CRLF-preserving. NOT shipped (FIN-9 calibration prep, 2026-06-03).
"""
import os

SA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised buffer"

EDITS = []

# --- T1a) TEF comment header: add Check Point SA source + FIN-9 tilt note -----
EDITS.append((
    "    # Range: 0.80-1.45 (deliberately modest to avoid probability inflation).\n"
    "    # Sources: Verizon DBIR 2025, IBM 2025, Sophos SA 2025, SABRIC 2024.\n"
    "    # Tuneable via FAIR parameters doc Section 12.\n",
    "    # Range: 0.80-1.45 (deliberately modest to avoid probability inflation).\n"
    "    # Sources: Verizon DBIR 2025, IBM 2025, Sophos SA 2025, SABRIC 2024,\n"
    "    # Check Point SA 2025 (sector attack-volume telemetry).\n"
    "    # FIN-9 (2026-06-03) SA-telemetry tilt: Check Point SA ranks Government #1\n"
    "    # (3,480 attacks/org/wk) and Communications #2 (1,062/wk) - both were under-\n"
    "    # weighted vs the global DBIR order. Gov/Public Sector 1.35 -> 1.45 (TIE with\n"
    "    # FS, NOT above: attack VOLUME != loss-event frequency, and inverting the\n"
    "    # global FS-#1 order is EXPERT-gated); Communications 1.05 -> 1.25; Consumer\n"
    "    # 0.95 -> 1.10 (SA top-3 consumer goods). FS HELD 1.45 (in 1.30-1.45 band;\n"
    "    # trimming would couple into the phishield headline p_breach). Healthcare\n"
    "    # HELD 1.40 (global #2 cost but thin SA attack data - colleague to confirm a\n"
    "    # possible trim to 1.20-1.35). TEF is a RELATIVE tilt; the absolute p_breach\n"
    "    # level is set by the 0.3 LEF constant (calibrated separately, doc 01).\n"
    "    # Tuneable via FAIR parameters doc Section 12.\n",
))

# --- T1b) Public Sector / Government 1.35 -> 1.45 ----------------------------
EDITS.append((
    '        "Public Sector": 1.35, "Government": 1.35,\n',
    '        "Public Sector": 1.45, "Government": 1.45,\n',
))

# --- T1c) Communications 1.05 -> 1.25 ----------------------------------------
EDITS.append((
    '        "Communications": 1.05,\n',
    '        "Communications": 1.25,\n',
))

# --- T1d) Consumer 0.95 -> 1.10 (Transportation held 0.95) -------------------
EDITS.append((
    '        "Transportation": 0.95, "Consumer": 0.95,\n',
    '        "Transportation": 0.95, "Consumer": 1.10,\n',
))

# --- T2) C2 POPIA expected fine: enforcement-anchored expected value ----------
EDITS.append((
    "        # POPIA: Administrative fine under Section 109 - statutory ceiling R10M.\n"
    "        # Section 109(3) factors (nature, duration, extent, number of subjects,\n"
    "        # public importance, prevention, risk assessment, prior offences) govern\n"
    "        # the actual amount imposed. The 2%-of-turnover figure used here is an\n"
    "        # internal capacity-scaling heuristic, NOT a statutory formula -\n"
    "        # POPIA does not specify a percentage-based trigger. Section 107 (the\n"
    "        # previous reference) is criminal penalties (court-imposed, post-conviction).\n"
    "        # For catastrophe-view modelling the full R10M statutory ceiling is used.\n"
    "        c2_popia = min(10_000_000, annual_revenue_zar * 0.02)\n"
    "        c2_popia_statutory_max = 10_000_000  # used by cat-view modelling\n",
    "        # POPIA: Administrative fine under Section 109 - statutory ceiling R10M.\n"
    "        # Section 109(3) factors (nature, duration, extent, number of subjects,\n"
    "        # public importance, prevention, risk assessment, prior offences) govern\n"
    "        # the actual amount imposed; POPIA specifies no percentage-based trigger.\n"
    "        # Section 107 is criminal penalties (court-imposed, post-conviction).\n"
    "        #\n"
    "        # EXPECTED (P50) fine - enforcement-anchored expected value (FIN-9,\n"
    "        # 2026-06-03). POPIA's entire enforcement record is TWO administrative\n"
    "        # fines, both R5M, both public-sector, both for non-compliance with an\n"
    "        # enforcement notice (not the breach itself), ZERO private-commercial.\n"
    "        # So model E[fine] = P(fine|breach) x E[fine|fine], anchored to that\n"
    "        # record, instead of the previous unsourced 2%-of-turnover (which over-\n"
    "        # priced large firms: rev x 0.02 sent a R500M org to the full R10M\n"
    "        # statutory ceiling on the *expected* line - a catastrophe-tier value,\n"
    "        # not a P50). Revenue-scaling of regulatory risk still lives in the\n"
    "        # catastrophe tier (capacity_factor below) and in C1 liability.\n"
    "        #   COLLEAGUE-GATED: P(fine|breach) for a private SA SME is ~0.02-0.05\n"
    "        #   (inferred from enforcement scarcity - 0 private fines to date - NOT a\n"
    "        #   published rate; a compliance-officer call). E[fine|fine] ~ R5M (both\n"
    "        #   actual s109 fines). Best-effort midpoint 0.03 x R5M = R150k (the old\n"
    "        #   2% gave R200k @ R10M, so the headline barely moves; the value here is\n"
    "        #   defensibility + correct high-revenue behaviour). Range R100k-R250k.\n"
    "        # For catastrophe-view modelling the full R10M statutory ceiling is used.\n"
    "        POPIA_P_FINE_GIVEN_BREACH = 0.03      # colleague-gated (private-SME enforcement probability)\n"
    "        POPIA_E_FINE_GIVEN_FINE = 5_000_000   # both actual s109 fines were R5M\n"
    "        c2_popia_statutory_max = 10_000_000   # s109 ceiling; used by cat-view modelling\n"
    "        c2_popia = min(c2_popia_statutory_max,\n"
    "                       POPIA_P_FINE_GIVEN_BREACH * POPIA_E_FINE_GIVEN_FINE)\n",
))

# --- T3) SA_INDUSTRY_COSTS sourcing/refresh stamp (values HELD) --------------
EDITS.append((
    "# South African industry breach cost data (IBM 2025, translated to ZAR)\n",
    "# South African industry breach cost data - IBM Cost of a Data Breach 2025 (SA),\n"
    "# translated to ZAR. cost_per_record is back-derived as breach_cost_zar / 23,445\n"
    "# (IBM SA 2025 avg breach size); \"Other\" = R44.1M national avg; FS/Hospitality/\n"
    "# Services match IBM 2025 reported. Values HELD this round (high-confidence,\n"
    "# sourced); only this sourcing/refresh stamp was added. REFRESH ANNUALLY against\n"
    "# the next IBM SA report (last stamped 2026-06-03, FIN-9 calibration prep).\n",
))

for i, (old, new) in enumerate(EDITS):
    n = s.count(old)
    assert n == 1, (f"edit {i} anchor count", n)
    s = s.replace(old, new, 1)

# Sanity: old values gone, new values present.
assert "annual_revenue_zar * 0.02" not in s, "old 2%-of-turnover POPIA still present"
assert "min(10_000_000, annual_revenue_zar * 0.02)" not in s, "old c2_popia still present"
assert "POPIA_P_FINE_GIVEN_BREACH = 0.03" in s, "new POPIA expected-value missing"
assert '"Public Sector": 1.45, "Government": 1.45,' in s, "TEF gov raise missing"
assert '"Communications": 1.25,' in s, "TEF comms raise missing"
assert '"Transportation": 0.95, "Consumer": 1.10,' in s, "TEF consumer raise missing"
assert "\r" not in s, "unexpected CR"
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print(f"OK scoring_analytics.py: SA cost/fine/TEF calibration applied ({len(EDITS)} edits)")
