# Code-Wide Heuristics Audit — Executive Summary

**Date:** 2026-06-03
**Method:** the new Card Verification Protocol **Step 6** applied code-wide — 6 module-owner agents enumerated every heuristic (hardcoded threshold, magic constant, multiplier, cap, fingerprint/substring, fallback default, status rule, curated table), screened each against the five back-test failure modes, and classified it. White-box, read-only, no credits, against fixed-code data (`test_fixtures/phishield_live.json`).
**Scope:** ~232 heuristics across `checkers_core`, `checkers_network`, `checkers_threats`, `checkers_supply_chain`, `scoring_analytics`, `scanner.py` + supporting.

## Tally

| Class | ~Count | Meaning |
|---|---|---|
| **justified** | ~93 | has an empirical/documented basis — leave |
| **fragile** | ~67 | works on the sample, brittle elsewhere — harden (free) |
| **arbitrary** | ~22 | no rationale — document or remove |
| **calibration-gated** | ~74 | scoring magic-number — value belongs to FIN-9, NOT intuited |

All Waves 1-5 fixes re-screened **clean** across every module.

## New correctness bugs (not in the original back-test)

| # | Bug | Module | Severity | Failure mode |
|---|---|---|---|---|
| 1 | **B2C/PCI auto-detect over-broad** — `PAYMENT_FORM_HINTS` matches generic `/cart`, "add to cart", Product JSON-LD, so a B2B site can auto-tick **B2C** → adds CPA s112 (10% turnover / R1M) to the cat stack, inflating regulatory + financial exposure | `flag_inference.py:431` | **HIGH** | generic-response-as-signal |
| 2 | **OSV synthetic-CVSS fabrication** — invents a numeric CVSS from a vector when the source has none → feeds CVE/RSI | `checkers_threats.py:1104` | medium | fabrication on absent input |
| 3 | **SSL cipher bit-strength mislabel** — `256 if "256" in name` matches the `SHA256` suffix → `AES_128_..._SHA256` renders as 256-bit | `checkers_core.py:160` | low (rendered) | wrong parse |
| 4 | **S-5 unknown-severity default 5 > low's 3** — a mild inversion (unknown treated worse than low) | `checkers_supply_chain.py` | low | inversion |
| 5 | **`total_checkers` stale fallback 27** vs the authoritative 31 (`len(WEIGHTS)`) | `scanner.py` | low | stale constant |

## Dominant theme — the "loose-substring" family (fragile)

The single biggest pattern: a **substring match against a whole string** treated as a positive signal — the same class as the WAF/F5 and DNSBL bugs, but spread across more checkers. All free word-boundary / probe-gate fixes:
- SPF `"all" in txt` (incidental match); WAF **body** markers (`"cloudflare"` in page text → phantom WAF bonus); WHOIS privacy keywords vs the whole blob.
- `RISKY_KEYWORDS` via `any(k in fqdn)` (flags `api.`, db-brands, even the apex) → inflates `risky_subdomains` → `sub_risk × 15`.
- VPN signatures: only RDS got the `require_200` gate in Wave 2 — the **other 7 vendors still match a token in any response** (soft-404 / marketing); apply the S-3 `_probe` gate uniformly. Plus `vpn_risk` "no VPN page = +20" risks inverting against ZTNA orgs.
- EOL substring mis-matches `7.1` vs `7.10`.

## Stale curated tables — extend the Wave-4/5 drift-test pattern

Several hardcoded tables silently go stale and have no drift test: `dnsbl.sorbs.net` (SORBS **ceased mid-2024** — likely dead), `PORT_INTEL`/`SERVICE_INTEL` (point-in-time CVSS/EPSS/KEV), `TAKEOVER_SIGNATURES`, `RANSOMWARE_CVE_MAP`, `KNOWN_BREACH_DATES`, `COMBO_LIST_SOURCES` (a new combo dump reads as fresh compromise), `JSE_LISTED_DOMAINS`, `SECTOR_FRAMEWORKS` statutory maxima, `SA_INDUSTRY_COSTS`. Clone the Wave-5 `vendor_breaches` drift-warn for each + add dated-review markers.

## Calibration-gated (~74) — consolidated for FIN-9

The large bucket is, correctly, **calibration not correctness** — flagged with anchors, never intuited. The highest-leverage constants (extends OUTSTANDING §6b):
1. `0.3` in `p_breach = vulnerability × TEF × 0.3` (scoring_analytics.py:2107) — scales every breach probability; unvalidated since Wave 1 made the coupling live.
2. `vulnerability = (100 − _overall_score/10)/100` (L2038) — the posture→probability curve, first time on a real score.
3. `dehashed_total × 2` (L677) — the confidence-blind credential input (the 5L problem).
Plus the CredentialRiskClassifier ladder (−50/−20/−30/−15/−10/−3, uncapped `darkweb×10`/`paste×3`, **HR recency computed-but-never-applied** — OUTSTANDING §6), the supply-chain penalty constants + `+0.15` cap + `1825d` lookback, RSI factor sizes, `K_TAIL=1.20`, `COST_PER_RECORD`/`REGULATORY_FINE`, HIBP step thresholds, EPSS 0.4/0.5, recency cutoffs 90d/360d.

## Recommendation

**A "Wave 6" (all free, correctness + robustness — no calibration):**
1. The 5 new correctness bugs — lead with **#1 (B2C auto-detect)**: it mis-prices regulatory exposure on B2B sites, so it directly affects the financial output FIN-9 will calibrate. Harden to ≥2 signals or broker-confirm.
2. The loose-substring family — apply word-boundary matching + the S-3 `_probe` gate uniformly (esp. the 7 remaining VPN vendors).
3. The stale-table drift tests — clone the Wave-5 pattern.

**Calibration (~74 constants) → FIN-9 / 5L**, per OUTSTANDING §6/§6b — the audit hands the session a complete, anchored parameter inventory.

**Rating note:** these are mostly *robustness* improvements on already-fixed-and-verified output (the scanner sits at ~8.5/10 post-Wave-5). The one item that moves the needle is #1 (B2C auto-detect), because it can mis-classify regulatory exposure. Wave 6 + the FIN-9 calibration are the path to a defensible 9.

*Per-module detail follows.*
