# Calibration Prep 04 — SA Cost / Fine Tables + TEF (Threat-Event Frequency)

**Status:** SANDBOX PREP for the calibration session. Values below are **research-grounded
PROPOSALS, NOT final**. No production code was edited. This is the most SA-specific parameter
group — anchored to IBM SA Cost of a Data Breach, the POPIA s109 fine structure + actual
Information Regulator enforcement to date, SABRIC, and Check Point SA sector telemetry.

Owner roles for the session: **DEV** proposes → **EXPERT** validates vs SA breach data →
**CRITIC** challenges (statutory-max vs expected-enforced; est_records for an SME) →
**ORCHESTRATOR** reconciles.

---

## 0. CRITICAL FRAMING — the params literally named in the brief are DEAD in production

The brief names `COST_PER_RECORD`, `REGULATORY_FINE`, and `est_records = max(1000, revenue/50000)`.
These are the **legacy USD path** (`scoring_analytics.py:1634-1684`). **They never execute in
production.**

- `FinancialImpactCalculator.calculate()` (L1661-1665) routes to `_calculate_zar()` whenever
  `annual_revenue_zar > 0`.
- `scanner.py:1195` passes `annual_revenue_zar = resolve_effective_revenue_zar(...)`, which
  **defaults a no-revenue scan to R10,000,000** (`peer_benchmarking.py:90`,
  `DEFAULT_REVENUE_ZAR_WHEN_ABSENT`). So `_zar` is **always ≥ R10M ⇒ ZAR path always fires**.
- The legacy `else` branch (USD `COST_PER_RECORD`/`REGULATORY_FINE`/`est_records`) is unreachable.

**Recompute proof** (throwaway, no edit): the legacy path, if forced (`annual_revenue_zar=0`),
returns `cost_per_record=219`, `est_records=1000`, `regulatory_fine=R750,000` for finance — a
mixed-currency artefact (219 was a *USD* figure now sitting in a ZAR product; the R750k fine has
no POPIA statutory basis). **It is a latent landmine, not a live input.**

**The LIVE equivalents to calibrate are:**

| Brief param (dead) | LIVE production equivalent | Location |
|---|---|---|
| `COST_PER_RECORD` (USD) | `SA_INDUSTRY_COSTS[*]["cost_per_record"]` (ZAR) | L916-941 |
| `REGULATORY_FINE` (flat ZAR) | C2 POPIA stack: expected `min(R10M, rev×0.02)` + cat `R10M×capacity_factor` | L2272-2348 |
| `est_records = rev/50000` | `record_density_divisor` per-industry + `estimated_records` | L2180-2210 |
| (TEF — correctly named) | `THREAT_EVENT_FREQUENCY` | L1840-1859 |

**DECISION FOR SESSION (recommended):** delete or hard-disable the legacy USD path so it can never
silently re-activate, and calibrate only the live ZAR equivalents. (Echoes the `OUTSTANDING.md`
§ "stale-table" flag and heuristics-audit row 79.)

---

## 1. SA research anchors (sources at bottom)

**IBM Cost of a Data Breach — South Africa**
- **2025:** avg total **R44.1M** (−17% YoY); avg **23,445 records**/breach ⇒ implied
  **~R1,880/record** (R44.1M ÷ 23,445). Top sectors: **Financial Services R70.2M**,
  Hospitality R57.5M, Services R56.8M.
- **2024:** avg total R53.1M; FS **R75.31M**, Industrial R67.26M, Hospitality R61.76M; breach
  sizes 2,100–113,000 records.
- Attack vectors (2025 SA, cost): phishing R50.4M (13%), compromised credentials R48M (13%),
  DoS R38.8M (13%), third-party/supply-chain R29.6M (17% — most *common*).

→ The code's `SA_INDUSTRY_COSTS` is the **IBM 2025 SA** table (FS R70.12M ≈ reported R70.2M;
"Other" R44.1M = the national avg). `cost_per_record` values are back-derived as
`breach_cost_zar / 23,445` (e.g. FS 70.12M/23,445 = R2,991 ≈ table's 2,992). **Internally
consistent and correctly sourced.** Only risk = annual staleness.

**POPIA s109 administrative fine — statutory vs ACTUAL enforcement**
- **Statutory max: R10,000,000** (s109; or up to 10 yrs imprisonment, or both).
- **Actual enforcement to date — only TWO administrative fines, both R5M, both vs government
  departments, both for *failure to comply with an enforcement notice* (not the breach itself):**
  1. **Dept of Justice & Constitutional Development — R5M**, July 2023 (1,200 files, ransomware;
     expired AV/SIEM/IDS licences). DoJ challenged it.
  2. **Dept of Basic Education — R5M**, infringement notice 23 Dec 2024.
- Other actions stopped at **enforcement notices** (no fine yet): TransUnion (SA's biggest breach),
  WhatsApp/Meta (settled Nov 2025), IEC, Lancet Labs, Blouberg Municipality.

→ **Expected-enforced fine ≈ R5M (the only data points), well below the R10M ceiling, and so far
0 fines against private-sector commercial entities.** Statutory max R10M is correct for the
**catastrophe view**; it is **too high for the expected-loss (P50) view**.

**SA sector attack frequency (for TEF)**
- **Check Point SA 2025:** **Government/Military #1 at 3,480 attacks/org/week**;
  **Communications #2 at 1,062/wk**; then financial services and consumer goods. SA overall avg
  1,884/wk (+69% YoY — the steepest global rise). Africa = most-attacked region (3,286/wk).
- **SABRIC 2024:** digital-banking fraud +86% YoY, **R1.888bn** gross losses (97,975 incidents),
  banking apps 65.3% of incidents — but **predominantly social-engineering, not technical breach**
  of the institution (relevant: SABRIC volume overstates *institutional* TEF for FS).

→ **SA-specific divergence from the global default:** global DBIR/IBM rank **FS #1**; SA Check
Point telemetry ranks **Government/Public Sector #1 by attack volume, Communications #2**. The
current TEF table (FS 1.45, Public Sector/Gov 1.35, Communications 1.05) under-weights the two
sectors SA attackers hit hardest. This is the headline TEF calibration question.

---

## 2. Proposal table

| Param | Current | Proposed (range) | Confidence | Anchor (sources) | Recompute | Open question |
|---|---|---|---|---|---|---|
| **Currency of cost-per-record** | ZAR (live `SA_INDUSTRY_COSTS`); USD orphan in dead `COST_PER_RECORD` | Confirm **ZAR**; **delete legacy USD table** | **Data-supported** (high) | scanner.py:1195 always sends `_zar≥R10M` ⇒ ZAR path only; legacy returns USD 219 / R750k | Forcing legacy: cpr=219, est=1000, fine=750k (mixed-currency artefact, never reached) | Delete vs hard-assert the dead branch? |
| **`cost_per_record` "Other"** | R1,881 | **R1,880 (R1,700–R2,050)** | **Data-supported** (high) | IBM SA 2025: R44.1M ÷ 23,445 rec = R1,880 | "Other" breach_cost R44.1M = national avg ✓ | Refresh annually (IBM 2026) |
| **`cost_per_record` Financial Services** | R2,992 | **R2,992 (R2,800–R3,200)** | **Data-supported** (high) | IBM SA 2025 FS R70.2M ÷ 23,445 | FS R10M scan: cpr ref 2992, used only as disclosure metric | FS is most *expensive* (IBM) but in SA most *attacked* = Gov (see TEF) |
| **`cost_per_record` Public Sector** | R3,273 | **R3,200–R3,400** (hold) | **Reasoned** (med) | IBM 2025 Public Sector highest-cost; multiplier 1.74 | breach_cost R76.73M | IBM SA doesn't publish every sector yearly — some rows are 2024-scaled |
| **`SA_INDUSTRY_COSTS` whole table** | IBM-2025-ZAR | **Hold; add a dated `# IBM 2025` refresh stamp** | **Data-supported** (high) | FS/Hospitality/Services match IBM 2025 reported | n/a | Which sectors are 2025-actual vs 2024-carried? Mark each |
| **REGULATORY_FINE — expected (P50) POPIA** | `min(R10M, rev×0.02)` ⇒ R200k @ R10M | **Anchor to ACTUAL enforcement: expected ≈ R0–R5M, enforcement-discounted.** Replace flat 2% with a **probability-weighted expected fine** (see §3) | **Reasoned** (med) | Only 2 fines ever, both R5M, both govt, 0 private; s109 max R10M | @R10M: current expected C2=R200k. Proposed expected ≈ R150k–R400k (P(fine)·E[fine\|fine]) | What is P(POPIA fine \| breach) for a *private* SA SME? Likely <5% to date — **needs colleague / compliance officer** |
| **REGULATORY_FINE — catastrophe (tail) POPIA** | `R10M × capacity_factor` (0.15 @ R10M ⇒ R1.5M) | **Hold R10M statutory ceiling** for cat view; keep capacity scaling | **Data-supported** (high) | s109 hard ceiling = R10M | @R10M cat: popia_statutory_scaled R1.5M ✓ | Capacity_factor band magnitudes (0.10–1.00) — separate calibration |
| **`est_records` heuristic (dead)** | `max(1000, rev/50000)` | **Delete** (replaced live by `record_density_divisor`) | **Data-supported** (high) | dead path only | rev/50000 @R10M = 1,000 (floored) | n/a — dead |
| **`record_density_divisor` finance** | R7,500/record | **R5,000–R10,000** (hold 7,500) | **Reasoned** (med) | code note "1 cust record per R5–10k"; not externally sourced | @R10M FS ⇒ 10M/7,500 = **1,333 records** (vs IBM SA avg 23,445!) | An R10M SME modelled at 1,333 records is **plausible for a tiny firm** but far below IBM's 23,445 enterprise avg — is the SME floor right? |
| **`estimated_records` (live, reference only)** | `max(100, zar//divisor)` — disclosure metric, NOT in cost calc | Hold; **document it is non-scoring** | **Data-supported** (high) | heuristics-audit row 67: "not a cost input" | C1 liability uses IBM total×multiplier×revenue-scale, NOT records×cpr | Should we surface "vs IBM SA avg 23,445" in the disclosure? |
| **TEF Financial Services** | 1.45 | **1.30–1.45** (hold ~1.40) | **Reasoned** (med) | IBM FS #1 cost; SABRIC R1.9bn — but SABRIC is social-eng, not institutional breach | p_breach @ vuln 0.619 = 0.619×1.45×0.3 = **0.269** | SABRIC volume overstates institutional TEF — discount it |
| **TEF Public Sector / Government** | 1.35 | **↑ 1.40–1.50** | **Data-supported** (med-high) | **Check Point SA: Gov #1 @ 3,480/wk** — most-attacked SA sector | Gov @ vuln 0.619: 0.619×1.50×0.3 = **0.279** | Raising Gov above FS is SA-specific (inverts the global DBIR order) — confirm with EXPERT |
| **TEF Communications** | 1.05 | **↑ 1.20–1.30** | **Data-supported** (med) | **Check Point SA: Comms #2 @ 1,062/wk**; telco cybercrime R5.3bn 2025 | n/a | Comms currently mid-pack; SA telemetry says #2 |
| **TEF Retail / Consumer** | 1.25 / 0.95 | **Consumer ↑ to ~1.10** | **Reasoned** (med) | Check Point SA: "consumer goods & services" in SA top-3 | n/a | Reconcile Retail vs Consumer (split keys) |
| **TEF Healthcare** | 1.40 | **1.20–1.35** (consider ↓) | **Reasoned** (low-med) | Global IBM #2 cost, but **not** in SA Check Point top sectors; Lancet/NHLS attacks exist | n/a | SA healthcare attack *frequency* thinner than global — needs SA data |
| **TEF range / `0.3` interaction** | 0.80–1.45 (modest) | Hold range; **note TEF × the `0.3` LEF constant jointly set absolute p_breach** | **Reasoned** (med) | FAIR LEF = vuln×TEF×0.3 | TEF is a *relative* multiplier; absolute level is the `0.3` (FIN-9 / doc 01) | Don't double-calibrate: fix `0.3` first (separate group), then TEF as relative tilt |

---

## 3. The statutory-max vs expected-enforced question (CRITIC's central challenge)

**Current model is already two-tier and largely correct:**
- **Expected (P50) C2** = `min(R10M, rev×0.02)` — code *explicitly flags* this 2% as "an internal
  capacity-scaling heuristic, NOT a statutory formula" (L2267-2271). Good honesty.
- **Catastrophe C2** = `R10M × capacity_factor` stacked with ECTA/CPA/sector maxima — the hard
  statutory ceiling, capacity-scaled. Correct for the tail.

**The gap:** the expected-view 2%-of-turnover is **not anchored to actual enforcement**. Reality:
- POPIA has produced **2 fines in its enforcement history, both R5M, both public-sector, zero
  private-commercial.** P(administrative fine | private SME breach) is empirically **very low**
  (arguably <5% to date — the Regulator's pattern is enforcement-notice-first, fine only on
  *non-compliance* with the notice).
- A statutory- or turnover-anchored expected fine therefore **overstates** the P50 regulatory
  cost for a private SME, and **understates the conditional severity** (when a fine lands it has
  been the full R5M, half the ceiling).

**DEV proposal (for EXPERT/colleague validation):** replace the flat 2% expected with an explicit
**expected-value decomposition**:

```
E[POPIA fine] = P(fine | breach) × E[fine | fine]
   where, anchored to enforcement to date:
     P(fine | breach)  ≈ 0.02–0.05  (private SME; higher for public sector / repeat offender)
     E[fine | fine]    ≈ R5M        (both actual fines; ~50% of the R10M ceiling)
   ⇒ E[POPIA fine] ≈ R100k–R250k   (vs current R200k @ R10M — coincidentally similar!)
```

**Reconciliation note (ORCHESTRATOR):** the *current* R200k expected output is, by luck,
inside the proposed R100k–R250k band — so the **headline expected loss barely moves**; the value of
the change is **defensibility** (anchored to real enforcement, not an unsourced 2%) and **correct
behaviour at the revenue extremes** (2%-of-turnover sends a R200M firm to the R10M cap on the
expected line, which over-prices; an enforcement-probability model would not). **P(fine|breach) is
the single biggest unknown and is a compliance-officer / colleague call, not a dev intuition.**

---

## 4. Recompute summary (throwaway python, no production edit)

Fixture assumption: **Financial Services, R10M** (the no-revenue default), `_overall_score=381`
(phishield real posture, post Wave-1 `_overall_score` wiring).

| Metric | Current production output |
|---|---|
| vulnerability | 0.619 (= (100 − 381/10)/100) |
| TEF (FS) | 1.45 |
| **p_breach** | **0.269** (0.619 × 1.45 × 0.3) |
| C1 liability | R7.17M |
| C2 regulatory (expected POPIA) | **R200k** (2% × R10M) |
| C2 catastrophe (statutory) | R1.5M (R10M × 0.15 capacity) |
| C4 ransom | R0.90M |
| C5 IR | R0.35M |
| **total most_likely** | **R3.88M** |
| est_records (live, finance R7,500 divisor) | **1,333** (cf. IBM SA avg 23,445) |

Sanity vs published SA: IBM SA 2025 FS avg breach = R70.2M (enterprise). The model returns R3.88M
for a **R10M micro-SME** — i.e. ~5.5% of the enterprise figure, scaled down by revenue elasticity.
**Directionally sane** (an SME is not an enterprise) but note the est_records (1,333) sits far below
IBM's 23,445 enterprise average — expected for a tiny firm, but the EXPERT should confirm the SME
record-density floor is realistic, since C1 (the largest component, R7.17M) is driven by the
IBM-total × multiplier × revenue-scale path, **not** by records × cost_per_record (cost_per_record
is a disclosure-only reference here — see heuristics-audit row 67).

---

## 5. Honesty ledger

| Claim | Confidence | Basis |
|---|---|---|
| Legacy USD `COST_PER_RECORD`/`REGULATORY_FINE`/`est_records` are dead in production | **Data-supported (high)** | code trace scanner.py:1195 + resolve_effective_revenue_zar default R10M + recompute |
| `SA_INDUSTRY_COSTS` = correct IBM-2025-SA-ZAR | **Data-supported (high)** | FS/Hospitality/Services match IBM 2025 reported; "Other"=R44.1M national avg |
| Per-record ~R1,880 ("Other") | **Data-supported (high)** | IBM 2025 R44.1M ÷ 23,445 records |
| POPIA expected fine should be enforcement-anchored, not 2%-turnover | **Reasoned (med)** | only 2 fines ever (both R5M, both govt); P(fine\|breach) low |
| **P(POPIA fine \| private SME breach) ≈ 0.02–0.05** | **NEEDS COLLEAGUE / compliance officer (low)** | inferred from enforcement scarcity; not a published rate |
| Statutory R10M correct for catastrophe tier | **Data-supported (high)** | s109 hard ceiling |
| TEF should raise **Gov/Public-Sector and Communications** above current | **Data-supported (med-high)** | Check Point SA 2025 sector ranking (Gov #1, Comms #2) |
| Exact TEF magnitudes | **Reasoned / needs-colleague (med)** | attack-volume ≠ loss-event-frequency; TEF is relative, absolute level set by the `0.3` LEF constant (separate group) |
| `record_density_divisor` values (R5k–R1M/record) | **Reasoned (low-med)** | code-internal SA-market observation, not externally sourced |

---

## 6. Biggest open question (carry into the session)

**What is P(POPIA administrative fine | breach) for a private-sector SA SME, and what conditional
severity should the expected-loss view use?** The entire POPIA enforcement record is **two R5M
fines, both against government departments, zero against private commercial entities**, with the
Regulator consistently issuing enforcement-notices-first. This makes the *expected* (P50)
regulatory line almost entirely a **compliance-officer judgement call**, not a dev/data decision.
The statutory R10M ceiling (catastrophe tier) and the IBM-anchored cost-per-record (ZAR, high
confidence) are settled; the regulatory **expectation** is the one genuinely unresolved,
colleague-gated input.

Secondary: should TEF invert the global order to put **Public Sector ≥ Financial Services** for the
SA market (Check Point telemetry says yes by volume; loss-severity says FS) — and should this be
done in TEF (frequency) or left to the cost multiplier (severity)?

---

## Sources

- IBM Cost of a Data Breach 2025 — South Africa: avg R44.1M, 23,445 records, FS R70.2M / Hospitality R57.5M / Services R56.8M; vectors phishing R50.4M, credentials R48M, third-party R29.6M (DoS R38.8M). (htxt.co.za 2025-07; techcentral.co.za/267820; iafrica.com)
- IBM Cost of a Data Breach 2024 — South Africa: avg R53.1M; FS R75.31M, Industrial R67.26M, Hospitality R61.76M; 2,100–113,000 records. (itweb.co.za/6GxRKqYQag9qb3Wj; intelligentcio.com/africa 2024-08)
- POPIA s109 administrative fine (max R10M / 10 yrs). (popia.co.za/section-109-administrative-fines)
- Information Regulator R5M fine — Dept of Justice, July 2023 (first-ever; ransomware, 1,200 files, expired AV/SIEM/IDS). (lexology.com; itweb.co.za inforeg-justice; inforegulator.org.za media statements)
- Information Regulator R5M infringement notice — Dept of Basic Education, 23 Dec 2024. (itweb.co.za education-dept-r5m)
- Enforcement notices (no fine): TransUnion, WhatsApp/Meta (settled 13 Nov 2025), IEC, Lancet Labs, Blouberg Municipality. (itweb.co.za inforeg-transunion; timeslive.co.za 2024-09-11; misa.org WhatsApp settlement)
- Check Point SA 2025 sector telemetry: Government/Military 3,480/wk (#1), Communications 1,062/wk (#2); SA avg 1,884/wk (+69% YoY); Africa 3,286/wk (most-attacked region). (intelligentcio.com/africa 2025-06-02; businessday.co.za 2025-12-17)
- SABRIC Annual Crime Statistics 2024: digital-banking fraud +86%, R1.888bn gross losses, 97,975 incidents, apps 65.3% (predominantly social-engineering). (sabric.co.za CRIME-STATISTICS-REPORT-2024; techafricanews.com 2025-08-29)
- Telco cybercrime SA R5.3bn 2025. (businessday.co.za 2026-01-12)
