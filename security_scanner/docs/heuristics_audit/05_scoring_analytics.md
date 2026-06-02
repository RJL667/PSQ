# scoring_analytics.py — Heuristics Audit

**Scope:** `scoring_analytics.py` — `RiskScorer` (WEIGHTS, per-checker risk maps, WAF bonus,
risk-level bands), `RansomwareIndex` (RSI factors, caps, diminishing returns, industry/size
multipliers), `FinancialImpactCalculator` (`_calculate_zar` p_breach / TEF / vulnerability,
cost components, regulatory stack, MC/PERT/GPD, return-period mapping, coverage K_TAIL),
`DataBreachIndex`, `RemediationSimulator` (REMEDIATION_MAP + Wave-4 caps), `MITIGATIONS`.
**Method:** Step-6 Card Verification Protocol (white-box). Each heuristic screened for the five
back-test failure modes (fabrication-on-absent, generic/error-as-signal, boolean-as-count,
inversion, stale table) and classified `justified` / `fragile` / `arbitrary` / `calibration-gated`.
**Calibration discipline:** per the protocol + FIN-9 rule, calibration-gated constants are FLAGGED
with the anchor that should set them — **no new values proposed here**. Concrete fixes are proposed
ONLY for genuine correctness bugs (fabrication/inversion/boolean-as-count/wiring).
Cross-references OUTSTANDING.md §6 + §6b and `credential_confidence_pbreach_design.md` (5L).

---

## A. RiskScorer — overall posture score (0-1000)

| Heuristic (value) | Location | What it does | Failure-mode / anchored? | Class | Recommendation / anchor |
|---|---|---|---|---|---|
| `WEIGHTS` dict (31 entries, ssl 0.09 … financial_impact 0.02; nominal sum ~1.32) | L481-524 | Relative category weight in weighted posture sum | Documented (docstring) — derived rows over-1.0 by design; redistribution rescales failed/skipped. Not empirically fitted, expert-set | calibration-gated | Weights are the posture-model's free parameters; anchor relative ordering to DBIR root-cause shares (credentials/exploits) + Sophos SA. Don't intuit individual deltas |
| `breach_risk = min(100, breach_count*15)` | L628 | HIBP breach count → 0-100 risk | Count-based (not boolean) — OK. 15/breach is arbitrary slope | calibration-gated | Slope vs DBIR repeat-breach base rate |
| `admin_risk = min(100, crit*50 + high*20)` | L636 | Exposed-admin count → risk | Count-based. Depends on exposed_admin 403-inversion fix (Wave 1) upstream — values here fine | calibration-gated | Slope arbitrary; flag |
| `hrisk = min(100, crit_count*35)` | L640 | High-risk protocol criticals → risk | Count-based OK | arbitrary | Document 35/port rationale or flag |
| `dnsbl_risk = min(100, listed*50)` | L643-645 | DNSBL listings → risk | Counts list **entries** (len of ip+domain listings), not a boolean — OK post Wave-1 DNSBL fix. 50/listing harsh (2 listings=100) | fragile | Depends on DNSBL checker correctly excluding open-resolver `127.x` replies; if upstream fixed, slope still steep — flag |
| `dehashed_risk = min(100, total_entries*2)` guarded by status not in (no_api_key, auth_failed) | L676-677 | Credential count → risk (weight 0.03) | Count-based, status-guarded (no fabrication on absent key). **But confidence-blind**: 13 stale email-only == 13 fresh passwords (the 5L problem) | calibration-gated | **Top-3 leverage.** Replace with confidence-weighted credential class per `credential_confidence_pbreach_design.md` K1-K7 (DBIR/Mandiant/Sophos SA). FIN-9 |
| `shodan_risk *= 1.3` (weaponized) / `*1.1` (PoC), cap 100 | L669-672 | Boost CVE risk for weaponized/PoC exploits | Count-gated (>0). Multipliers arbitrary | arbitrary | Document or anchor to EPSS/KEV exploit-maturity |
| `vpn_risk = 40 if rdp_exposed else (20 if not vpn_detected else 0)` | L660 | RDP/VPN posture → risk | Boolean-driven flags (legitimately boolean) — OK | fragile | "no VPN detected = 20" risks penalising orgs whose VPN isn't externally visible; flag basis |
| Score defaults via `inv(...score, DEFAULT)` (ssl 50, email 5/10, http 50, tech 100, vt 100, st 100, fd 100, pc 100, wr 30, id 100, ext_ip 100) | L623-744 | Fallback risk when checker absent | **Fabrication-on-absent screen:** most default to 100-score→0-risk (safe, no false penalty) OR are status-guarded to 0. `web_ranking` default 30→70 risk if absent is a mild penalty-on-absent | fragile | wr default 30 invents risk when ranking unknown; prefer redistribute (status-skip) over a baked-in penalty |
| WAF bonus −50 (full) / −25 (blinding WAF) | L797-802 | Web-control credit, halved when WAF blinded the scan | Anti-inversion design (correctly discounts blinded credit) — good. Magnitudes arbitrary | calibration-gated | −50/−25 vs measured WAF efficacy; flag |
| Risk-level bands 600/400/200 (Critical/High/Medium/Low) | L806-811 | 0-1000 → label | Arbitrary cutpoints; cosmetic | calibrationarbitrary | Document; align with premium tiers |
| Redistribution `scale = (remaining+excluded)/remaining` | L611-620 | Reallocate failed/skipped weight | Correct conservation logic — no failure mode | justified | Sound |
| `completeness_pct = 1 - failed/assessable` | L843 | Scan-completeness % | Correct (skipped excluded from denominator) | justified | Sound |
| COMPLIANCE_MAP control weights (0.6-1.2); pass/partial/fail at 70/40 | L236-460, L889-893 | Framework % via weighted sub-control avg | 70/40 cutoffs arbitrary but cosmetic; weights expert-set | arbitrary | Document; not a scoring input to p_breach |

## B. RansomwareIndex (RSI, 0.0-1.0)

| Heuristic (value) | Location | What it does | Failure-mode / anchored? | Class | Recommendation / anchor |
|---|---|---|---|---|---|
| `base = 0.05` inherent | L1003 | Floor exposure | Documented (internet-exposure baseline) | calibration-gated | Modest; flag |
| RDP +0.25 | L1009-1011 | #1 ransomware vector | Boolean flag (legit). Sized as dominant single signal (documented) | calibration-gated | Anchor vs Mandiant/Sophos RDP initial-access share |
| DB ports +0.10 each, cap 0.20 | L1014-1019 | Exposed DB ports | Count-based, port-allowlisted — OK | calibration-gated | Slope/cap vs anchor |
| Credential class +0.20/+0.15/+0.08/0 (CRIT/HIGH/MED/LOW) | L1026-1039 | `credential_risk.risk_level` → RSI | **Confidence-aware (the precedent 5L wants to match)** — uses level not raw count; LOW=0 (no fabrication). Sophos SA 34% cited | calibration-gated | Already the good pattern; values still FIN-9. Anchor: Sophos SA creds #1 (34%) |
| KEV +0.08 each cap 0.20; high-EPSS(>0.5) +0.04 cap 0.12; other crit/high +0.02 cap 0.08 | L1042-1064 | CVE severity → RSI | Count-based, KEV/EPSS-gated — OK | calibration-gated | Slopes/caps vs EPSS exploit-probability |
| info_disclosure +0.02/crit cap 0.08 | L1069-1075 | Critical exposed files | Count-based, risk_level=="critical" gated — OK | calibration-gated | Flag |
| No DMARC +0.08 / policy none +0.05 | L1081-1087 | Email vector | Boolean — OK. Sophos SA 22% cited | calibration-gated | Anchor to DMARC efficacy (CISA BOD 18-01) |
| No WAF +0.05; weak SSL (D/E/F) +0.05 | L1090-1098 | Hygiene | Boolean — OK | calibration-gated | Flag |
| SUPPLY_CHAIN_CAP 0.22 + S-10/S-3/S-2/S-4/S-1 sub-factors (0.02-0.05) | L1131-1231 | SC vectors, proportionally scaled under cap | Status=="completed"-gated (no fabrication); cap+rescale documented vs RDP 0.25; DBIR 30% / Patchstack / Mandiant cited | calibration-gated | Well-reasoned; values FIN-9. Anchor: DBIR third-party 30% |
| Glasswing −0.05 (favourable), floor base≥0 | L1236-1247 | AI-vuln-programme credit | Observable-signal-gated, floored — OK | arbitrary | −0.05 undocumented magnitude; flag |
| `_diminishing`: linear ≤0.5, `0.5+0.5(1-e^-2x)` above | L988-999 | Anti-stacking compression | Math sound; −2.0 rate arbitrary | calibration-gated | Curve shape vs target distribution; flag |
| INDUSTRY_MULTIPLIER 0.80-1.30 | L967-986 | Ransomware-targeting uplift | Sophos/CheckPoint baseline; SA adj public-sector only; rest "require SA calibration" (self-documented) | calibration-gated | SA ransomware-targeting data |
| Size multiplier 0.85-1.12 by revenue band | L1265-1286 | Maturity-by-size | Bands aligned to Sophos SA median R200M (documented) | calibration-gated | Flag bands |
| RSI label bands 0.75/0.50/0.25 | L1290 | Label | Arbitrary cutpoints | arbitrary | Document |

## C. FinancialImpactCalculator — ZAR path (`_calculate_zar`, the live underwriting path)

| Heuristic (value) | Location | What it does | Failure-mode / anchored? | Class | Recommendation / anchor |
|---|---|---|---|---|---|
| `vulnerability = (100 - _overall_score/10)/100` | L2037-2038 | Posture score → 0-1 vulnerability | **Now live (Wave-1 wired `_overall_score`; was pinned at 0.5).** Linear map never validated against working coupling | calibration-gated | **TOP-1 leverage** (§6b). Curve shape vs DBIR/IBM base rates. FIN-9 |
| `p_breach = vulnerability × TEF × 0.3` | L2107 | FAIR LEF | **The `0.3` is the single highest-leverage constant** — scales every breach-family probability. Never validated post-coupling | calibration-gated | **TOP-2 leverage** (§6b). Anchor absolute p_breach for a worst-posture org vs DBIR/IBM industry base rate. FIN-9 |
| TEF table 0.80-1.45 | L1840-1859 | Industry targeting frequency | DBIR/IBM/Sophos/SABRIC cited; range deliberately modest (documented) | calibration-gated | Per-industry SA targeting; flag |
| SC vulnerability uplift: Magecart +0.06, S-1 +0.04, S-5 crit +0.04/high +0.02, cap +0.15 | L2066-2104 | Direct p_breach uplift for SC paths | Status-gated (no fabrication); DBIR 30%/IBM CoDB/Mandiant cited; cap documented; no double-count w/ cat-tail (design note) | calibration-gated | Values FIN-9; anchor DBIR/IBM CoDB |
| IBM_BREACH_TOTAL R49.22M; MEDIAN_REVENUE R200M; C4_PROPORTION 0.1040 | L2120-2122 | Severity anchor + ransom share | IBM SA + Sophos SA derivation shown (R8M×64%) | calibration-gated | Refresh each IBM/Sophos annual; flag drift |
| Elasticity 0.35-0.60 by revenue band | L2124-2139 | Revenue→severity scaling exponent | Graduated, documented intent; exponents arbitrary | calibration-gated | Anchor to IBM revenue-regression |
| Graduated industry multiplier (only if >1.0) | L2150-2155 | Small-co data-density discount | Reasoned (documented) | calibration-gated | Flag |
| `record_density_divisor` (R5k-R1M/record by industry) | L2180-2210 | est. records (reference/disclosure only, **not in cost calc** — documented) | Not a cost input; disclosure transparency | fragile | SA-market observation, not sourced; flag but low-leverage |
| `records_validity_ceiling` (50k-500k) | L2225-2257 | Floor-estimate disclosure trigger | Disclosure only; documented vs IBM regression window | arbitrary | Document basis; non-scoring |
| C2 POPIA `min(10M, rev×0.02)` | L2272-2273 | POPIA fine (expected) | 2% explicitly flagged "internal heuristic, NOT statutory"; R10M ceiling correct | calibration-gated | Enforcement-discount % (OUTSTANDING §6) |
| C2 GDPR rev×0.04 (flag-gated); PCI R1M×(1−adj); EXTERNAL_PCI_VISIBILITY 0.30; other R2M/jurisdiction | L2275-2295 | Per-jurisdiction fines | Flag-gated (no fabrication). 0.30 visibility documented; R2M arbitrary | calibration-gated | PCI visibility + R2M vs SA precedent |
| Cat stack (ECTA R1M, CPA max(R1M,10%rev), capacity_factor 0.10-1.00, SECTOR_FRAMEWORKS statutory maxima, FSCA R100M assumption) | L1356-1484, L2301-2348 | Statutory-max cat stack, capacity-scaled | Statutory maxima sourced (gap-analysis v10); FSCA R100M flagged as model assumption; **STALE-TABLE risk** (statutory maxima change by amendment) | calibration-gated | Re-verify statutory maxima annually (stale-table). Capacity bands flag |
| C5 IR tier R250k-R5M by revenue | L2365-2382 | DFIR cost | Reasoned bands; arbitrary magnitudes | calibration-gated | SA DFIR market data |
| INDUSTRY_BI_FACTOR 0.05-1.75 (86 sub-industries) | L1877-1977 | Downtime cost allocation (conservation, not inflation — documented) | Sourced from FAIR lookup tables; exact, no averages | justified | Cited lookup-table source |
| SA_AVG_DOWNTIME 25d; IMPACT_FACTOR 0.50 | L2399-2401 | C3 downtime | Sophos SA cited; 0.50 documented as recovery-curve avg | calibration-gated | Anchor 25d/0.50 to Sophos SA |
| INCIDENT_SPLIT_RATIOS (0.05-0.50) | L1986-1993 | Incident-type decomposition | Sophos SA 2025 derivation shown (60%×39%≈0.25) | calibration-gated | Refresh vs Sophos SA annual |
| Per-incident downtime/cost modifiers (silent ×0.60 C5, extort C4×0.40, opp C1×0.50/C5×0.40, C3 2d/3d/1d/5d) | L2459-2519 | Incident cost shaping | Reasoned; magnitudes arbitrary | calibration-gated | Flag |
| `loss_pct` → fin_score steps 0.30/0.15/0.08/0.04 → 10/30/50/70/90 | L2786-2798 | Loss% → 0-100 financial score | Step function arbitrary; **note:** this `score` feeds `fin_risk` back into posture (weight 0.02) — mild circularity, low weight | fragile | Document steps; circularity acceptable at 0.02 |
| `p_interruption` 0.05 base + 0.05 each (WAF/CDN/single-ASN), cap 0.5 | L2109-2115 | BI/DDoS probability | Boolean signals — OK | calibration-gated | Flag |
| SA_INDUSTRY_COSTS (breach_cost_zar, cost_per_record, multiplier) | L916-941 | IBM-2025-ZAR per-industry anchors | "IBM 2025 translated to ZAR" — sourced | calibration-gated | Refresh annually (stale-table); flag |

## D. Monte Carlo / PERT / GPD / return periods

| Heuristic (value) | Location | What it does | Failure-mode / anchored? | Class | Recommendation / anchor |
|---|---|---|---|---|---|
| MC_ITERATIONS 50_000 | L1326 | Sim count for stable P99.6 (~200 tail) | Documented (wall-time/Render-memory tradeoff) | justified | Sound |
| `np.random.seed(42)` | L1750, L2550 | Determinism | Reproducible output — intentional | justified | Note: identical seed both paths; fine |
| PERT λ=4 | L1337 | Standard PERT shape | Standard | justified | Standard |
| PERT spreads: total_breach 0.5×/5.0× (was 2.5×, widened B3); mc_c2 upper=cat_stack; downtime PERT(3,25,120); component 0.5×/2.5× | L2564-2583 | MC bounds | Widening documented (Transnet/Life/Experian precedent) | calibration-gated | Tail recalibration vs SA cat data (OUTSTANDING §6) |
| GPD MOM (shape=0.5(1−m²/v), scale=0.5m(1+m²/v)); sanity guards (n<50→raw, fitted<raw→raw, >10×raw→raw) | L1486-1551 | Tail extrapolation for return periods | Pure-numpy MOM (no scipy, Render constraint, documented); guards prevent overshoot | justified | MLE upgrade deferred (OUTSTANDING §6); guards sound |
| K_TAIL 1.20 (WAF blind-spot tail widening), shortfall cap 0.60 | L2670-2671 | Widen P75+ when WAF blinded scan | EPISTEMIC-uncertainty design (correctly NOT via p_breach; restores P5-P50 + mode); documented | calibration-gated | SCN-029: calibrate vs blinded-vs-rescan deltas. **Do NOT re-add K_TAIL_SC** (double-count, design note L2700) |
| Return-period mapping P99/P99.5/P99.6 → 1-in-100/200/250 | L2997-3005, L3009-3017 | Percentile → return period | Mathematically correct (1/(1−q)); prefers GPD-fitted | justified | Correct |
| SME_BANDS snap (R1M…R15M, then R5M increments) | L2763-2772 | Cover-band snapping (deprecated/internal) | Cosmetic; cover no longer recommended (FAIS) | justified | Deprecated path |
| `_DEDUCTIBLE_TABLE` (RSI 0.10-1.00 → 0.5%-20%), clamp ≥0.10 | L1600-1631 | RSI → deductible % | Non-linear interp; magnitudes arbitrary | calibration-gated | Actuarial deductible curve |

## E. DataBreachIndex (DBI, 0-100, higher=better)

| Heuristic (value) | Location | What it does | Failure-mode / anchored? | Class | Recommendation / anchor |
|---|---|---|---|---|---|
| breach_count 0→30 / ≤3→15 / else 0 | L3234-3242 | Count points | Count-based — OK | arbitrary | Document cutoffs |
| recency <365d→0 / <1095d→10 / else 20; except→10 | L3244-3261 | Recency points | Date-parsed (real recency, not boolean); except-fallback 10 reasonable | justified | Date-anchored, sound |
| data_severity: severe-class set → 0 / emails-only→10 / none→15 | L3263-3273 | Sensitivity points | Curated severe-class set; **stale-table risk** (HIBP class names) | fragile | Verify against current HIBP `data_classes` vocabulary periodically |
| credential_leaks: unknown→10 / 0→20 / ≤100→10 / else 0; status-guarded `-1` | L3275-3289 | Dehashed volume points | Status-guarded (no fabrication on absent key) — good | arbitrary | Cutoff 100 arbitrary; document |
| trend: recent(<730d) 0→15 / ≤2→7 / else 0 | L3291-3312 | Trend points | Date-parsed — OK | justified | Date-anchored |
| DBI label bands 80/60/40/20 | L3314-3315 | Label | Cosmetic | arbitrary | Document |

## F. RemediationSimulator + MITIGATIONS

| Heuristic (value) | Location | What it does | Failure-mode / anchored? | Class | Recommendation / anchor |
|---|---|---|---|---|---|
| `RSI_RESIDUAL_FLOOR = 0.05` | L3341 | RSI floor (no posture risk-free) | Set heuristically (Wave 4); mirrors RSI base 0.05 | calibration-gated | §6b: ~81% modelled loss-cut now a calibration Q. FIN-9 |
| `MAX_RSI_REDUCTION_FRACTION = 0.15` | L3342 | Residual ≥15% of current RSI | Wave-4 heuristic; mirrors 85% loss cap | calibration-gated | §6b. FIN-9 |
| REMEDIATION_MAP rsi_reduction values (0.01-0.35) | L3344-3429 | Per-fix RSI delta | Mirror RSI factor weights (RDP 0.35 etc); condition_fns status/count-gated (no fabrication); ghost-audit closed (5 added 2026-05-27) | calibration-gated | Must track RSI factor sizes; flag |
| savings `= (rsi_reduction/current_rsi) × total_likely × 0.7` | L3446 | Per-step savings | 0.7 realisation factor arbitrary | arbitrary | Document 0.7 |
| 85% total-savings cap | L3190-3196 (`_build_mitigations`), L3477 floor | Can't eliminate all risk | Internally consistent w/ RSI floor — good | justified | Sound |
| MITIGATIONS reductions (rsi/probability/bi 0.02-0.25) | L3063-3093 | Incident-family deltas | Regex-pattern-matched on issues (substring risk: e.g. `r"SSL.*grade.*(C\|D\|F\|T)"` could mis-match) | fragile | Patterns brittle; align values w/ REMEDIATION_MAP; flag |

## G. Peer benchmarking interplay (module: `peer_benchmarking.py`)

Out-of-file but in-scope as interplay: peer module **consumes** `rsi_score` / `risk_score`
outputs of this module and resolves the revenue band "the SAME way the FinancialImpactCalculator"
capacity-factor table does (peer_benchmarking.py L25, L300). Note `rsi_score or 0.5` fallbacks
(peer L338/L420) — a fabrication-on-absent screen point, but it lives in the peer module, not here.
Cohort-bias correction is calibration-gated (OUTSTANDING §6, `lower_tier_upsell`). No correctness
bug in this module's side of the interface.

---

## Summary

**total = 56**  •  **justified = 13**  •  **fragile = 11**  •  **arbitrary = 12**  •  **calibration-gated = 36**
*(counts exceed 56 because several rows carry a primary class plus a secondary stale-table/fragility flag; primary-class tally: justified 13 / fragile 11 / arbitrary 12 / calibration-gated 36 ≈ the dominant bucket).*

### The 3 highest-leverage calibration constants (all FIN-9, do NOT intuit)
1. **`0.3` in `p_breach = vulnerability × TEF × 0.3`** (L2107) — scales every breach-family
   probability; never validated since Wave-1 made the `_overall_score` coupling live. Anchor:
   DBIR / IBM CoDB absolute breach base rates.
2. **`vulnerability = (100 − _overall_score/10)/100`** (L2038) — the posture→probability curve,
   first time coupled to a real score. Anchor: DBIR/IBM base-rate calibration of the curve shape.
3. **`dehashed_risk = min(100, total_entries × 2)`** (L677) — confidence-blind credential input;
   the 5L pre-read's whole purpose. Replace with the confidence-weighted credential class
   (`credential_confidence_pbreach_design.md` K1-K7). Anchor: Sophos SA (creds #1, 34%) + DBIR/Mandiant.

### Genuine correctness bugs found in THIS module
**None new.** All five back-test failure modes were screened:
- **Fabrication-on-absent:** every API-keyed checker (dehashed, virustotal, securitytrails, GDPR/PCI
  flags) is status- or flag-guarded before contributing — no invented values. The only mild
  penalty-on-absent is `web_ranking` default score 30 → risk 70 (L703) — *fragile, not a bug*
  (prefer redistribution over a baked-in penalty).
- **Boolean-as-count:** the count-based maps (breach_count, dehashed total_entries, dnsbl listings,
  KEV/EPSS counts) all consume real integers, not booleans. DNSBL counts list **length** (L643-645),
  correctly avoiding the "13 with passwords" class of bug.
- **Inversion:** none — the WAF bonus (L797) and WAF blind-spot K_TAIL (L2663) are explicitly
  designed *against* inversion (blinded scans are discounted / tail-widened, not rewarded).
- **Stale-table:** flagged (not bugs today) on `SECTOR_FRAMEWORKS` statutory maxima (L1374),
  `SA_INDUSTRY_COSTS` / `IBM_BREACH_TOTAL` (annual IBM/Sophos refresh), and DBI's severe-class set
  / HIBP `data_classes` vocabulary (L3265) — add a periodic-refresh check.

The module's correctness was materially improved by the 2026-06-03 Wave 1-5 fixes (especially wiring
`_overall_score` into `vulnerability`, which had been pinned at 0.5). The residual work is almost
entirely **calibration**, correctly deferred to FIN-9 + the 5L credential-confidence session — not
correctness. The dominant audit finding is that **36 of 56 heuristics are calibration-gated**, which
is expected for the calibration-heaviest module and consistent with OUTSTANDING §6/§6b.
