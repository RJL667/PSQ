# Calibration Prep 01 — p(breach) core

**Parameter group:** the posture→probability curve (`vulnerability`) and the `0.3`
multiplier in `p_breach = vulnerability × TEF × 0.3`.
**Status:** SANDBOX PREP — *proposed* values for the 2026-06-03 calibration session.
**NOT applied to production.** No edits made to `scoring_analytics.py`.
**Author:** calibration team (dev / domain-expert / critic / orchestrator roles).

---

## TL;DR

There are **two** issues, not one:

1. **CORRECTNESS (headline, not calibration):** the current curve is **inverted**.
   `vulnerability = (100 − _overall_score/10)/100` assumes the score rises as posture
   *improves*. But `_overall_score` is **0–1000 where HIGHER = WORSE** (`scoring_analytics.py`
   L807: `Critical if risk_score >= 600 … Low` below 200). So a **good** org (phishield,
   169 = Low) is assigned `vulnerability = 0.831` and a **terrible** org (900) is assigned
   `0.10`. The curve is **backwards**. This must be fixed before any calibration of the
   constant is meaningful — and it is a *bug*, so it is arguably not gated by the
   "scoring-change = calibration-gated" rule, but is in-scope here because it lives on the
   exact line we were asked to calibrate.

2. **CALIBRATION (the actual ask):** even once corrected, the *shape* (linear vs convex)
   and the `0.3` constant set the absolute p(breach). Anchored to BitSight / Cyentia /
   SecurityScorecard loss-event base rates, a **convex curve `(score/1000)^k` with k≈1.8
   and the existing `0.3` retained** reproduces sane absolute values (good org ≈ 1.8 %/yr,
   weak org ≈ 26 %/yr).

---

## Parameter table

| Param | Current | Proposed (range) | Confidence | Empirical anchor (sources) | Recompute result | Open question for colleague |
|---|---|---|---|---|---|---|
| `vulnerability` curve | `(100 − score/10)/100` — **inverted**: good org→0.831, worst org→0.10 | **Correct the direction + make convex:** `vulnerability = (score/1000)**k`, **k = 1.8** (range **1.5–2.0**) | **Direction fix: data-supported (high).** Convexity & k: **reasoned-extrapolation (medium)** | Score direction confirmed in code (L807). Convex shape matches **SecurityScorecard** relative ladder A=1.0 / B=2.9× / C=5.4× / D=9.2× / **F=13.8×** (steeply convex). **BitSight/Marsh** absolute: rating ≥700→**<1%**, <500→**~3%** annual. | phishield 169(Low): **0.831 → 0.041** vuln. Monotonic ↑ with worse posture, bounded [0,1] (verified k∈{1.5,1.8,2.0}). | Is convex `(s/1000)^1.8` the right shape, or do you prefer a logistic/piecewise mapping pinned to the four risk bands (Low/Med/High/Crit)? |
| `0.3` multiplier | `0.3` | **Retain 0.3** (range **0.20–0.35**) — **conditional on adopting the convex curve.** If a *linear* curve is chosen instead, drop to **~0.06–0.10**. | **Conditional (medium).** Data sets the *output* range; the constant is the free scalar to hit it | IBM CoDB **SA $2.37M** (loss model anchor); **Cyentia IRIS**: SMB loss-event **<2%/yr**, F1000 ~25%/yr; SA survey "any attack" 40–50% (*attempt*, not loss — do **not** anchor here). | With convex k=1.8 & 0.3: good=**1.8%**, Medium=**5.0%**, High=**10.3%**, Critical=**20%**, worst=**36%** (TEF=1.45). Brackets the 1–3% strong/weak band + leaves a defensible tail. | Anchor p(breach) to the **loss-event** base rate (1–3% SME, my assumption) or to a broader "material incident" rate? This single choice moves the constant ~3–5×. |

---

## Recompute detail (throwaway python, no production edit)

Score scale **0–1000, higher = worse** (bands: <200 Low, 200–399 Med, 400–599 High, ≥600 Critical).
TEF = 1.45 (Financial Services, phishield's industry).

**Current formula (inverted) vs proposed convex `(s/1000)^1.8 × TEF × 0.3`:**

| Posture | score | CURRENT p_breach | PROPOSED p_breach | Empirical target (annual loss-event) |
|---|---|---|---|---|
| excellent | 50 | 0.391 | **0.002** | ≪1% |
| **phishield (Low/good)** | **169** | **0.361** | **0.018** | <1–2% (BitSight strong / Cyentia SMB) |
| Medium | 300 | 0.304 | **0.050** | ~3–5% |
| High | 450 | 0.239 | **0.103** | ~5–10% |
| Critical | 650 | 0.152 | **0.200** | ~15–25% |
| worst | 900 | 0.043 | **0.360** | tail / weak-posture upper bound |

**Note the inversion in the CURRENT column:** p_breach *falls* as posture worsens
(0.391 at score 50 → 0.043 at score 900). The proposed column is correctly **monotonic
increasing** and bounded [0,1] (asserted over s = 0…1000 for k = 1.5/1.8/2.0).

Worked single-line check for phishield (169, Financial Services):
- Current: `vuln=(100−16.9)/100=0.831 → 0.831×1.45×0.3 = 0.3615` (matches the live fixture
  `probability_drivers.p_breach = 0.3615` — confirms the formula as wired).
- Proposed: `vuln=(169/1000)^1.8=0.041 → 0.041×1.45×0.3 = 0.018`.

---

## Rationale & honesty labelling

- **The base-rate distinction is the crux.** SA SME "experienced a cyber attack" surveys
  read **40–50%/yr** (Mastercard, UK Gov Cyber Security Breaches Survey, MySecurityMarketplace).
  But those count *attempts/attacks*. The scanner's `p_breach` feeds a **loss** model
  (IBM-anchored ZAR), so it must anchor to the **material breach / loss-event** rate, which
  Cyentia IRIS puts at **<2%/yr for SMBs** (and ~25% for Fortune-1000). BitSight/Marsh give
  the posture-conditioned version: **<1% strong, ~3% weak**. The proposed curve targets
  this lower, loss-relevant band. *(data-supported)*

- **Why convex, not linear.** SecurityScorecard's empirically-fit ladder (A→F = 1.0→13.8×)
  is strongly convex: risk barely moves across the top grades then accelerates at the bottom.
  A convex `(s/1000)^k` reproduces "a Low org is genuinely safe; risk bites hard only as you
  slide toward Critical." Linear over-penalises mid-posture orgs. *(reasoned-extrapolation —
  the 13.8× spread is data; mapping it onto our 0–1000 scale via a single exponent is a
  modelling choice.)*

- **Why keep 0.3.** With the convex curve, 0.3 already lands the outputs on the empirical
  band, so changing both the curve *and* the constant would be over-fitting two knobs to one
  target. If the room prefers a **linear** curve instead, the constant must fall to ~0.06–0.10
  to avoid a 36% p_breach for a merely-average org. *(conditional)*

- **Ranges, not false precision.** k = **1.5–2.0** and C = **0.20–0.35** are the defensible
  bands; k=1.8 / C=0.3 is the central recommendation. The absolute SME loss-event rate
  (~1–3%) is itself a thin, triangulated number — **needs-colleague** confirmation of which
  base rate (loss-event vs material-incident) we are underwriting to.

- **Interaction note (out of our group but flagged):** the `sc_vuln_uplift` (≤+0.15) and the
  per-industry **TEF** (≤1.45) both multiply/add *after* the curve. Under the current inverted
  curve they were stacking on an already-near-1.0 vulnerability and getting clipped; under the
  corrected convex curve they will have real headroom and behave very differently. The TEF team
  and SC-uplift owners should re-check their magnitudes **against the corrected curve**, not the
  current one.

---

## Sources

- **Cyentia Institute — Information Risk Insights Study (IRIS):** F1000 ~1-in-4/yr loss event;
  SMB loss-event rate **<2%/yr**. https://www.cyentia.com/iris/
- **BitSight / Marsh McLennan correlation study:** rating ≥700 → breach probability **<1%**;
  rating <500 → **~3%**.
  https://www.bitsight.com/blog/these-14-cybersecurity-analytics-can-help-you-make-better-cyber-insurance-decisions
- **SecurityScorecard Scoring 3.0 — Breach Likelihood ladder:** A=1.0, B=2.9×, C=5.4×, D=9.2×,
  **F=13.8×** (relative).
  https://support.securityscorecard.com/hc/en-us/articles/22601556325147-A-Closer-Look-at-Scoring-3-0-Vocabulary-and-Breach-Likelihood
- **IBM Cost of a Data Breach 2025 — South Africa:** average breach **$2.37M** (down from $2.78M).
  https://www.ibm.com/reports/data-breach  ·  https://mea.newsroom.ibm.com/codb-me-findings-2025
- **Sophos State of Ransomware in South Africa 2025:** 60% encryption rate (vs 50% global);
  median ransom demand R17M; recovery ~R23M.
  https://assets.sophos.com/X24WTUEQ/at/tsspfmkhgxkbm4w6r7h/sophos-state-of-ransomware-in-south-africa-2025.pdf
- **South Africa Information Regulator (POPIA):** FY2024/25 **2,374** security-compromise
  notifications (~198/mo); 2025 running at ~284/mo (+40%). (denominator unknown — frequency
  context only, not a per-org rate)
  https://www.itweb.co.za/article/inforeg-exposes-popia-violators-as-data-breaches-mount/kLgB17ezby5M59N4
- **SA / global SME "attacked" surveys (attempt-rate, NOT loss-rate — context only):** ~40–50%/yr.
  Mastercard (46%), UK Gov Cyber Security Breaches Survey 2025 (50% small / 70% medium identify
  breaches/attacks). https://www.mastercard.com/us/en/news-and-trends/stories/2025/small-business-cybersecurity-study.html

---

## Pre-session checklist for the colleague

1. **Confirm the inversion fix** (good org should get LOW vulnerability) — this is a bug, get
   explicit sign-off to correct the direction.
2. **Pick the base rate we underwrite to:** loss-event (~1–3% SME) vs material-incident
   (higher). Sets whether C stays 0.3 (convex) or drops.
3. **Pick the curve family:** convex `(s/1000)^k` (k≈1.8) vs band-pinned piecewise vs logistic.
4. Re-validate TEF and `sc_vuln_uplift` magnitudes **against the corrected curve** (they were
   tuned against the broken one).
