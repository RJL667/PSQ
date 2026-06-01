# Calibration pre-read — confidence-weighted credential contribution to p(breach)

**For:** FIN-9 calibration session, 2026-06-03 (with colleague — international breach-cost experience)
**Status:** design + calibration knobs laid out; **numbers are placeholders to be set live against the anchors below.** Do not ship before the 2-step gate + sanity-check.
**Relates to:** OUTSTANDING `5L`, the §6 "Credential-risk scoring calibration" ticket, and the cat-tail no-double-count rule.

---

## 1. One-paragraph problem statement

The financial model's credential input to the **probability of breach** is a raw
count — [`dehashed_risk = min(100, total_entries × 2)`](../scoring_analytics.py#L669)
(weight `0.03`) — which flows into the overall posture score → `vulnerability` →
[`p_breach = vulnerability × TEF × 0.3`](../scoring_analytics.py#L2099). It is blind
to **confidence** (was a credential actually captured, or is this just a browser-History
visit?), **recency** (fresh infostealer vs a 6-year-old combo list), and
**password-presence**. So today **13 stale, low-confidence, email-only appearances move
p(breach) exactly as hard as 13 freshly-stolen passwords.** The catastrophe model
(severity / loss given breach) is fine — this is purely about the *probability* input.

## 2. The precedent we are matching (this is not a new mechanism)

| Path | Credential input today | Confidence-aware? |
|---|---|---|
| **RSI** (ransomware susceptibility) | [`credential_risk.risk_level`](../scoring_analytics.py#L1018) → `+0.20 / +0.15 / +0.08 / 0` for CRIT/HIGH/MED/LOW, **replacing** raw counts | **Yes** |
| **p(breach)** (financial model) | raw `dehashed_total × 2` → vulnerability → p_breach; plus HIBP `breach_count` → a separate scenario p_breach ([L1664](../scoring_analytics.py#L1664)) | **No** |
| **Export** (on-demand CSV) | full `match_type → confidence` model (`credential_export.py`) | Yes, but **downstream / reporting-only** |

**The design = give p(breach) the same confidence-aware credential input RSI already
has**, enriched with the new `match_type` + recency signals, and **replace** the raw
count (do not add — see §6).

## 3. Proposed model

### 3.1 Classify at scan time — no PII in the scored path
For every credential signal, derive `(has_password: Y/N, match_type, recency_band)`.
**The plaintext password is never needed for scoring** — only the boolean + metadata.
Passwords stay in the consented encrypted export. (POPIA-clean by construction.)

`match_type → confidence` (already implemented in the export; reuse verbatim):

| Confidence | match_type | Meaning |
|---|---|---|
| **high** | `plaintext_password`, `password_store`, `autofill`, `credit_cards` | a secret was actually captured |
| **medium** | `hashed_password`, `cookies` | hash (crackable) or live session token |
| **low** | `email_only`, `browser_history`, `aggregated_domain_index` | exposure/visit only — no credential in hand |

### 3.2 Collapse to a confidence-weighted credential class (None → Critical)
Weight each record by confidence × recency-decay, sum, and threshold into a class —
analogous to `credential_risk` but incorporating match_type + recency. The class then
feeds p(breach) the same graduated way RSI is fed.

### 3.3 Wire into p(breach), replacing the raw count
Replace the `dehashed_total × 2` term with a `credential_confidence_contribution`
(class → contribution). Keep it as an **observed-risk probability uplift (pre-MC)**,
consistent with the cat-tail design (observed → p uplift; unobserved → K_TAIL).

## 4. Calibration knobs — **the table to fill tomorrow**

> Leave blank / placeholder now; set against the anchors in §5. Be deterministic.

| # | Knob | Placeholder | Anchor that should set it |
|---|---|---|---|
| K1 | Confidence multipliers (high / med / low) | `1.0 / 0.4 / 0.1` ? | Ratio of breach likelihood given a *captured credential* vs a *mere exposure* (DBIR/Mandiant initial-access shares) |
| K2 | Recency decay (per band, <30d … >2yr) | full → 0.?? at >2yr | Infostealer freshness vs combo-list reuse; how fast stolen-cred value decays (IBM CoDB dwell + reuse data) |
| K3 | Combo-list discount (re-circulated) | ×0.?? | COMBO_LIST_SOURCES are re-packaged historical data — should not read as fresh |
| K4 | Class thresholds (None/Low/Med/High/Crit cutoffs on the weighted sum) | TBD | Align top class with "active compromise" (Sophos SA 2025: creds #1 root cause, 34%) |
| K5 | Class → p(breach) contribution (analogue of RSI's +0.20/+0.15/+0.08) | TBD | Calibrate so a CRITICAL credential class yields a defensible absolute p(breach), cross-checked vs DBIR/IBM base rates |
| K6 | Contribution cap | TBD | Prevent a single channel dominating p(breach); keep within the vulnerability budget |
| K7 | Low-confidence floor | `0` or small ε? | **Decision:** does fresh-but-low-confidence (e.g. a History visit) contribute *nothing* to p(breach), or a small monitoring floor? |

## 5. Empirical anchors to calibrate against

- **Verizon DBIR 2025** — stolen-credential involvement in breaches; use-of-stolen-creds initial-access share. Sets K1, K5 base rates.
- **Mandiant M-Trends 2025** — stolen credentials = **#2 initial-access vector (16%)**, exploits #1 (33%). Sets the relative weight of credentials vs other vectors (so we don't over-rotate p(breach) onto creds).
- **IBM Cost of a Data Breach 2024** — credential-based breach frequency + dwell time; informs K2 recency decay.
- **Sophos SA 2025** — credentials = **#1 root cause (34%)** (already cited in the RSI code). Local anchor for K4/K5 top class.
- **Infostealer vs combo-list reuse** (HudsonRock / SpyCloud reporting) — how much fresh infostealer captures out-rank recycled combo lists. Sets K2/K3.
- **Cross-check:** the resulting absolute p(breach) for a "CRITICAL credential" org must sit sensibly vs the industry base rate already encoded in TEF — not double the whole-industry frequency off one signal.

## 6. No-double-count discipline (hard rule)

- **Replace** `dehashed_total × 2`, do not stack on top of it.
- The HIBP `breach_count` scenario path ([L1664](../scoring_analytics.py#L1664)) overlaps — decide whether it folds into the new class or stays separate (open question Q3).
- `credential_correlation` stays **reporting-only**; we are promoting a *confidence-weighted credential class*, not the correlation card, into the score.
- Consistent with the cat-tail rule: observed risk → probability uplift (pre-MC); unobserved → K_TAIL (untouched here).

## 7. Verification plan (after calibration)

1. `py tooling/verify_supply_chain_financial_wiring.py` (expect 31/31).
2. `py tooling/verify_scan_smoke.py` (exit 0 — this is a scan-path/scoring change).
3. Present **per-checker p(breach) deltas** for phishield + a high-confidence reference target, and run the AskUserQuestion sanity-check against the §5 anchors. Iterate K1-K7 until calibrated.
4. Only then commit + push (both remotes) → Render.

## 8. Open questions for the session

- **Q1** — Refine the existing `CredentialRiskClassifier` in place (superseding the §6 ticket: cap IntelX per-mention, date-gate HR CRITICAL) and feed its richer output to *both* RSI and p(breach)? Or add a parallel `credential_confidence` layer and leave the classifier alone?
- **Q2** — Low-confidence freshness (K7): zero contribution, or a small monitoring floor that only lifts on content-fetch confirmation?
- **Q3** — Does the HIBP `breach_count` scenario p(breach) ([L1664](../scoring_analytics.py#L1664)) fold into the new class, or remain a separate scenario?
- **Q4** — Content-fetch-unconfirmed dumps default to **low** until confirmed — agreed? (Interim control already documented in Manual §6.4.)

## 9. Decisions already made — do not relitigate

- **POPIA:** scored/rendered path sees only `has_password (Y/N)` + class; real passwords live only in the consented encrypted export.
- **Cat model unaffected** — this changes the *probability* input only.
- **match_type → confidence tiers** as defined in §3.1 (already shipped in the export).
- This is a **scoring change → calibration-gated**: no shipping on intuited factors; numbers come from §5 anchors + the sanity-check.
