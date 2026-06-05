# Item #18 — SPF qualifier scoring (presence != protection) — Card Verification

**Date:** 2026-06-05 · **Status:** SANDBOX, NOTHING SHIPPED · worktree `blissful-chandrasekhar-0714c9`
(uncommitted) · Awaiting user ship decision + magnitude calibration sign-off.

## Problem (user-reported)
`EmailSecurityChecker._calculate_score` penalised only **absent SPF** and **`+all`**. `~all` (soft-fail)
and `?all` (neutral) scored **identically to the secure `-all` (fail)** terminal — the qualifier was even
parsed by the regex and then **discarded**. So a spoofable `~all` posture (e.g. the gmail.com example,
`~all` + DMARC `p=none`) earned full SPF marks. (DMARC was already correctly policy-graded; DKIM remains
presence-only, which is defensible because DKIM's enforcement teeth come from DMARC alignment.)

## Fix (rule-based, per Card-Verification + anchoring discipline)
`checkers_core.py` (mutator `tooling/_apply_item18_spf_qualifier.py`):
1. `_check_spf` now stores `all_qualifier` (`-`/`~`/`?`/`+`); a **bare `all`** is mapped to `+`
   (implicit Pass per **RFC 7208 §4.6.2**), which also fixes a latent bug where `dangerous = "+all" in
   txt` missed a bare `all`.
2. `_calculate_score` adds a soft-qualifier penalty **gated on DMARC not being at enforcement**:
   `~all` → −1, `?all` → −2, **only when** DMARC policy is not `quarantine`/`reject`.

## Anchoring channel (one-of-four; no double-count)
**Channel 1 — Probability (pre-MC).** `email_security` score → `email_risk` (inverted) → weight **0.06**
(`scoring_analytics.py:507`) → overall risk score → `vulnerability` → `p_breach`. Observed posture raises
probability. One signal, one channel. No severity/tail/reporting-only contribution.

## Data anchors
- **RFC 7208** §4.6.2 (bare `all` ≡ `+all`, Pass) and §4.7 (`-all` Fail is the enforcing default-result).
- **NIST SP 800-177** (Trustworthy Email): `-all` is the recommended hard-fail terminal.
- **M3AAWG** sender best practice: publish `-all`; DMARC `p=quarantine`/`reject` is the enforcement layer.
- The manual already preached `-all` (part3 4.4.1) — this brings the **checker** in line with the manual.

## Truth table (`py tooling/_verify_item18_spf.py` — ALL PASS)
| Case | SPF | DMARC | Score | Note |
|---|---|---|---|---|
| Secure | `-all` | `p=reject` | **10** | no penalty |
| **gmail-style** | `~all` | `p=none` | **7** | −2 DMARC none, −1 `~all` (now flagged) |
| **Guard (no over-correct)** | `~all` | `p=reject` | **10** | `~all` NOT penalised — DMARC governs |
| Guard | `~all` | `p=quarantine` | **9** | −1 quarantine; `~all` NOT penalised |
| Neutral | `?all` | none | **4** | −4 absent DMARC, −2 `?all` |
| Soft, no DMARC | `~all` | none | **5** | −4, −1 |
| Dangerous | bare `all` | `p=reject` | **7** | −3 (bare-`all` now caught) |
| Absent SPF | — | `p=reject` | **7** | −3 |

Qualifier extraction verified incl. bare `all`→`+` and `redirect=`→None.

## Card Verification Protocol — Step 6 (white-box heuristics sweep)
| Heuristic | Value | Classification | Basis |
|---|---|---|---|
| `-all` is the secure terminal; `~all`/`?all` non-enforcing | rule | **justified** | RFC 7208 / NIST SP 800-177 / M3AAWG |
| Bare `all` ≡ `+all` (Pass) | rule | **justified** | RFC 7208 §4.6.2 (fixes a real miss) |
| DMARC-enforcement **guard** on the penalty | `policy in {quarantine,reject}` | **justified** | DMARC governs failing-mail disposition regardless of SPF qualifier; prevents dinging valid `~all`+enforcing-DMARC senders |
| `~all` penalty magnitude | **−1** | **calibration-gated** | conservative; sits between existing `invalid` (−1) and `absent/+all` (−3); flagged for the formal calibration session |
| `?all` penalty magnitude | **−2** | **calibration-gated** | `?all` (neutral) ≈ no assertion, weaker than `~all`; same gate |

**Failure-mode screen:** no fabrication-on-absent-input (qualifier read only when SPF present+valid);
no generic-response-as-signal; no boolean-as-count; **no inversion** (the guard specifically prevents
penalising a well-configured `~all`+enforcing-DMARC domain); no stale table. The two magnitudes are
**calibration-gated and flagged, not intuited** — the *logic* is justified; the *numbers* are tunable.

## Downstream / blast radius
A spoofable `~all`+`p=none` domain now scores ~1 point lower on email_security (of 10), i.e. a small,
correct upward nudge to `p_breach` via the 0.06 weight. Mature `~all`+enforcing-DMARC senders are
unaffected (guard). `-all`/`redirect=` unaffected.

## Gate
- `verify_supply_chain_financial_wiring.py` → **28/28 PASS** (relative deltas; email is not an SC signal).
- `verify_scan_smoke.py` → **exit 0** (79.8s; example.com publishes `v=spf1 -all` → unaffected).

## Item #18c — remediation map wired (2026-06-05, follow-on, DONE)
The soft-fail finding now also drives BOTH remediation surfaces (mutator
`tooling/_apply_item18c_remediation_map.py`; manual `_apply_item18d_manual.py`):
- **RECOMMENDATIONS** (per-finding advice; substring-matched): added `~all` and `?all` keys → "harden to
  `-all`" advice (with the DMARC-enforcement caveat).
- **MITIGATIONS** (expected-loss saving): one entry, pattern `SPF ends with '[~?]all'`, **Medium**,
  `data_breach` family, `probability_reduction = 0.02` (**conservative + calibration-gated** — anchored to
  the existing secondary email-hardening rung: Enable DKIM = 0.02; smaller than full email-auth absence =
  0.08). Label "Harden SPF to a hard-fail policy ('-all')".
- **Verified** (`py tooling/_verify_item18c_remediation.py`): both advice strings resolve; the mitigation
  fires on an injected `~all` finding (Medium, ~R24k saving on phishield R10M) and does NOT spuriously
  fire the absent-SPF mitigation (SPF is present). Manual bullet extended (lock). Verifier 28/28; smoke
  exit 0.
- **Step 6:** the `0.02` saving is the only new knob → **calibration-gated/flagged**; the advice text and
  the pattern are **justified** (RFC 7208 / the item #18 finding).

## Open for user
- **Magnitude sign-off** (the SPF score `−1`/`−2` and the remediation `0.02`) at the calibration session —
  logic locked, numbers conservative.
- Optional follow-on: surface the SPF `all_qualifier` in the email card render (currently only the issue
  string + score reflect it).
- Separate gap (not wired): the **DMARC `p=none`** weakness likewise has no remediation entry (only
  *absent* DMARC does) — same shape as the SPF gap; flag for a future pass if wanted.
