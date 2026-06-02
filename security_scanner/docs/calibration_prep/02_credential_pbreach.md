# Calibration prep — credential signals → p(breach) / RSI (param group 02)

**For:** FIN-9 / 5L calibration session, 2026-06-03 (with colleague — international breach-cost experience)
**Status:** SANDBOX — research-grounded **PROPOSED** values + ranges, NOT final. **No production code edited.** Proposals only.
**Relates to:** `docs/credential_confidence_pbreach_design.md` (the K1–K7 plan), `OUTSTANDING.md` §5 (5L), §6 ("Credential-risk scoring calibration" ticket), §6b (FIN-9 inputs).
**Recompute basis:** `test_fixtures/phishield_live.json` (fixed-code baseline; 13 DeHashed records, 2 plaintext pw, 6 enriched sources, 40 IntelX results / 12 "darkweb").

---

## 0. The problem this group fixes (one paragraph)

Three credential paths into the score are **confidence-blind**:
1. **p(breach)** gets `dehashed_risk = min(100, total_entries × 2)` (weight `0.03`, `scoring_analytics.py` L677/L769) → `_overall_score` → `vulnerability` → `p_breach = vulnerability × TEF × 0.3` (L2107). 13 stale email-only appearances move p(breach) **exactly as hard as** 13 fresh passwords.
2. **RSI** gets `credential_risk.risk_level` → `+0.20/+0.15/+0.08` (L1028–1039) — graduated, but the *level* itself is set by a confidence-blind ladder.
3. The `CredentialRiskClassifier` ladder (`checkers_threats.py` L1839+) deducts **darkweb ×−10/mention and paste ×−3 UNCAPPED** — 12 darkweb mentions = −120, flooring the 0–100 score to 0, and can out-deduct Hudson Rock's flat −50 even when HR is the stronger signal.

**The phishield fixture is the textbook failure case:** its HIGH level + floored-to-0 score is driven by "12 darkweb mentions" that, on inspection of `intelx.recent_results`, are **entirely `Slow-dom-*.txt` aggregated-domain indexes and `History/` browser-visit records — NOT one `Passwords.txt`/`Autofill` capture.** Hudson Rock shows **0 infected employees**. So the signal escalating phishield is low-confidence and mostly old, yet it scores like an active compromise.

---

## 1. Empirical anchors (what the numbers are pinned to)

| Anchor | Figure | Pins |
|---|---|---|
| **Verizon DBIR 2025** | Stolen creds = **22%** of breaches (**#1** initial-access vector); **30%** managed / **46%** unmanaged infostealer-log devices carry corporate creds; 88% of basic web-app attacks use stolen creds | K1 (capture is real & common), K5 base rate |
| **Mandiant M-Trends 2025** | Stolen creds = **#2** vector at **16%** (up from 10%); **exploits #1 at 33%** | Ceiling discipline — creds must NOT out-rotate p(breach) past exploit/RDP/KEV channels |
| **IBM CoDB 2024** | Compromised creds = **16%** of breaches; **292-day** dwell (longest of any vector); **$4.81M** (costliest) | K2 recency decay (long dwell ⇒ slow decay, not a cliff), severity context |
| **Sophos SA 2025** | Compromised creds = **#1 root cause, 34%** (already cited in RSI code) | **Local** anchor — sets the CRITICAL top class |
| **SpyCloud "New Age of Combolists" / 2025–26 Identity Exposure** | Old breach compilations **1–2% still valid**; fresh infostealer ULP **30–60% valid** (samples 60/46/38%), curated combos **up to 98%**; reuse **42% corporate / 65% consumer**; **⅓** of ransomware orgs had an infostealer infection in the **preceding 16 weeks (~112d)** | **K1 high:low ratio (~15–50×)**, **K2 decay shape**, **K3 combo discount** |

**Cross-check (anti-double-count):** the resulting *absolute* p(breach) for a CRITICAL-credential org must sit sensibly vs the industry base rate already in TEF — not double whole-industry frequency off one signal. Because this channel is **weight 0.03 on a 0–100 slot**, even a max contribution (100) moves the posture score only ~3 points, so the cap risk is modest — but RSI (+0.20) is the louder lever and is where over-rotation would bite.

---

## 2. Proposed values

> Multiplier model (per credential record / leak mention):
> **`w = K1[confidence] × K2[recency_band] × (K3 if combo-source)`**, summed to `W`; `W` → class via **K4**; class → contributions via **K5** (p(breach) 0–100 slot) and the existing RSI ladder. Low-confidence records contribute per **K7**.

| # | Param | Current | **Proposed (range)** | Conf. | Anchor | Recompute (phishield) | Open question |
|---|---|---|---|---|---|---|---|
| **K1** | Confidence multipliers high / med / low | none (blind) | **1.0 / 0.4 / 0.1** (low 0.05–0.15; med 0.3–0.5) | **data-supported** | SpyCloud: fresh-valid 30–60% vs old-valid 1–2% ⇒ high:low ≈ 15–50×; 0.1 low sits mid-band | high=ALIEN TXTBASE pw records; all 11 others low | Is low=0.1 already too generous given 1–2% validity? Could go 0.05 |
| **K2** | Recency decay per band (<30d…>2yr) | none | **<30d 1.0 / 30–90d 1.0 / 90–180d 0.8 / 180–360d 0.6 / 1–2yr 0.4 / >2yr 0.25** (>2yr floor 0.2–0.3) | **reasoned** (anchored) | IBM 292-d dwell ⇒ no fast cliff; SpyCloud 16-wk infostealer→ransomware ⇒ full weight to ~90d | phishield sources mostly >2yr (Apollo'18, Canva'19, Nitro'20) → heavy decay | Plateau to 90d or start decay at 30d? Colleague call |
| **K3** | Combo-list discount (×) | none | **×0.3** (0.25–0.4) | **reasoned** | SpyCloud: combos *can* be fresh (up to 98%) BUT only with infostealer provenance; default-discount the re-circulated case | ALIEN TXTBASE, Apollo, SocRadar all combo → pw records 0.12 each | ALIEN TXTBASE is dated 2024-12 (recent) **and** combo — does fresh+combo deserve less discount? **(biggest tension below)** |
| **K4** | Class thresholds on `W` (CRIT/HIGH/MED/LOW) | n/a | **CRIT ≥4 / HIGH ≥2 / MED ≥0.8 / LOW ≥0.2 / else NONE** | **reasoned** | Tuned so 5 fresh password captures→CRIT; 13 old email-only combos→NONE; Sophos SA 34% = top class = "active compromise" | **phishield W=0.59 → LOW** (was HIGH) | A *single* fresh password capture lands MEDIUM (W=1.0) — should it be HIGH? |
| **K5** | Class → p(breach) contribution (0–100 slot, ×0.03) | `dehashed_total×2`, cap 100 | **CRIT 100 / HIGH 70 / MED 35 / LOW 10 / NONE 0** | **reasoned** | Same 0–100 scale as the slot it replaces; graduated like RSI | **phishield 10** (was 26) → posture delta 0.30 pt (was 0.78) | Keep on 0.03 slot, or promote to a small direct vulnerability uplift like the SC channel? |
| **K6** | Contribution cap | 100 (implicit) | **100** (keep) | data-supported | One channel at weight 0.03 can't dominate; cap already non-binding | n/a | Only revisit if K5 is promoted off the 0.03 slot |
| **K7** | Low-confidence-fresh floor into p(breach) | n/a | **0** (no monitoring floor in the *score*; surface in *report* only) | **reasoned** | A fresh `History/` visit ≠ raised breach probability; export disclaimer already says "monitoring, not theft" | phishield IntelX mentions (all low-conf) → **0** contribution ✓ | Tiny ε (e.g. LOW floor 5) on *content-fetch-confirmed* fresh dumps only? |
| **L1** | Ladder cap — darkweb deduction | ×−10/mention, **uncapped** | **cap −40** (≈4 mentions) **+ confidence-gate** (only `media==13`/stealer-token paths count) | **reasoned** | §6 ticket; mention-count ≠ credential count; aggregated-index spam shouldn't floor the score | 12 mentions: −120→ capped −40, and most are low-conf so largely excluded | Cap level −30 vs −40? |
| **L2** | Ladder cap — paste deduction | ×−3/paste (>3), **uncapped** | **cap −30** | **reasoned** | §6 ticket symmetry | phishield paste=0, no effect | — |
| **L3** | HR CRITICAL date-gate (preserve as hard floor) | `hr_employees>0` ⇒ CRITICAL always | **HR ≥1 infected employee ⇒ CRITICAL floor**, but **stale infection (days_since > 180–365) ⇒ HIGH** via `days_since_compromise` | **reasoned** | §6 ticket; correlation already date-anchors (`active_theft_fresh` ≤90d). HR is a *confirmed* infection ⇒ must stay a class floor regardless of `W` | phishield HR=0 → no trigger (so de-escalation is safe here) | Stale-cliff at 180d or 365d? |

### Hard floors that survive the weighted sum (no-double-count safe)
- **A confirmed live infostealer infection (Hudson Rock employee, recent) hard-sets CRITICAL** regardless of `W`. The weighted sum governs the *DeHashed/IntelX* corpus; it must never *down*-grade a real infection. (phishield HR=0, so this floor is dormant and the de-escalation to LOW is correct.)
- **`credential_correlation` stays reporting-only** — what is promoted is the *class*, not the correlation card (design §6).
- **Replace, don't stack** `dehashed_total×2`. HIBP `breach_count` scenario path (L1664) is **out of scope for this group** → Q3.

---

## 3. Recompute result (phishield_live.json, today=2026-06-02)

Per-record weighting (faithful to fixture `breach_details` + `enriched_sources`):

| Channel | Detail | Current | **Proposed** |
|---|---|---|---|
| DeHashed weighted sum | 2× ALIEN TXTBASE high+combo+1–2yr (0.12 ea) + 11× low old (Apollo/Canva/Nitro/SocRadar/BvD) | — | **W=0.59** |
| IntelX mentions | 10 sampled: all `Slow-dom`/`History`/unspecified = **low confidence** → 0 under K7=0 | drives HIGH + score→0 | **W=0.0** |
| **Credential class** | | **HIGH** | **LOW** |
| **p(breach) contribution** (0–100, ×0.03) | | **26** (`13×2`) | **10** → posture delta 0.78pt → **0.30pt** |
| **RSI factor** | | **+0.15** (HIGH) | **+0.0** (LOW) |

**De-escalation is the correct call here:** every password-bearing record is in a combo source dated ≥2019 (`ALIEN TXTBASE` is 2024-12 but combo), Hudson Rock shows **zero** active infections, and the "darkweb" volume is aggregated-index/browser-history noise. Current scoring treats this as active-compromise HIGH; the proposed model reads it as historical LOW.

### Counterfactual checks (model behaves)
- **Remove the 2 plaintext passwords** (pure old email-only): W=0.37 → still **LOW**. ✓ (volume of old email-only doesn't manufacture risk)
- **Archetype A — 5 fresh (<30d) `Passwords.txt`, non-combo:** W=5.0 → **CRITICAL**. ✓
- **Archetype C — 3 hashed, 90–180d, non-combo:** W=0.96 → **MEDIUM**. ✓
- **Archetype E — 13 old email-only combo:** W=0.10 → **NONE**. ✓
- **Archetype F — 1 fresh email-only aggregated index:** W=0.10 → **NONE**. ✓ **(confirms a low-confidence/old — and even low-confidence/fresh — exposure does NOT spike p(breach), the core 5L requirement)**

---

## 4. Biggest open questions (for the colleague)

- **Q-A (the tension): fresh + combo.** ALIEN TXTBASE is dated 2024-12 (recent) **and** a combo source, and it is where phishield's only real passwords sit. K3=0.3 currently discounts it to 0.12/record. SpyCloud says curated combos can be 98% valid — so a *recent* combo with infostealer provenance may deserve **less** discount than a re-circulated 2019 dump. **Proposal to debate:** make K3 recency-aware (full discount only when the combo's own date is >1yr; near-1.0 when <90d). This is the single knob most likely to be wrong as a flat 0.3.
- **Q-B: single fresh password capture = MEDIUM or HIGH?** Under K4, one fresh `Passwords.txt` (W=1.0) → MEDIUM. One confirmed fresh corporate credential is arguably HIGH. Lower the HIGH threshold to ~1.0, or add "≥1 high-confidence fresh record ⇒ min HIGH" floor?
- **Q-C (Q3 from design): HIBP `breach_count` scenario p(breach) (L1664)** — fold into this class or leave separate? (Out of scope for *this* recompute; flagged.)
- **Q-D: K5 placement** — keep on the 0.03-weighted posture slot (small absolute p_breach effect), or promote to a direct vulnerability uplift like the supply-chain channel (`sc_vuln_uplift`)? Affects whether the magnitude is meaningful at all.

## 5. Honesty / confidence labels
- **data-supported:** K1 ratio band, K6 (multiplier vs validity %; cap non-binding).
- **reasoned (anchored, needs sign-off):** K2 shape, K3 level, K4 thresholds, K5 mapping, K7, L1–L3. Tuned against archetypes + anchors, not intuited, but the exact cutpoints are judgment.
- **needs-colleague:** Q-A (fresh+combo), Q-B (single-capture class), Q-D (slot vs uplift).
- Ranges are given, not false precision. No production constant changed.

## 6. Verification gate (after numbers are set — NOT done here)
1. `py tooling/verify_supply_chain_financial_wiring.py` (expect 31/31).
2. `py tooling/verify_scan_smoke.py` (exit 0 — scan-path/scoring change).
3. Present per-checker p(breach) deltas (phishield + a high-confidence reference) + AskUserQuestion vs §1 anchors; iterate K1–K7 until calibrated.
4. Only then commit + push (both remotes) → Render.
