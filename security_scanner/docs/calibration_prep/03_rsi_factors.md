# RSI Factor Weights — Calibration Prep (PROPOSED, not final)

**Parameter group:** Ransomware Susceptibility Index (RSI) additive factor weights + base + band mapping.
**Code:** `scoring_analytics.py` class `RansomwareIndex.calculate()` (L1001-1306).
**Status:** SANDBOX PREP for the 2026-06-03 calibration session. **No production code edited.** All values below are research-grounded *proposals* for discussion, with confidence tags and recompute evidence.
**Date:** 2026-06-02.

---

## TL;DR (read this first)

The current model's **single largest factor is `RDP exposed +0.25`**, justified in-code as "the #1 ransomware vector." The 2026 evidence — **and especially the SA-specific cut** — does not support RDP being the single biggest *root cause*. It supports a **credentials ≈ vuln-exploit > email** ordering, with **RDP/remote-access being an *exposure surface* through which the credential and vuln channels are realised** (CISA: RDP compromise is *achieved via* brute-force, stolen creds, or VPN-software exploits — it is not an independent root cause).

**Headline proposal:** rebalance so the **dominant root cause (credentials) is at least as heavy as RDP**, trim RDP from +0.25 to a still-strong **+0.18–0.22** (it remains a confirmed observable, which earns a premium over a probabilistic signal), and lift the top credential tier so CRITICAL credentials ≥ RDP. Recompute shows bands stay sane: Phishield stays **Medium (~0.45–0.49)**, worst-case primary stacks stay **Critical (~0.84)**.

---

## Empirical anchors — initial-access vectors, SA-prioritised

| Source (year) | Vector shares relevant to RSI | Note |
|---|---|---|
| **Sophos State of Ransomware in *South Africa* 2025** (primary SA anchor) | **Compromised credentials 34% (#1)** · **Exploited vulnerabilities 28% (#2)** · **Malicious email 22% (#3)** | 150+ SA orgs. Also: 58% cite "lack of expertise", 53% "unknown defence weakness" as operational root cause → supports a non-zero base + size multiplier. |
| **Mandiant M-Trends 2025 — *ransomware-specific* intrusions** | **Brute-force #1** (incl. RDP login attempts, VPN default creds, password spraying) · **stolen credentials 21% & exploits 21% (tied #2)** · prior compromise 15% · third-party 10% | "Brute-force #1" = the RDP/remote-access *surface*; its payload is credential abuse. Creds + exploits co-dominant. |
| **Mandiant M-Trends 2025 — all intrusions** | Exploits 33% (#1) · stolen credentials 16% (#2) | Generic, not ransomware-only. |
| **Verizon DBIR 2025** | Stolen credentials = #1 initial-access (22%) · vuln-exploitation **+34% YoY** (edge/VPN devices) · **54% of ransomware victims had prior infostealer credential exposure** | Strong support for heavy credential weight + the credential↔infostealer link the scanner already models. |
| **Coveware Q4 2024** | Phishing #1; remote-access compromise rising fast at #2 (VPN vulns + stolen creds + brute force); software-vuln & insider declining | No public per-vector %; remote-access "often initiated through phishing" → overlap, not independence. |
| **CISA #StopRansomware** | RDP/exposed remote services = top-tier initial access, but achieved *via* brute-force / compromised creds / VPN-software exploit | Confirms RDP is a **surface that overlaps** the credential + vuln channels — central to the no-double-count argument. |
| **Patchstack State of WordPress 2024** | 96% of WP CVEs in plugins; **11.6% actively exploited / expected**; 33% unpatched at disclosure | Validates the existing S-10 CMS factor sizing (small, version-readability-gated). |

**Synthesised relative ordering (named vectors, SA-weighted):** Credentials **40%** ≳ Vuln-exploit **33%** > Email **26%**. RDP/remote-access and DB-port exposure are *surfaces* feeding the credential + vuln channels, so they earn an **observability premium** but must not be summed as if independent of them (double-count risk).

---

## Proposed factor table

| Factor | Current | Proposed (range) | Confidence | Anchor (sources) | Recompute / effect | Open question |
|---|---|---|---|---|---|---|
| **RDP (3389) exposed** | +0.25 | **+0.18–0.22** | Reasoned | M-Trends (brute-force #1 but = surface); CISA (RDP via creds/brute/vuln, not independent root cause) | Worst-case stack 0.84→0.84 (diminishing absorbs the trim). Removes the "RDP-alone (0.345) > CRITICAL-cred-alone (0.287)" inversion. | Keep a premium for being a *confirmed observable* vs probabilistic credential risk — how big? 0.20 is the proposed midpoint. |
| **Credential CRITICAL** | +0.20 | **+0.20–0.24** | Data-supported | SA 34% #1; DBIR creds #1; M-Trends creds 21% (tied) | CRITICAL-cred-alone 0.287→up to ~0.32; ensures #1 root cause ≥ RDP surface. | Depends on credential team confirming CRITICAL = genuinely active (infostealer/real-time). |
| **Credential HIGH** | +0.15 | **+0.15–0.18** | Data-supported | As above; HIGH = recent breach w/ passwords or dark-web trade | Phishield 0.451→**0.489** at 0.18 (still Medium). | **Input-integrity flag (see §Double-count):** HIGH is fed by the credential card's count-vs-boolean bug — fix the *input* before lifting the *weight*. |
| **Credential MEDIUM** | +0.08 | **+0.06–0.08** | Reasoned | MEDIUM = historical/email-only → weakest cred tier | negligible | Should email-only historical exposure contribute to a *ransomware* index at all, or only to DBI? |
| **Exposed DB port (each)** | +0.10, cap 0.20 | **+0.06–0.08 each, cap 0.16** | Reasoned | DB-port = exposure surface, not a named ransomware root cause; overlaps RDP/remote-access narrative | Phishield: trimming 0.10→0.08 offsets the credential lift to net ~0.451. | Is an exposed managed DB (e.g. takealot RDS) materially a *ransomware* vector or a *data-breach* one? Lean: weight more in DBI. |
| **CISA KEV CVE (each)** | +0.08, cap 0.20 | **+0.08–0.10 each, cap 0.20–0.24** | Data-supported | Vuln-exploit = 28% SA / 21% M-Trends ransomware / +34% DBIR YoY; KEV = confirmed exploited | Lifts the vuln channel toward parity with credentials (empirically co-dominant). | Combined vuln cap (KEV+EPSS+other = 0.40) already ≈ credentials; is per-CVE or the cap the right lever? |
| **High-EPSS CVE (>0.5, each)** | +0.04, cap 0.12 | **+0.04, cap 0.12** (hold) | Reasoned | EPSS = probabilistic, below KEV | unchanged | — |
| **Other crit/high CVE (each)** | +0.02, cap 0.08 | **+0.02, cap 0.08** (hold) | Reasoned | Unconfirmed exploitability | unchanged | — |
| **No DMARC** | +0.08 | **+0.07–0.09** (hold ~0.08) | Data-supported | Email 22% SA (#3); CISA BOD 18-01: p=reject cuts inbox-success 69%→14% | unchanged | — |
| **DMARC policy = none** | +0.05 | **+0.05** (hold) | Reasoned | Partial enforcement | unchanged | — |
| **No WAF** | +0.05 | **+0.03–0.05** | Reasoned / weak | WAF absence is a hygiene proxy, not a named ransomware vector | Phishield: trim to 0.04 helps net the credential lift. | **Back-test Theme-1 caveat:** WAF *detection* itself has false-positive bugs (F5 off `x-frame-options`) — the *input* may be unreliable; don't over-weight. |
| **Weak SSL (D/E/F)** | +0.05 | **+0.02–0.03** | Reasoned / weak | Weak TLS is rarely the ransomware entry vector; mostly hygiene/MITM | minor | Candidate to drop from RSI entirely and keep only in posture/DBI. SSL grade also has a known sslyze-6.x scoring bug (back-test). |
| **Base value** | 0.05 | **0.05** (hold) | Reasoned | "Inherent internet exposure"; SA 58% lack-of-expertise supports a non-zero floor | — | — |
| **Diminishing knee** | 0.50 | **0.50** (hold) | Reasoned | Prevents stacking inflation; bands behave well in recompute | — | Revisit only if rebalanced caps change the typical raw-score distribution. |
| **Band map** | C≥0.75 / H≥0.50 / M≥0.25 / L | **hold** | Data-supported | Recompute: Phishield Medium, worst-case Critical — both correct | — | — |
| Supply-chain stack (S-1/2/3/4/10) | cap 0.22 | **hold cap 0.22** | Reasoned | Verizon 30% third-party; Patchstack 11.6% exploited; cap < single RDP by design | unchanged | Owned by supply-chain team; the **cat-tail "no double-count" rule** (observed→probability uplift) already governs this — leave to that group. |

---

## Recompute evidence (throwaway python, production pipeline replicated, no edit)

Reproduced the live pipeline exactly (`_diminishing` + industry×size multipliers).

**Phishield (fixture `phishield_live.json`):** active factors = HIGH credential (+0.15) + 1 exposed DB port PostgreSQL/5432 (+0.10) + No WAF (+0.05); base 0.05 → raw **0.35** → ×1.15 (finance) ×1.12 (revenue=0) = **RSI 0.451 (Medium)**. My harness reproduces 0.451 to the digit.

> ⚠️ **Fixture artifact:** `annual_revenue = 0` triggers the **micro-business multiplier 1.12**. At a realistic R500M the same findings give **RSI 0.362**. The brief's "0.728-ish" current value was **not reproducible** from this fixture — likely stale or from a different target. Confirm the intended baseline with the team.

| Scenario | Current | Proposed | Band |
|---|---|---|---|
| Phishield, rev=0 (as-shipped) | 0.451 | 0.489 (cred HIGH→0.18) / 0.451 (Prop B: also DBport→0.08, WAF→0.04) | Medium → Medium |
| Phishield, realistic R500M | 0.362 | ~0.40 | Medium → Medium |
| Worst-case primary stack (RDP + CRITICAL cred + 2 KEV + no-DMARC + no-WAF + weak-SSL), finance R200M | raw 0.84 → **0.859 Critical** | RDP 0.20 + cred 0.22 → raw 0.81 → **0.841 Critical** | Critical → Critical (preserved) |
| Single-signal: RDP-alone | 0.345 | ~0.29 (at RDP 0.20) | — |
| Single-signal: CRITICAL-cred-alone | 0.287 | ~0.32 (at cred 0.22) | **fixes the inversion** |

**Takeaway:** the rebalance toward the empirically-dominant credential channel is **net-neutral on the headline RSI** when paired with modest trims to the surface/hygiene factors (RDP, DB-port, WAF, SSL), while **correcting the single-signal ordering** to match SA/global evidence and **preserving the Critical band** for true primary-access stacks.

---

## Double-count & input-integrity checks (CRITIC)

1. **RDP vs credentials vs DB-ports — surface vs root-cause.** RDP-exposed, DB-port-exposed, *and* credential-risk can all fire for the same compromise path (CISA: RDP is breached *via* stolen creds/brute-force). Summing them at full weight over-counts the remote-access narrative. **Mitigation in proposal:** trim the *surface* factors (RDP, DB-port), keep the *root-cause* factor (credentials) heavy. The brute-force overlap is the reason credentials should not be *below* RDP.
2. **Credential card input bug (cross-team — flag to credential group).** Back-test Theme 3: the Credential Risk Assessment that sets `risk_level=HIGH` (→ +0.15 here) reportedly renders "passwords for 4 emails across 13 records" when only **2 records / 1 mailbox** actually carry a password. **The RSI weight is only as good as the tier classification feeding it — fix the input before tuning the weight.** Do not lift HIGH→0.18 until the credential team confirms the tier is correctly assigned.
3. **WAF / SSL inputs are themselves buggy (back-test Theme 1).** No-WAF (+0.05) and weak-SSL (+0.05) are fed by checkers with known false-positives (F5 fingerprint off `x-frame-options`; sslyze-6.x grade bug). Proposed trims partly hedge this, but the *correctness* fix lives in those checkers, not in RSI.
4. **Phase-4f / third_party_correlation already correctly excluded** (reporting-only, code comment L1100-1108) — no action; do not add it as a factor.
5. **Supply-chain stack governed by the cat-tail rule** — observed risk → probability uplift (pre-MC), not K_TAIL. Leave to the supply-chain team; the 0.22 cap < single-RDP design intent is sound.

---

## Honesty / confidence summary

- **Data-supported:** credential-channel should be ≥ RDP (SA 34% #1, DBIR #1, M-Trends tied-#2); vuln-exploit deserves parity with credentials (28% SA, +34% DBIR); email ~0.08 (22% SA). Band map validated by recompute.
- **Reasoned (defensible, not directly measured):** the *exact* RDP trim (0.25→0.18–0.22), DB-port and WAF/SSL trims, the observability premium for confirmed surfaces. These are judgement calls on how to split a probabilistic root-cause weight from an observed-surface weight.
- **Needs-colleague (2026-06-03):** (a) the intended Phishield baseline RSI (0.451 reproduces; 0.728 does not); (b) confirmation that the credential-tier input bug is fixed before lifting the HIGH weight; (c) whether exposed managed DBs belong in RSI or DBI; (d) the precise RDP-vs-credentials premium given underwriting appetite. Ranges given throughout where the SA-specific data is thin (Coveware/M-Trends give no clean SA per-vector split — only the Sophos SA cut does).

**Sources:** Sophos State of Ransomware in South Africa 2025; Mandiant M-Trends 2025; Verizon DBIR 2025; Coveware Q4 2024; CISA #StopRansomware; Patchstack State of WordPress 2024.
