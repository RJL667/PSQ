# Credential & Dark-Web — Card Back-Test Findings

Cohort: phishield.com cached scan (`test_fixtures/phishield_live.json`, scan 2026-06-01).
Credit-free: all reasoning from cached JSON + code trace. No live provider calls.
Scope: HIBP brand-breach, Dehashed, Credential Risk Assessment, Hudson Rock, IntelX.
Note: the "Credential Exposure Correlation" card was fixed earlier this session (`password_records=2`, renders "(2 with passwords)" correctly) — excluded from deep re-test but used as the reconciliation anchor below; it is the only one of the five that gets the password count right.

---

## 1. Brand Breach Record (HIBP)
- **Source/provider:** Have I Been Pwned free brand-breach endpoint (`BreachChecker.check`).
- **Ground-truth:** phishield `breaches` = `{breach_count: 0, breaches: [], data_classes: []}`. Correct: phishield is a B2B domain, not a consumer breached-service in HIBP's named catalogue. The card scope note explicitly defers email-level exposure to Credential Risk Assessment.
- **Code trace:** `checkers_threats.py:182-224` (free endpoint, 404→count 0). HTML `templates/results.html:1679-1706`; PDF `pdf_report.py:1026-1073`. Score wiring `scoring_analytics.py:619-620` (`breach_count*15`, cap 100), WEIGHTS `breaches=0.07`.
- **Verdict:** PASS
- **Severity:** n/a
- **Finding:** Renders correctly as "Clean — see Credential Risk", scope is well-disclaimed (no overstated "no exposure" claim), no double-count with Dehashed (separate weight, separate question). The free endpoint returns 404/empty for B2B domains by design.
- **Solution(s):** None needed. (Optional: the card says "Set HIBP_API_KEY to upgrade to paid domain-lookup" — fine; do not auto-enable, it is metered.)

---

## 2. Dehashed Credential Leaks
- **Source/provider:** Dehashed v2 search (`DehashedChecker.check`), paid/metered.
- **Ground-truth:** 13 records, 6 sources, **2 plaintext** (both ALIEN TXTBASE, `rudolph@`), 0 hashed, `corporate_count=9` (per-record), 4 `unique_emails`, `staff_accounts_total=4`. Score 68 (penalty `2*5 + 11*2 = 32`).
- **Code trace:** `checkers_threats.py:1175-1363`. HTML `templates/results.html:1790-1827`; PDF `pdf_report.py:1505-1566`. Score wiring `scoring_analytics.py:667-669`.
- **Verdict:** BUG (two, both low/medium)
- **Severity:** medium
- **Finding:**
  (a) **`unique_emails` case-sensitivity double-count.** `emails_seen` is a case-sensitive set (`checkers_threats.py:1255-1260`), so `Rudolph@phishield.com` and `rudolph@phishield.com` count as 2 distinct mailboxes → `unique_emails=4` when there are only **3** real mailboxes (louise, nkululeko, rudolph). This inflates the "Unique emails" row on the Dehashed card AND propagates into the Credential Risk factor (card 3) and the RSI composite. The masked staff list shows the same address twice (`Ru***h@` and `ru***h@`).
  (b) **Two-meaning "corporate" count.** Dehashed card shows `corporate_count=9` ("9 corporate") which is per-record, while the remediation/exec cards use `staff_accounts_total=4` (unique). Same underlying data, two different numbers on different pages — reader confusion, not a math error.
  Minor adjacent: a record with BOTH plaintext and hash (`has_hash:true, has_password:true`) is counted only as plaintext (`elif` at line 1275), so the per-row "[HASH EXPOSED]" flag can coexist with `hashed_count=0`. Cosmetic.
- **Solution(s):** (1) FREE — lowercase the email before adding to `emails_seen` (and dedupe the masked staff list case-insensitively) at `checkers_threats.py:1255-1260` / `:1314`; fixes (a) and the duplicated masked address in one line. (2) Label disambiguation — rename the Dehashed-card row to "Corporate records (9)" vs exec "Staff mailboxes (4)", or render both as unique. (3) No scoring change needed; `total_entries*2` is unaffected by email dedupe.

---

## 3. Credential Risk Assessment (CredentialRiskClassifier)
- **Source/provider:** Composite — Dehashed + HIBP enrichment + Hudson Rock + IntelX (`CredentialRiskClassifier.classify`).
- **Ground-truth:** `risk_level=HIGH, risk_score=55`. Score reconstructs exactly: 100 − 30 (passwords) − 15 (recent breaches) = 55; IntelX 60-leak adds a factor line only (no deduction, correct — `darkweb=0`). Recency factor names SocRadar.io + ALIEN TXTBASE as "2023+".
- **Code trace:** `checkers_threats.py:1789-1934`; HIBP enrichment `:1741-1782`; `KNOWN_BREACH_DATES` `:1796-1807`. HTML `templates/results.html:1970-2009`; PDF `pdf_report.py:1717-1787`. Feeds RSI at `scoring_analytics.py:1018-1032` (HIGH → +0.15 RSI base).
- **Verdict:** BUG
- **Severity:** medium
- **Finding:**
  (a) **Boolean-as-count overstatement (same bug-class as the just-fixed correlation card).** Factor text (`:1870`) reads *"Plaintext or hashed passwords exposed for 4 email(s) across 13 breach record(s)"* — but `has_passwords` is a single boolean OR over all records; only **2 records / 1 unique mailbox** actually carry a password. The card asserts passwords for "4 emails across 13 records" when reality is 2 records, 1 email. This is the exact pattern the correlation fix corrected (it now says "2 with passwords") but the Credential Risk card was NOT updated to match.
  (b) **Recency anchoring of combo lists is heuristic.** `KNOWN_BREACH_DATES["alien txtbase"]="2024-12-01"` (`:1797`) anchors a continuously-recompiled stuffing/combo compilation to a single "fresh" date, so it is counted as a 2023+ "recent breach" driving the HIGH level (−15). ALIEN TXTBASE is re-circulated infostealer/combo data, not a point-in-time corporate breach — recency attribution is soft. (The sibling correlation card sets `combo_only:false` and still treats it as recent.)
- **Solution(s):** (1) FREE — change the factor to count password-bearing records, mirroring the correlation fix: use `dehashed.credential_breakdown.plaintext_count + hashed_count` (=2) and the password-bearing unique-email count, e.g. "passwords exposed for 1 mailbox across 2 of 13 records". (2) FREE — flag combo/stuffing sources (ALIEN TXTBASE, Naz.API, Collection #1, RockYou) as "re-circulated, date approximate" in the recency factor so HIGH is not driven purely by a guessed combo-list date; or down-weight combo-list recency vs named-breach recency. (3) Architecture: keep classifier scored via RSI (already correct, no standalone weight) — do not add to WEIGHTS.

---

## 4. Hudson Rock Infostealer Detection
- **Source/provider:** Hudson Rock Cavalier free OSINT API (`HudsonRockChecker.check`).
- **Ground-truth:** `compromised_employees=0, users=0, third_party_exposures=1, total=0, score=95`. Score math correct (100 − 1×5). Card header shows "1 third-party"; one issue line. Infection-date anchors all null (no employee/user hits) — consistent.
- **Code trace:** `checkers_threats.py:1591-1692`. HTML `templates/results.html:1909-1932`; PDF `pdf_report.py:1569-1637`. NOT in WEIGHTS — scored indirectly via `credential_risk.risk_level` → RSI (`scoring_analytics.py:1018-1032`). Design note `scoring_analytics.py:505-515` confirms reporting-via-composite is intentional (no double-count).
- **Verdict:** PASS (one low-severity gap)
- **Severity:** low
- **Finding:** Card is accurate and correctly attributed. Gap: the **third-party exposure does not influence the score at all.** Hudson Rock only reaches the score through `credential_risk`, and the classifier (`:1820-1835`) keys exclusively on `compromised_employees`/`compromised_users` — `third_party_exposures` is read by nobody for scoring. So phishield's 1 third-party infostealer hit is surfaced but contributes 0 to RSI / overall. Defensible (third-party is supply-chain, handled elsewhere) but it is a silent reporting-only signal.
- **Solution(s):** (1) FREE — leave as-is (third-party credential risk is genuinely covered by the S-1/S-5/third_party_correlation supply-chain channel; adding it to credential_risk would double-count). (2) If desired, surface a tiny MEDIUM nudge in `credential_risk` only when third_party>0 AND no other credential signal exists (avoids the current "1 third-party, LOW overall" blind spot) — but verify no double-count with vendor_breach first.

---

## 5. IntelX Dark-Web Monitoring
- **Source/provider:** Intelligence X free tier (`IntelXChecker.check`). Free tier = 50/day, reset midnight UTC.
- **Ground-truth:** `total_results=60, leak_count=60, paste_count=0, darkweb_count=0`. All 60 records are media "Text File" → all classified as `leak`. `recent_results` capped at 10 (dates 2026-04-16 back to 2025-06, all pre-scan — recency sane). Score 100 (no darkweb, pastes ≤5). The 60 here are infostealer-log filenames (`.rar/...Microsoft Edge_Default.txt`, ZA IP-tagged) — consistent with infostealer dumps, correctly described in the PDF narrative.
- **Code trace:** `checkers_threats.py:1941-2043`. HTML `templates/results.html:1934-1968`; PDF `pdf_report.py:1640-1714`. NOT in WEIGHTS; reaches score via `credential_risk` IntelX factor (informational unless `darkweb_count>0`).
- **Verdict:** BUG (low)
- **Severity:** low
- **Finding:** **Request/result count mismatch.** The live request asks `maxresults: 40` (`:1970`) but the cached result has `total_results=60`. The free `/intelligent/search` does not strictly honour the 40 cap here, so the displayed "60 results" reflects whatever the API returned — a fresh re-scan could return a different number for the same domain, making the headline count non-reproducible. Secondary: every record falls into `leak_count` because the media-type map (`:2004-2010`) only recognises `media in (1,2)=paste` and `media==13=darkweb`; infostealer text dumps (the dominant IntelX content) all land in the catch-all `leak` bucket. That is acceptable (they ARE leak entries) but means `darkweb_count` will almost always be 0 even for genuine criminal-forum infostealer logs — the "Dark web mentions" row understates.
- **Solution(s):** (1) FREE — align the displayed count with the request cap (set `maxresults` to the intended display cap, or label the total as "≥N / first page") so the headline is reproducible. (2) FREE — recognise infostealer-log filename patterns (`.rar/...Default.txt`, IP-tagged archives) as dark-web-grade rather than generic "leak", OR rename the "Dark web mentions" row to "Forum/market mentions" and keep infostealer dumps under "Leak DB entries" with a note that these are stealer logs (the PDF narrative already explains this well; the HTML kv-table does not). (3) Sustainable-replacement for IntelX 50/day is a known open item — out of scope here.

---

## Cluster summary
cards=5, BUG=3 GAP=0 PASS=2 NEEDS-LIVE=0; headline = **Credential Risk Assessment repeats the just-fixed boolean-as-count bug** — its factor claims "passwords exposed for 4 email(s) across 13 breach record(s)" when only 2 records / 1 mailbox carry a password (and the `unique_emails=4` itself is inflated by a case-sensitivity double-count of `Rudolph@`/`rudolph@`, real count 3). Both are FREE one-line fixes; the email-dedupe fix also cures the duplicated masked staff address. Hudson Rock + IntelX are correctly architected as reporting-only-via-RSI (no double-count), but HR third-party and IntelX infostealer-log classification are silent/understated (low severity). HIBP brand-breach is clean and correctly scoped.
