# Credential & Dark-Web — Re-Test

Cohort: phishield.com cached `test_fixtures/phishield_live.json` (card outputs are PRE-FIX). All
results recomputed from the fixture's RAW fields through the post-Wave code — no live provider
calls. Fix commits: `2b36471` (Wave 3a, Dehashed + Credential Risk), `f13ba11` (Wave 4, IntelX).

---

## 1. Brand Breach Record (HIBP)
- **Was:** PASS — `breach_count=0`, correctly scoped to B2B domain, defers to Credential Risk.
- **Now:** FIXED (no change needed / no regression)
- **Evidence:** No HIBP checker change across Waves 1–4 (`git log f0cf35e..f13ba11 -- checkers_threats.py` touches only Dehashed/CredRisk/IntelX). Fixture still `breach_count=0, breaches=[], status=completed`. Clean, untouched.

## 2. Dehashed Credential Leaks
- **Was:** BUG — `unique_emails=4` (case-sensitive double-count of `Rudolph@`/`rudolph@`); masked staff showed `Ru***h@` + `ru***h@`; `corporate_count=9` vs `staff=4` dual-number confusion.
- **Now:** FIXED (case bug) | PARTIAL (label confusion still open)
- **Evidence:** `checkers_threats.py:1276-1281,1335` now `.strip().lower()`. Recompute on the 13 cached `breach_details`: unique mailbox set = {louise, nkululeko, rudolph} → **3** (was 4); masked staff = `['lo***e@', 'nk***o@', 'ru***h@']` — duplicate pair gone. The `corporate_count=9` (per-record) vs `staff_accounts_total` (unique) dual-number labelling (orig. item 2b, cosmetic) was NOT relabelled in pdf_report/results.html — minor reader-confusion gap remains.

## 3. Credential Risk Assessment (CredentialRiskClassifier)
- **Was:** BUG — factor read "Plaintext or hashed passwords exposed for 4 email(s) across 13 breach record(s)" (boolean-as-count); only 2 records / 1 mailbox carry a password.
- **Now:** FIXED
- **Evidence:** `checkers_threats.py:1885-1906` now counts `pw_records = plaintext+hashed` and `pw_mailboxes` (case-insensitive, has_password OR has_hash). Recompute on fixture: `pw_records=2, pw_mailboxes=1` → factor renders **"Plaintext or hashed passwords exposed for 1 mailbox(es) across 2 of 13 breach record(s)"**. Matches the correlation-card fix. Risk_level/score (HIGH/55) wiring unchanged (correctness-only). Recency-heuristic gap (combo-list date anchoring, orig. item 3b) untouched — deferred, low.

## 4. Hudson Rock Infostealer Detection
- **Was:** PASS (low gap: `third_party_exposures=1` reaches score via nobody).
- **Now:** FIXED (no change needed / no regression)
- **Evidence:** No HR checker change in any wave. Fixture unchanged: `compromised_employees=0, third_party_exposures=1, score=95`. Reporting-only-via-RSI architecture intact; orig. third-party-blind-spot gap (low, by-design) not addressed and not a regression.

## 5. IntelX Dark-Web Monitoring
- **Was:** BUG — request asked `maxresults:40` but card showed `total_results=60` (non-reproducible); every record bucketed `leak`, `darkweb_count` always 0 even for infostealer logs.
- **Now:** FIXED (reproducibility) | PARTIAL (darkweb classification)
- **Evidence:** `checkers_threats.py:1989` `MAX_RESULTS=40`; `:2032-2068` truncates returned records to 40 and sets `result_cap_applied=True` — synthetic 60→40 confirmed, count now bounded/reproducible. New `_is_darkweb_grade` (`:2002-2013`) classifies on `media==13`, `bucket` in (darknet/logs/stealer), or `_STEALER_TOKENS` in name. **PARTIAL:** the bucket path (the load-bearing one — IntelX `leaks.logs.*`) cannot be confirmed from this fixture because `recent_results` strips `bucket`/`media`-int. Tested classifier on the 10 cached record NAMES alone (media=0): only **1 of 10** matched (`Microsoft Edge_Default.txt` via `_default.txt`); the other 9 clear stealer dumps (`.rar/...Slow-dom...txt`, `/Important Files/Desktop/1md.txt`, ZA/CN IP-tagged) miss every token. So in production `darkweb_count` correctness hinges entirely on IntelX returning a `logs`/`darknet` bucket — unverifiable credit-free; if it does not, the row still understates. No regression; reproducibility fix is solid.

## Re-test summary
fixed=3 partial=2 still-broken=0 regressions=0 new=0; headline = **all 3 original BUGs corrected** — Dehashed case-double-count (4→3 mailboxes, masked staff de-duped) and Credential Risk boolean-as-count ("4 emails/13" → "1 mailbox across 2 of 13") both verified by recompute on cached RAW fields; IntelX is reproducible (40-cap truncation confirmed) but its `darkweb_count` classification is PARTIAL — depends on an IntelX `bucket` field not captured in the fixture (name-token fallback caught only 1/10 cached stealer logs). Residual low gaps (Dehashed corporate-vs-staff dual-label, CredRisk combo-date recency, HR third-party blind spot) were out of fix scope and remain.
