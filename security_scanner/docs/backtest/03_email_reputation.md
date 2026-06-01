# Email & Reputation — Card Back-Test Findings

Repo: `dazzling-germain-0b0427/security_scanner`. Method: cached JSON (phishield_live.json, takealot_live2.json) + free DNS via dnspython + code trace. No credits spent.

---

## Email Security (SPF / DMARC / DKIM / MX)
- **Source/provider:** `EmailSecurityChecker` in `checkers_core.py:318` — live DNS (TXT/MX), no API.
- **Ground-truth (free dnspython):**
  - phishield SPF = `v=spf1 redirect=_sn4qmlzpy.sdmarc.net` → checker `valid=True, has_redirect=True, dns_lookups=11, exceeds_lookup_limit=True`. CORRECT.
  - phishield DMARC = `p=reject; pct=100; rua=…` → `policy=reject, pct=100`. CORRECT.
  - phishield MX = mimecast.co.za x2; DKIM real key only at `k2._domainkey`. Cached shows `selectors_found:['k2']`. CORRECT.
  - takealot DKIM cached shows **all 41 selectors "found"**. Live query proves `nonexistent-xyz-123._domainkey.takealot.com` and `zzqqww._domainkey.takealot.com` BOTH resolve to a generic `heritage=external-dns…` TXT (a wildcard `*._domainkey` record), NOT DKIM keys. Only `google._domainkey` is a real `v=DKIM1` key.
- **Code trace:** `_check_dkim` (`checkers_core.py:452`) treats ANY successful `resolve(selector._domainkey.domain, TXT)` as a hit — never validates the TXT starts with `v=DKIM1` or contains `p=`. Rendered: `templates/results.html:1224` and `pdf_report.py:584` join `selectors_found`.
- **Verdict:** BUG (DKIM false-positive on wildcard `_domainkey`) + minor GAP (SPF qualifier).
- **Severity:** medium
- **Finding:** DKIM detection over-reports on any domain with a wildcard `*._domainkey` TXT (e.g. takealot reports 41/41 selectors "Found" when only 1 is real), giving a false "DKIM fully configured" impression. Separately, `_check_spf` (line 369) sets `dangerous` only for `+all`; it never distinguishes `~all` (softfail) from `-all` (hardfail) — a softfail SPF is scored identically to a strict one (GAP).
- **Solution(s):** (1) In `_probe`, require the returned TXT to start with `v=DKIM1` OR contain `p=` before counting a selector — drops wildcard noise, zero cost. (2) Parse the SPF all-qualifier (`-all`/`~all`/`?all`) and add a small penalty for non-`-all`; reporting-only, no new weight.

## IP / Domain Reputation (DNSBL)
- **Source/provider:** `DNSBLChecker` in `checkers_network.py:892` — DNS lookups against Spamhaus zen/dbl, spamcop, sorbs, barracuda, uceprotect, uribl.
- **Ground-truth (free dnspython):** `takealot.com.dbl.spamhaus.org` AND control `zzq-random-xyz123.com.dbl.spamhaus.org` BOTH return `127.255.255.254`; TXT = `"Error: open resolver; …"`. `phishield.com.dbl` → same. `…zen.spamhaus.org` TXT = `"Error: open resolver"`. `multi.uribl.com` → `127.0.0.1` (= query refused). These are Spamhaus/URIBL **error/blocked return codes**, NOT listings. spamcop/sorbs/barracuda/uceprotect all NXDOMAIN (correct).
- **Code trace:** `checkers_network.py:925/933` — `dns.resolver.resolve(…, "A")` succeeding → appended to listings, with NO inspection of the returned `127.x.x.x` value. Scored: `scoring_analytics.py:635-637` `dnsbl_risk = min(100, listed*50)`, weight `0.06` (line 482); also fires remediation row (line 3362) + financial probability uplift (line 3079). Rendered red at `templates/results.html:1710/1717`, `pdf_report.py:1076`.
- **Verdict:** BUG (systematic false-positive; always-fires inversion class)
- **Severity:** critical
- **Finding:** BOTH cached scans (phishield AND takealot — a clean top-1113 retailer) show `blacklisted:True` with `domain_listings:['dbl.spamhaus.org']`. The scan host's public resolver is rate-limited/blocked by Spamhaus, which returns `127.255.255.252/254`; the checker treats any A-answer as a listing. Every scan false-flags a DBL listing, inflating dnsbl_risk by `50*0.06 = 3` risk points, triggering a bogus "prior compromise/spam" remediation and premium-relevant probability uplift on clean domains.
- **Solution(s):** (1) Filter return codes: only count `zen` answers in `127.0.0.2–127.0.0.11` and `dbl` answers in `127.0.1.2–127.0.1.99`; treat `127.255.255.x` as "query blocked → checker unavailable", not a listing (free, decisive fix). (2) Run Spamhaus from a dedicated/authenticated resolver (DQS key, free tier) instead of a shared public resolver so error codes stop appearing. (3) Until fixed, suppress DBL/zen from scoring (set those zones reporting-only) to stop premium contamination.

## VirusTotal Reputation
- **Source/provider:** `VirusTotalChecker` in `checkers_threats.py:1370` — VT API v3 domains endpoint (free tier 4/min, 500/day); `no_api_key` fallback.
- **Ground-truth (cached, credit-free):** phishield `status:completed, malicious:0, suspicious:0, reputation:0, score:100, pop_rank:197905`; takealot `…score:100, pop_rank:1113`. Consistent with two clean, legitimate domains. No live VT lookup needed.
- **Code trace:** parses `last_analysis_stats`, `total_votes`, `categories`, `popularity_ranks`; `score = 100 - min(100, mal*10 + sus*5)` (line 1474). Scoring guards `no_api_key/auth_failed/rate_limited` → risk 0 (`scoring_analytics.py:672-683`, weight 0.05). Rendered with no-key fallback at `templates/results.html:2012/2029`, `pdf_report.py:1790`.
- **Verdict:** PASS
- **Severity:** n/a
- **Finding:** Card is accurate, correctly gated, and degrades cleanly without a key. Minor note: `reputation` (VT community score, can be negative) is captured but not used in `score` and not shown as a penalty; a strongly-negative community reputation would not lower the card. Low-priority enhancement, not a bug.
- **Solution(s):** (Optional) factor `reputation < -X` into the issues/score as a soft signal; reporting-only, no new weight.

## Fraudulent Domains (Typosquat / Lookalike)
- **Source/provider:** `FraudulentDomainChecker` in `checkers_threats.py:2050` — generates permutations, DNS-resolves them; opt-in (`include_fraudulent_domains`, default False).
- **Ground-truth:** Card is ABSENT from both cached scans (`'fraudulent_domains' in categories` = False) because the flag defaults off (`scanner.py:438`, `app.py:844`). Permutation logic verified by reading code only (no aggressive domain registration/queries).
- **Code trace:** 8 techniques (omission, swap, dup, homoglyph, keyboard, TLD, dot, hyphen); `_split_domain` (line 2082) handles `.co.za`/`.org.za` etc.; caps to 60 checked, 20 displayed. Scored `scoring_analytics.py:686` weight 0.04; rendered `templates/results.html:2058` (+ enabled/disabled fallback at 2094) and `pdf_report.py:2109`. When disabled the renderer shows the correct "enable to run" panel — no ghost.
- **Verdict:** GAP (coverage, not a bug)
- **Severity:** low
- **Finding:** No always-fires inversion (the disabled-state fallback is correct). But permutation coverage misses high-value classes for SA brand-abuse: (a) homoglyph map is ASCII-only — no Unicode/IDN confusables (e.g. Cyrillic `а`, `ο`) which are the dominant real-world lookalike vector; (b) no insertion/bitsquatting/transposition-of-words; (c) `dns_lookups`-style nested checks absent. Also resolution-only flagging misses registered-but-parked lookalikes that don't resolve.
- **Solution(s):** (1) Add IDN/Unicode confusable expansion (use the `confusable_homoglyphs` table, offline, free) — biggest accuracy win for phishing detection. (2) Optionally flag NS/registration via free RDAP for non-resolving permutations to catch parked squats. (3) Keep opt-in (cost/time), but document that disabling it leaves the brand-abuse kill-chain phase uncovered.

---

## Cluster summary
cards=4, BUG=2 GAP=1 PASS=1 (Email card carries both a BUG and a minor GAP; counted under BUG). NEEDS-LIVE=0.
**Headline:** DNSBL checker (`checkers_network.py:925/933`) counts Spamhaus/URIBL `127.255.255.x` "open-resolver / query-blocked" return codes as real blacklist listings — BOTH phishield and a clean top-1113 retailer (takealot) are flagged `blacklisted:True` on every scan, inflating dnsbl_risk (weight 0.06), triggering a false "prior compromise" remediation and a premium-relevant probability uplift. Fix by validating return-code ranges (free). Secondary: DKIM over-reports on wildcard `*._domainkey` records (takealot shows 41/41 selectors "found", only 1 real).
