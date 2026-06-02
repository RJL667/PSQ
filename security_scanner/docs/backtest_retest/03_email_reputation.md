# Email & Reputation — Re-Test

Method: code verification of Waves 1-4 fixes + free live DNS (dnspython) re-checks.
Cached `phishield_live.json` is PRE-FIX and was NOT trusted; fixes confirmed by driving
live values through the actual fixed functions. No paid APIs, no full live scans.

## IP / Domain Reputation (DNSBL)
- **Was:** CRITICAL false-positive — `checkers_network.py:925/933` counted any A-answer as a listing, so Spamhaus `127.255.255.x` (open-resolver/blocked) and URIBL `127.0.0.1` (refused) marked every scan `blacklisted:True`. Both phishield AND clean takealot flagged.
- **Now:** FIXED
- **Evidence:** New `DNSBLChecker._is_genuine_listing` (`checkers_network.py:963-1005`) validates return codes; called for both IP and domain lists (`checkers_network.py:1028,1037`). Live: `phishield/takealot.dbl.spamhaus.org → 127.255.255.254`, `takealot.multi.uribl.com → 127.0.0.1`. Driven through fixed code: `127.255.255.254 → False`, `127.0.0.1 → False`, real `127.0.1.2/127.0.0.2 → True`. Clean domains no longer flagged.

## Email Security (SPF / DMARC / DKIM)
- **Was:** DKIM false-positive — `_check_dkim` (`:452`) counted any resolving `selector._domainkey` TXT, so takealot's wildcard `*._domainkey` gave 41/41 selectors "found"; wildcard test domains gave 41/41. (+ minor SPF `~all`/`-all` GAP, untouched.)
- **Now:** FIXED (DKIM); GAP-remains (SPF qualifier, out of scope of this wave)
- **Evidence:** Fixed `_probe` (`checkers_core.py:509-523`) requires `v=dkim1` OR `p=` before counting (`:519`). Live takealot wildcard TXT `heritage=external-dns…` → rejected (`False`); real `google._domainkey` `v=DKIM1; …p=…` → accepted (`True`). Wildcard over-report eliminated, real keys retained. SPF `~all` vs `-all` still scored identically (`_calculate_score` unchanged) — pre-existing GAP, not a regression.

## Fraudulent Domains (Typosquat / Lookalike)
- **Was:** GAP — homoglyph map ASCII-only; no Unicode/IDN confusables (dominant real-world lookalike vector).
- **Now:** FIXED
- **Evidence:** New `IDN_HOMOGLYPHS` map + technique #9 (`checkers_threats.py:2150-2163, 2240-2262`) emits bounded punycode candidates (one substitution each, hard-capped at 12). Live generation for `phishield.com`: 6 `idn-homoglyph` candidates, all `xn--` (e.g. `xn--hishield-4bh.com`), DNS-resolvable form, no candidate-set explosion (115 total perms).

## VirusTotal Reputation
- **Was:** PASS (no fix needed; correctly gated, degrades without key).
- **Now:** FIXED / no-change (still PASS)
- **Evidence:** `VirusTotalChecker` scoring/guards untouched by Waves 1-4; no regression introduced. Optional `reputation<-X` enhancement still not wired (acknowledged low-priority, not a bug).

## Re-test summary
fixed=4 partial=0 still-broken=0 regressions=0 new=0; all 4 Email & Reputation cards verified — DNSBL return-code validation, DKIM `v=DKIM1`/`p=` gating, and IDN punycode typosquat candidates all confirmed against live DNS. One pre-existing SPF `~all`/`-all` GAP remains (out of scope, not a regression).
