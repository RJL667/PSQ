# Card Back-Test — Executive Summary

**Date:** 2026-06-02 (overnight autonomous run)
**Method:** Card Verification Protocol, credit-free — 7 parallel research agents, each auditing a card cluster against cached real scan data (phishield.com, takealot.com) plus free ground-truth (openssl, curl, dig, crt.sh, Shodan InternetDB). No paid APIs, no live scans, no source code edited.
**Coverage:** 34 cards across 7 clusters. **Result: 17 bugs, 7 gaps, 10 pass.**

---

## The headline: most bugs share five root causes

The individual findings are listed below, but the value is in the **patterns** — fixing the root cause clears several cards at once, and most fixes are free.

### Theme 1 — WAF/CDN responses scored as findings (the single biggest issue)
A Cloudflare/F5 edge returns **403 (blanket deny)** to anything sensitive and **200 (catch-all)** to anything else. Three checkers read those generic edge responses as positive findings:
- **Exposed Admin** treats a 403 on `/.env`, `/.git`, `wp-config.php` as a *critical exposure* — the logic is **inverted**: a 403 means the path is protected. Well-defended orgs are penalised hardest (backwards for underwriting).
- **CMS Plugin Surface** reads the 200 catch-all as plugin "presence" — flags takealot (not even WordPress) as WordPress with 25 plugins.
- **Subdomains** brute-forces against wildcard DNS (`*.takealot.com` resolves) and fabricates "risky" subdomains.

**The fix template already exists in-repo:** the S-3 dependency-manifest probe (`checkers_supply_chain.py` `_probe`, 200-only + body-sanity) is the correct WAF-robust pattern. Adopt it across Exposed Admin, CMS Plugins, and Subdomains. Free.

### Theme 2 — a generic/standard response read as a positive signal
- **DNSBL** counts *any* A-record answer as a blacklisting; Spamhaus's "open resolver / query blocked" reply (`127.255.255.254`) and URIBL's refusal (`127.0.0.1`) are misread → **every** scan returns `blacklisted:True`. Validate the documented return-code ranges. Free.
- **DKIM** counts any resolving `selector._domainkey` as a hit without checking `v=DKIM1` → a wildcard `*._domainkey` reports 41/41 selectors "found". Require `v=DKIM1`/`p=`. Free.
- **WAF (F5 BIG-IP)** fingerprints off `x-frame-options`, a ubiquitous standard header → false F5 detection + phantom WAF credit. Tighten the signature. Free.
- **VPN / RDS Web** flags a Cloudflare SPA as a Microsoft RDS gateway off a weak substring. Free.

### Theme 3 — a boolean rendered as a count (the bug fixed this session, not propagated)
The "13 with passwords" overstatement fixed in the Credential Exposure Correlation card this session **lives on in its siblings**:
- **Credential Risk Assessment** states "passwords for 4 emails across 13 records" when only **2 records / 1 mailbox** carry a password — and this one feeds the RSI score (HIGH → +0.15).
- **Dehashed** counts `Rudolph@` and `rudolph@` as two mailboxes (`unique_emails` not lower-cased) → inflated counts.
Both are the same free fix already proven this session: count password-bearing records; normalise case.

### Theme 4 — scoring decoupled from posture (wiring)
- **Financial Impact:** `vulnerability` is **pinned at 0.5 in production** because `cat_results["_overall_score"]` is never set before the financial calculator runs — so `p_breach`, incident probabilities, expected loss and every Monte-Carlo return-period tail are **decoupled from the actual risk score**. (This is the `_overall_score not propagated` WARN visible in the smoke test.) The regen/verifier paths inject the score, which masked it. One-line fix. **High priority — it undermines the headline financial numbers.**
- **CVE card** fabricates "1 ASN / 1 Country / org Unknown" on the free InternetDB path (which carries no geo/ASN). Free fix: ip-api.com (45/min, no key) or Team Cymru DNS-ASN.

### Theme 5 — ghosts, dead code, and stale tables
DNS records (AAAA/TXT/DNSSEC) computed but never rendered while a DNSSEC remediation still fires; two dead-ghost PDF renderers (`cat_ransomware_risk`, `cat_data_breach_index`); two divergent remediation cards rendered consecutively (R2.01M vs R2.70M); S-1 contributes nothing autonomously; `vendor_breaches.json` carries permanently-expired rows; hardcoded EOL table (use endoflife.date).

---

## Master findings table (severity-ranked)

| # | Card | Verdict | Severity | One-line finding | Fix cost |
|---|---|---|---|---|---|
| 1 | SSL/TLS | BUG | **critical** | sslyze 6.x API mismatch swallowed by `except: pass` → every cert graded "Invalid" (−40) on 100% of scans | Free |
| 2 | IP/Domain Reputation (DNSBL) | BUG | **critical** | any A-record = "listed"; Spamhaus open-resolver reply misread → every scan `blacklisted:True` | Free |
| 3 | Exposed Admin & Paths | BUG | **critical** | 403 (protected) counted as critical exposure — inverted; penalises well-defended orgs | Free |
| 4 | Financial Impact | BUG | **high** | `_overall_score` never set in prod → `vulnerability` pinned 0.5 → p_breach + all MC tails decoupled from posture | Free (1 line) |
| 5 | WAF | BUG | high | F5 signature keys off `x-frame-options` → false F5 + phantom WAF credit | Free |
| 6 | CMS Plugin Surface | BUG | high | CDN 200 catch-all → non-WordPress site reported WordPress + 25 plugins | Free |
| 7 | Subdomains | BUG | high | no wildcard-DNS guard fabricates subs; crt.sh shows 77 real vs 16 captured; PDF still claims "via CT" | Free |
| 8 | Credential Risk Assessment | BUG | medium | boolean `has_passwords` rendered as count ("4 emails / 13 records") — feeds RSI | Free |
| 9 | Email-Vendor Surface (S-4) | BUG | medium | Mandrill/Zoho SPF mis-classified "unknown" → suppresses a real HIGH Mailchimp breach match downstream | Free |
| 10 | Third-Party Cross-Correlation | BUG | medium | severity hard-set CRITICAL on any vendor overlap regardless of underlying breach severity; stale docstring | Free |
| 11 | CVE / Known Vulns | BUG | medium | fabricated "1 ASN / 1 Country / Unknown org" on free path | Free (ip-api) |
| 12 | Dehashed | BUG | medium | `unique_emails` case-sensitive → double-counts mailboxes | Free (1 line) |
| 13 | Open Ports / Protocols | GAP | medium | per-IP attribution lost on CDN targets (real FTP shown under Cloudflare apex) | Free (render) |
| 14 | VPN & Remote Access | BUG | medium | weak substring flags Cloudflare SPA as Microsoft RDS Web | Free |
| 15 | Email Security (DKIM) | BUG | medium | wildcard `*._domainkey` → 41/41 selectors "found" without `v=DKIM1` | Free |
| 16 | Remediation Roadmap | BUG | medium | two divergent remediation cards (R2.01M vs R2.70M) render consecutively; unbounded rsi_reduction sum | Free |
| 17 | Supply-Chain S-1 | GAP | medium | inert (broker-declared only; auto-discovery deferred); 2 expired `vendor_breaches.json` rows | Free |
| 18 | DNS Intelligence | GAP | low | AAAA/TXT/DNSSEC computed but never rendered; DNSSEC remediation still fires | Free |
| 19 | Technology Stack & EOL | GAP | low | hardcoded stale EOL table | Free (endoflife.date) |
| 20 | Fraudulent Domains (Typosquat) | GAP | low | ASCII-only homoglyphs miss IDN/Unicode confusables (dominant real vector) | Free |
| 21 | IntelX Dark-Web | BUG | low | non-reproducible count (asks 40, shows 60); infostealer text dumps all fall in `leak_count` → `darkweb_count` ~always 0 | Free |
| 22 | PDF dead-ghost renderers | BUG | low | `cat_ransomware_risk` / `cat_data_breach_index` read stale shapes; never wired | Free (delete) |

**PASS (verified accurate):** HTTP Security Headers, VirusTotal, HIBP Brand Breach, Hudson Rock, Third-Party JavaScript (S-2), Exposed Dependency Manifests (S-3), RDP/Remote (recently-fixed — held), Origin IP Discovery (recently-fixed — held), RSI (reconciles), DBI (reconciles).

---

## Recommended remediation order (all fixes free unless noted)

**Wave 1 — correctness bugs that distort every report (do first):**
1. SSL sslyze 6.x API fix (#1) — un-breaks cert grading on 100% of scans.
2. `_overall_score` wiring (#4) — re-couples the entire financial model to posture.
3. DNSBL return-code validation (#2) — stops universal false "blacklisted".
4. Exposed Admin 403-inversion (#3) — stop penalising defended orgs.

**Wave 2 — the WAF/CDN response-handling family (shared template):**
5. Adopt the S-3 `_probe` pattern (200-only + body-sanity + wildcard-DNS guard) across Exposed Admin (#3), CMS Plugins (#6), Subdomains (#7); switch Subdomains' primary source to crt.sh.

**Wave 3 — count/attribution accuracy:**
6. Boolean-as-count + case-normalisation (Credential Risk #8, Dehashed #12); S-4 vendor patterns (#9, unlocks the Mailchimp breach match); cross-correlation severity propagation (#10); CVE ASN/geo via ip-api (#11); per-IP port attribution (#13); WAF/RDS/DKIM signature tightening (#5, #14, #15).

**Wave 4 — ghosts & hygiene:**
7. Render or remove DNS-records/DNSSEC (#18); reconcile the two remediation cards (#16); delete dead PDF renderers (#22); prune expired vendor rows + plan S-1 auto-discovery (#17); endoflife.date EOL (#19); IDN typosquat (#20); IntelX count/darkweb classification (#21).

**Architecture / budget notes:** every fix above is free and respects the low-footprint posture — three use free keyless services already trusted by the design (crt.sh, Shodan InternetDB, ip-api.com / endoflife.date at 45/min no-key). None require live credit spend, aggressive probing, or new paid tiers. Calibration-class questions (factor magnitudes) were explicitly **deferred to FIN-9**; everything above is correctness, not calibration.

---

*Per-cluster detail follows.*
