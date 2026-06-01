# Attack Surface & Tech — Card Back-Test Findings

Fixtures used: `test_fixtures/phishield_live.json` (F5 BIG-IP ASM WAF),
`.../charming-ishizaka-3b0bf1/.../takealot_live2.json` (Cloudflare).
Ground truth: crt.sh (`%25.takealot.com` → **77** real subdomains), `nslookup`,
non-intrusive `curl -I` against takealot.

> **Cluster headline (read first):** A single root cause — **WAF/CDN HTTP 403
> blanket-deny + 200 catch-all responses are treated as positive findings** —
> corrupts 3 of the 5 cards (Exposed Admin, CMS Plugin Surface, and via
> wildcard DNS the Subdomains card) on BOTH fixtures. The phantom findings max
> out `admin_risk` and `sub_risk` in the score, so **better-defended orgs (WAF
> present) are penalised harder** — an underwriting inversion.

## Subdomains (CT logs / crt.sh)
- **Source/provider:** `SubdomainChecker` — crt.sh CT logs (Source 1) + DNS brute-force of 48 prefixes (Source 2).
- **Ground-truth:** crt.sh returns **77** real subdomains for takealot.com (incl. high-value `admin.`, `jira.`, `remotessl.`, `cpt-hq-fortiauth.`, `urbackup.hq.`, `security-elasticsearch-*`, `sellercapital.`). The takealot fixture captured **ct_count=0** (crt.sh empty/slow during scan) and fell back to **16 brute-forced** names. `nslookup thisdoesnotexist-zzz99.takealot.com` **resolves** → `*.takealot.com` is a **wildcard**. So brute "hits" like `jenkins./grafana./kibana./backup./crm./webmail./ftp.` are wildcard phantoms (none appear in crt.sh's authoritative list); 9 of them are flagged "risky".
- **Code trace:** `checkers_network.py:143-160` (crt.sh) + `:162-180` (brute, no wildcard guard) → `:251` risky filter → score `:258/265`. Render `templates/results.html:1752-1788`; `pdf_report.py:1149-1190`. Score `scoring_analytics.py:655-656` `sub_risk=min(100, risky*15)`. `ct_count` set at `:158` *before* the 150-cap at `:183` (can exceed `total_count`).
- **Verdict:** BUG (+ GAP on CT completeness)
- **Severity:** high
- **Finding:** No wildcard-DNS detection → brute-force fabricates "risky" subdomains on any wildcard apex; for takealot that yields 9 phantom risky subs that max `sub_risk` to 100. Separately, when crt.sh is empty/slow the card silently under-discovers (16 vs 77 real) yet the PDF still narrates "discovered via Certificate Transparency logs." `ct_count` can exceed `total_count` after the cap.
- **Solution(s):** (1) Add a wildcard probe — resolve one random label; if it resolves, drop brute-force results that share that IP set (free, ~1 extra DNS query). (2) Make crt.sh resilient: retry once + fall back to a second free CT source (certspotter free tier) and mark `ct_source_ok=false` so the PDF stops claiming CT when it was brute-only. (3) Set `ct_count` after the cap (or label it "CT entries pre-cap").

## Exposed Admin & Sensitive Paths
- **Source/provider:** `ExposedAdminChecker` — HEAD/GET probes of 38 admin/sensitive paths.
- **Ground-truth:** phishield fixture: **all 12** critical paths (`.env`, `.git/HEAD`, `wp-config.php`, `backup.sql`…) return **identical HTTP 403** behind **F5 BIG-IP ASM**. takealot: 4 critical paths all **403** behind **Cloudflare**. Live `curl -I https://www.takealot.com/.env` = **403**, but a random control path = **200** → the 403s are WAF managed-rule blanket-denies, not real exposures.
- **Code trace:** `checkers_core.py:1016` — `r.status_code == 200 or (risk=="critical" and r.status_code in [401,403])` counts 403 as a critical finding. Render `results.html:1730-1748`; `pdf_report.py:1116-1145` ("…including N critical exposure(s)"). Score `scoring_analytics.py:626-628` `admin_risk=min(100, crit*50+high*20)` → both fixtures hit **100**.
- **Verdict:** BUG (inversion)
- **Severity:** critical
- **Finding:** A WAF returning 403 to `/.env` means the file is **protected**, yet the checker reports it as a "critical exposure" and the PDF says "N critical exposure(s)". With WAF active, every critical path 403s → `critical_count` 12 (phishield) / 4 (takealot), `admin_risk` maxes to 100. WAF-protected orgs are scored as worst-case.
- **Solution(s):** (1) Treat 403/401 as "present-but-protected" (info, not critical) — only HTTP **200** with a non-WAF body counts as exposure. (2) WAF-aware suppression: if `waf.detected`, require a 200 + content-type/size sanity check before flagging. (3) Detect blanket-deny: if ≥N critical paths all return the same status from the same WAF, collapse to one "WAF blocks sensitive paths (good)" note.

## Technology Stack & EOL
- **Source/provider:** `TechStackChecker` — `Server`/`X-Powered-By` headers + hardcoded `EOL_SIGNATURES` table + CMS/JS-lib regex on body.
- **Ground-truth:** phishield: `Server: Apache` only, no EOL → correct PASS. takealot: `Server: cloudflare`, `X-Powered-By: Awesome` (Cloudflare's joke header) shown verbatim as "disclosed technology". `EOL_SIGNATURES` is **stale vs endoflife.date**: no PHP 8.0 (EOL Nov-2023) / 8.1 (EOL Nov-2025, live today 2026-06-02), no Node 18 (EOL Apr-2025)/20, no nginx ≥1.20, no Apache 2.4 branch.
- **Code trace:** `checkers_threats.py:14-49` (table) `:80-103` (header+EOL match) `:166` `eol_count`. Render `results.html:2242-2266` (`ts_tl='tl-crimson' if eol else 'tl-green'` — **no amber**, and X-Powered-By/jQuery/AngularJS penalties never move the light). Score `scoring_analytics.py:640` + REMEDIATION `:3360` keyed on `eol_count`.
- **Verdict:** GAP (+ minor BUG)
- **Severity:** medium
- **Finding:** EOL table is hand-maintained and already behind current endoflife dates (misses PHP 8.x, Node 18/20, modern nginx/Apache) so it will under-detect on real SA stacks; `X-Powered-By: Awesome` is surfaced as if meaningful; traffic light is binary (red/green) despite info-leak/old-jQuery penalties.
- **Solution(s):** (1) Replace the hardcoded table with the free **endoflife.date** JSON API (cached daily) keyed by detected product+major — kills staleness for ~0 cost. (2) Filter known-decoy headers (`X-Powered-By: Awesome`, PHP/ASP echo from CDNs) before display. (3) Add an amber light when `score < 100` but no EOL (info-leak / old-JS).

## CMS Plugin Surface (WordPress)
- **Source/provider:** `CMSPluginSBOMChecker` — `_is_wordpress` discriminator then probes 25 popular plugin dirs for `readme.txt` Stable-tag.
- **Ground-truth:** takealot is **not WordPress** (custom React/Node SPA) yet fixture shows `is_wordpress=True`, `plugin_count=25` (all `status_code 403`, 0 versioned). Live: `curl -I /wp-content/` and `/wp-login.php` → **200** (CDN catch-all), random path → **200**. So `_is_wordpress` trips on the 200 catch-all and every plugin dir "exists". phishield: 25/25 plugins, all 403 behind F5 — also implausible (no single site runs all 25 of these).
- **Code trace:** `checkers_supply_chain.py:871-886` `_is_wordpress` (accepts 200/301/302/401/403) → `:888-908` `_probe_plugin` (accepts 200/301/302/401/403) → `:941-962` score. Render `results.html:2268-2298`; `pdf_report.py:2407`. Score `scoring_analytics.py:735-736` `cms_risk=inv(score)`, weight 0.03, REMEDIATION `:3387`.
- **Verdict:** BUG (false positive)
- **Severity:** high
- **Finding:** Accepting 403 (and any non-404) as "plugin present" + a 200/403 catch-all defeating the WP discriminator makes the card report a full 25-plugin WordPress SBOM for sites that aren't WordPress (takealot) or behind a WAF (phishield). `cms_risk` then contributes phantom risk via the 0.03 weight.
- **Solution(s):** (1) Require **HTTP 200** AND a successfully-parsed `readme.txt` Stable-tag (or a plugin asset) — a bare 403 dir is not evidence of a plugin. (2) Harden `_is_wordpress`: confirm a real WP fingerprint (`wp-json` API 200 with JSON, or `wp-content` 200 serving a real asset), and bail if a random control path also 200s (catch-all). (3) Cap/flag "all 25 probed plugins matched" as a WAF/catch-all artefact, not a finding.

## Exposed Dependency Manifests (S-3)
- **Source/provider:** `DependencyManifestChecker` — HEAD+GET 15 manifest/lockfile paths, parse deps, OSV.dev CVE cross-ref.
- **Ground-truth:** Both fixtures: `exposed_manifests=[]`, 0 deps, 0 CVEs — correctly clean. This checker is the **only one of the five that handles WAF correctly**: `_probe` (`:188-201`) requires HTTP **200**, rejects HTML/`<!doctype`/"not found"/"404" bodies, and demands ≥10 bytes — so a WAF 403 is correctly ignored. Card hidden when `status != completed`/no manifests, so no empty-card noise.
- **Code trace:** `checkers_supply_chain.py:136-520`; OSV enrich `:348-413`; render `results.html:2142-2197`; `pdf_report.py:2206`. Score `scoring_analytics.py:723-724` `dm_risk=inv(score)`, weight 0.04, REMEDIATION `:3381`.
- **Verdict:** PASS
- **Severity:** n/a
- **Finding:** Logic is sound and WAF-robust; the 200-only + body-sanity gate in `_probe` is exactly the pattern the Admin and CMS checkers are missing. Minor: only exact-pinned versions are OSV-queried (SemVer ranges skipped by design — documented, acceptable).
- **Solution(s):** Use `_probe`'s 200-only + body-sanity gate as the template to retrofit `ExposedAdminChecker` and `CMSPluginSBOMChecker`.

## Cluster summary
cards=5, BUG=3 GAP=1 PASS=1 NEEDS-LIVE=0; headline = **WAF/CDN 403 blanket-deny and 200 catch-all responses are scored as positive findings**, fabricating "12 critical exposures" + a full 25-plugin WordPress SBOM + 9 wildcard-DNS "risky subdomains" on WAF/CDN-fronted orgs — maxing `admin_risk` and `sub_risk` and **penalising well-defended targets**. `DependencyManifestChecker._probe` already does it right (200-only + body sanity) and should be the fix template.
