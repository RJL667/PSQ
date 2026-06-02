# Attack Surface & Tech — Re-Test

Method: code verification of the committed fixes + free, non-intrusive live
re-checks against takealot.com (HttpWebRequest HEAD/GET, `[System.Net.Dns]`,
crt.sh JSON). Cached `phishield_live.json` is PRE-FIX, so all confirmation is
code + live. All five touched files byte-compile clean
(`py_compile` on checkers_core / checkers_network / checkers_supply_chain /
checkers_threats / scoring_analytics → OK).

## Subdomains (CT logs / crt.sh)
- **Was:** BUG (high) — no wildcard-DNS detection → brute-force fabricated 9
  "risky" phantom subs maxing `sub_risk`; crt.sh secondary/flaky so card
  silently under-discovered (16 vs 77) yet PDF claimed CT; `ct_count` could
  exceed `total_count`.
- **Now:** FIXED
- **Evidence:** `checkers_network.py:157-185` crt.sh is now PRIMARY with
  `%25`-encoding + 2-attempt retry + `ct_source_ok` flag; `:73-83 _wildcard_ips`
  resolves two random labels, `:193-204` suppresses brute-force on a wildcard
  apex, `:217` discards residual wildcard-IP brute hits; `:230`
  `ct_count=min(ct_count,total_count)` caps it. Live: crt.sh (after one 404
  retry, exactly the new loop) returned **76** unique subs; random labels
  `nx-*.takealot.com` → NXDOMAIN (no wildcard today, so brute hits with
  distinct IPs are legitimately kept — guard behaves correctly in both states).

## Exposed Admin & Sensitive Paths
- **Was:** BUG/INVERSION (critical) — 403/401 counted as critical exposure;
  WAF/CDN blanket-deny maxed `admin_risk` to 100, penalising well-defended orgs.
- **Now:** FIXED
- **Evidence:** `checkers_core.py:1098` now `if r.status_code != 200: return None`
  (403/401/404/3xx rejected), `:1103-1116` body-sanity GET rejects HTML shells
  (`<html`/`<!doctype`), "not found"/"404", and <10-byte bodies. Live proof of
  robustness on BOTH failure modes: `.env` & `.git/HEAD` → **403** (now
  suppressed); `wp-config.php`/`backup.sql`/`dump.sql` → **200 but body is the
  Next.js SPA shell** `<!DOCTYPE html><html…>` (16.6 kB) → caught by the
  `<!doctype` reject; random control → 404. Zero false criticals.

## Technology Stack & EOL
- **Was:** GAP + minor BUG (medium) — EOL table stale vs endoflife.date (no PHP
  8.x, Node 18/20, modern nginx/Apache); `X-Powered-By: Awesome` decoy surfaced
  & penalised; binary red/green traffic light (no amber).
- **Now:** PARTIAL
- **Evidence:** EOL GAP FIXED — `checkers_threats.py:14-67` table "Refreshed
  2026-06-02 against endoflife.date" now includes PHP 8.0 (EOL Nov-2023)/8.1,
  Node 16/18, nginx 1.16/1.18, IIS 8.x, Tomcat 9, Python 3.8. BUT the two minor
  BUG items remain: (1) no decoy-header filter — `:104-108` still emits
  "X-Powered-By discloses technology: Awesome" and applies `-5` for Cloudflare's
  joke header; (2) traffic light still binary — `results.html:2269`
  `ts_tl = 'tl-crimson' if ts.eol_detected else 'tl-green'`, no amber for
  info-leak/old-jQuery penalties.

## CMS Plugin Surface (WordPress)
- **Was:** BUG/false-positive (high) — `_is_wordpress` & `_probe_plugin`
  accepted any non-404 (incl. 403/catch-all 200), so a full 25-plugin WordPress
  SBOM was reported for non-WP/WAF sites; phantom `cms_risk`.
- **Now:** FIXED
- **Evidence:** `checkers_supply_chain.py:880-936 _is_wordpress` adds a catch-all
  guard (random path 200-body) + requires a genuine fingerprint (homepage
  `/wp-content/` or WP generator, OR `wp-login.php` 200 with `user_login`/
  `wp-submit`/`wordpress` markers AND body ≠ catch-all); `:938-974 _probe_plugin`
  now requires readme.txt **200** + real WP readme markers (`=== `/`stable tag:`/
  `tested up to:`), rejecting HTML shells. Live: takealot home has no
  `/wp-content/` or WP generator; `wp-login.php` → 200 but body is the SPA shell
  (= catch-all, no WP markers) → rejected; `akismet/readme.txt` → **404**. So
  `is_wordpress=False`, `plugin_count=0`. SBOM no longer fabricated.

## Exposed Dependency Manifests (S-3)
- **Was:** PASS — the only WAF-robust checker; `_probe` 200-only + body-sanity.
- **Now:** FIXED (no regression)
- **Evidence:** `checkers_supply_chain.py:188-201 _probe` unchanged — HEAD+GET
  both must be 200, len ≥10, rejects `<html`/`<!doctype`/"not found"/"404". This
  remained the template the Admin (`checkers_core.py:1098-1116`) and CMS
  (`:938-974`) fixes were modelled on. Compiles clean.

## Re-test summary
fixed=4 partial=1 still-broken=0 regressions=0 new=0; the WAF/CDN 403-blanket +
200-catch-all root cause is eliminated across Exposed Admin (inversion gone,
robust to both the 403 and the SPA-shell-200 case), CMS Plugins (false 25-plugin
WP SBOM gone), and Subdomains (crt.sh primary + wildcard guard + ct_count cap);
S-3 unregressed. Only residual: Tech Stack EOL **table** refreshed but the two
minor cosmetics — `X-Powered-By: Awesome` decoy still surfaced/penalised and the
binary (no-amber) traffic light — are not yet addressed.
