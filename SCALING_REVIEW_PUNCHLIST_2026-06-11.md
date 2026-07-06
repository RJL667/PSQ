# Scaling / Dashboard / VM-Deploy Branch Review — Punch-list

**Branch reviewed:** `rjl667/master` @ `d5fa008` (38 commits: WS0 checker seam, WS1-WS10 scaling, React dashboard, VM deploy)
**Base:** clean fast-forward of `master` @ `03ce0a2` (contains the 2026-06-11 hardening). Merge would be a clean fast-forward; nothing diverged.
**Reviewed:** 2026-06-11, three parallel deep reads (checker output preservation; production hardening; dashboard + VM deploy).

**Context (clarified after first draft):** the branch owner is the project's brother, a former
systems architect, assisting with the hardening work. The `pii-proxy` was not deleted but
**relocated**: it is the redaction server from the roadmap, now running standalone on the Google
VM. `veilguard.phishield.com/scanner` is the intended production target (a VM the team owns and
provisioned), not an accidental exposure. The intended end-state is: `brafter` (origin) becomes the
deploy origin to the VM, functionality is verified first, then the UI is brought back in line with
the current on-Render look, and API keys are mapped when ready.

---

## Overall verdict

The work is sound and production-grade, not scaffolding. The merge is safe-by-default:
every scaling subsystem is opt-in by environment variable and defaults to today's
in-process / SQLite / local-disk behaviour, so a merge plus Render auto-deploy does not
break the current single-box deployment. Checker output is preserved on the healthy-scan
path (mechanical call-site swaps; supply-chain checkers untouched), and this is backed by a
genuinely well-built golden regression harness plus all existing gates staying green.

The items below are the gaps to close before the branch is relied on for underwriting numbers
and before the public VM is left running. None of them indicate the refactor is wrong; they
are the edges the current test coverage does not reach plus two operational exposures.

**Evidence the output is preserved (healthy path):**
- Golden replay gate: 39 of 40 checker baselines byte-identical (the 1 exception is a harness
  masking bug, see P2-3, not real drift).
- `verify_supply_chain_financial_wiring.py` 28/28; `pdf_snapshot.py --check` 6/6 byte-identical;
  `verify_subindustry_dropdown_mapping.py` 410/410; live `verify_scan_smoke.py` pass, shape intact.
- WS1-WS10 offline suite: 191/191 pass (Postgres/Redis paths covered via SQLite/FakeRedis or skip).
- `checkers_supply_chain.py` (S-1..S-10): zero diff.

---

## P0 — Authentication: ACCEPTED-OPEN for the development / testing phase (decision 2026-06-30)

### P0-1. Both deployments are intentionally unauthenticated during dev/testing
**Decision (project owner, 2026-06-30): leave both environments unauthenticated for now.** The
project is still in the development / production-readiness phase; API / authentication keys will be
**issued to public users when the time is right** (at production launch). This is a deliberate
choice, not an oversight, and applies to BOTH deployments, which are at parity:

- **VM** `https://veilguard.phishield.com/scanner` — `SCANNER_API_KEY` unset (verified in `.env`,
  2026-06-30). `/api/scan`, `/results/<id>`, `/pdf`, `/metrics` all return 200 unauthenticated.
- **Render** `https://phishield-scanner.onrender.com` — also unauthenticated (verified live
  2026-06-30: an `@require_api_key` endpoint returned 200 without a key). It has been open its whole
  life; the app had no auth mechanism at all before the 2026-06-11 opt-in work, and the Render URL is
  actually advertised in the scanner's User-Agent on every request, so it is the more discoverable of
  the two.

Both carry the always-on per-IP rate limiter (light abuse-damping). Real-world risk is low while the
URLs are unshared and traffic is test-only.

**When ready for production (do for BOTH environments together):**
- Set `SCANNER_API_KEY` on the VM and on Render, AND have the frontend send `X-Api-Key` (see P1-3,
  the prerequisite not yet done — frontend header must land first or the form 401s); and/or
- An interim Caddy edge control (basic-auth or IP allow-list) on the VM `/scanner/*` block is
  available if the new URL needs closing sooner than the full key roll-out.

This item is therefore **not a blocker** — it is a tracked production-launch task, intentionally
deferred.

---

## P1 — Before relying on the branch for underwriting output

### P1-1. `waf_truncated` is set but never consumed by scoring or the report
The WAF-aware early-exit commit (`57e43b6`) sets a `waf_truncated` flag on checker results and its
message states truncated checkers are "reported as not assessed, never all clear." That wiring does
not exist: `scoring_analytics.py`, `pdf_cards.py`, and `pdf_report.py` do not read the flag, so a
checker that exited early on a WAF-blocked target currently scores and renders as a clean pass.

This contradicts the "Not assessed" principle added on 2026-06-11 (muted cards must distinguish
"assessed, no findings" from "not checked"). Practical impact is currently narrow (the skipped paths
are non-scoring medium-risk or 403 responses), but the guarantee in the commit message is not real
until the flag is threaded into the score and the report.

**Fix:** consume `waf_truncated` in the scorer and the renderer (mirror the existing WAF coverage
notice / "not assessed" card path), or soften the commit's claim until it is wired.

### P1-2. Failure / quota path is live by default but unexercised by the gates
WS7 turned on, by default, on the paid-provider clients in `providers.py`: retry (3 attempts with
real backoff sleeps), a per-provider circuit breaker (opens after 5 consecutive failures), and a
usage ledger with daily caps plus a retry budget. The golden cassettes contain 73 HTTP 200s and a
single terminal 403, so no gate exercises any of this. Under real provider stress the checker output
can change in ways the harness cannot currently see:
- a breaker tripping mid-loop silently zeroes the remaining work (for example per-CVE NVD CVSS
  enrichment in `ShodanVulnChecker._fetch_cvss`, `checkers_threats.py:~485`);
- a daily-cap or budget hit short-circuits a provider to `None`, i.e. "no data" rather than a value.

These feed the financial model only through whether a checker reports data versus skips, so a healthy
scan is unaffected, but an outage / quota event now behaves differently from the pre-refactor code and
is untested.

**Fix:** add a few non-200 cassettes (429, 503, timeout) to the regression harness and assert the
intended degradation (skip with weight redistribution, no partial-enrichment surprise). Alternatively,
document the new behaviour as an accepted change with the breaker/cap thresholds called out.

### P1-3. Frontend does not send `X-Api-Key` (blocks enabling auth anywhere)
`/api/scan` and the four pre-flight / balance endpoints carry `@require_api_key`, but neither the Jinja
submit form nor the React SPA's runtime fetches (submit, progress poll/SSE, balance checks) send the
header. While `SCANNER_API_KEY` is unset this is a no-op, but the day auth is enabled on either Render
or the VM (see P0-1), submit and pre-flight start returning 401. This is the long-standing prerequisite
noted in `OUTSTANDING.md`.

**Fix:** have the frontend attach `X-Api-Key` (from build-time config or a meta tag) on every state-
changing / expensive call before auth is switched on.

---

## P2 — Hygiene (small, low-risk)

### P2-1. `redis` is not pinned in `requirements.txt`
`redis_support.py` does `import redis` only when `REDIS_URL` is set. Dormant today, but the VM runbook
(`DEPLOYMENT.md` §8) instructs setting `REDIS_URL` and raising worker count to scale, which would crash
with `ModuleNotFoundError`. A code comment claiming redis-py "is installed" is incorrect.
**Fix:** add `redis>=5.0` to `requirements.txt` before activating Redis.

### P2-2. Peer-rating selector reads the wrong field name
`frontend/src/data/selectors.ts` (`getPeerSummary`, ~line 750) reads `p.rating`, but the backend emits
`peer_rating` (`peer_benchmarking.py:357`). The rating renders as "—/10" even when present. Harmless
until the July cohort fills the pool above the min-cell threshold, then it silently suppresses a real
rating. (The `percentile` field name matches, so the percentile line works.)
**Fix:** one-line rename in the selector.

### P2-3. Shodan-age regression gate is non-deterministic (false failure)
`mig_threats_full.py` `full_shodanvuln` reports a diff because CVE `age_days` / `*_age_days` /
`*_unpatched_days` increment one per day and are not in `result_diff.DEFAULT_VOLATILE_KEYS`. The migration
itself is a clean call-site swap and replays byte-identically. Also note the `mig_*` runners print
"GATE FAILED" but still exit 0, so a CI hook keyed on exit code would miss a genuine future drift here.
**Fix:** add `age_days` and the `*_age_days` / `*_unpatched_days` patterns to the volatile-key set, and
make the `mig_*` runners exit non-zero on failure.

### P2-4. Stale / contradictory docstrings in `providers.py`
The module docstring (lines ~7-23) and per-checker header comments still say "No added retry
(max_attempts=1) ... breaker effectively disabled ... cache slots empty," but `_client` sets
`max_attempts=3`, `failure_threshold=5`, and wires the ledger and cache. This will mislead a maintainer
about credit burn and failure semantics.
**Fix:** correct the comments to reflect the live WS6/WS7/WS9 configuration.

### P2-5. Checkpoint + usage writes amplify SQLite write load on the free tier
Production now always passes `resume=True`, so roughly 30 `scan_checkpoints` rows plus one `usage` row
per provider call are written per scan. Best-effort (try/except), output-safe, but extra write traffic on
the `SQLITE_BUSY`-prone path. Not a Render blocker; it makes the Postgres cut-over more desirable than the
docs imply.
**Fix:** none required for correctness; prioritise the Postgres cut-over if Render stays under real volume.

---

## Product decision (not a defect)

The new React dashboard does not consume the `monte_carlo`, `risk_probability`, `return_periods`,
`cover_ladder`, or `loss_exposure` blocks. The 1:50 / 1:100 / 1:250 return-period and cover-ladder views
(noted internally as commercially mandatory) remain in the PDF but are dropped from the interactive
dashboard, which now shows only a min / expected / max range. Merging to origin makes this thinner view
the Render results page as well. Decide whether the dashboard should surface those blocks before or after
a wider rollout.

---

## VM deploy notes (secondary)

- Edge is **Caddy**, not nginx; sub-path `handle_path /scanner/*` to `127.0.0.1:8001`, `ProxyFix(x_prefix=1)`,
  React built with `SCANNER_BASE_PATH=/scanner`. Server and client URL prefixes agree.
- SSE: the `/scanner/*` block has no `flush_interval -1`; the app's `X-Accel-Buffering: no` is an nginx hint
  Caddy ignores. Likely works (Caddy streams by default) but the runbook has no live SSE/progress check.
  Recommend adding `flush_interval -1` plus an SSE smoke step.
- No rollback path (in-place overwrite, forward-only migrations). Consider a versioned release / symlink swap.
- `caddy_patch.py` inserts after the first `encode` line in the whole Caddyfile, not scoped to the named
  site block; an invalid reload could drop the co-hosted Veilguard site. Runtime is well isolated (separate
  container, loopback ports); blast radius is concentrated in the shared Caddyfile.
- `age` binary fetched from GitHub by version tag with no checksum.

---

## Suggested sequencing

1. P0-1 now (lock the VM).
2. P1-1, P1-2, P1-3 with the branch owner before underwriting reliance.
3. P2 items as a quick cleanup pass (all small).
4. Decide the dashboard fidelity question, then merge to `origin/master` (clean fast-forward, safe-by-default).
