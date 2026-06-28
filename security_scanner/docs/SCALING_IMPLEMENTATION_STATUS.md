# Scaling implementation — status & morning brief

Companion to [SCALING_DESIGN.md](SCALING_DESIGN.md). Tracks what's actually been
built vs. what's blocked on you. Updated: 2026-06-28 session (WS0 enablement —
checker-level gate + provider-client scaffold).

---

## TL;DR
I built the two pieces of the plan that are **safe to do unattended** — pure,
additive, fully-tested code that changes **no** runtime behaviour and touches the
live scanner not at all. Everything past this point needs infrastructure,
credentials, or a billing decision that's yours to make (see "Blocked on you").
Nothing was committed; nothing on disk was modified outside new files.

---

## ✅ Done & verified (safe, additive, unwired)

### 1. SCALE-00c — Golden-output regression harness
The safety gate the design says must exist *before* the WS0 refactor.
`tooling/regression/`:
- `result_diff.py` — reusable structural comparator (volatile-field masking,
  numeric tolerance, JSON-path diffs). 14/14 unit tests pass
  (`py tooling/regression/test_result_diff.py`).
- `golden.py` — `--capture` / `--check` driver over the scoring/financial layer.
  Deterministic & offline (replays fixtures through `scoring_analytics.py` with
  no network; Monte Carlo is seeded). Includes a determinism self-check.
- `baselines/` — two frozen baselines (phishield finance R10M score 282; takealot
  retail R13.5B score 205).
- **Proven to bite:** a deliberately tampered baseline (+7 to the score) made
  `--check` fail with exact pinpointing (`$.overall_risk_score 289 -> 282`,
  exit 1); re-capture restored a clean pass.
- Verify now: `py tooling/regression/golden.py --check` → `GOLDEN CHECK PASSED`.

**Gates:** the scoring/financial layer (`scoring_analytics.py`, `insurance.*`).
**Does not yet gate:** the network checkers — that needs a record/replay cache,
which is entangled with WS0's egress seam (chicken-and-egg the design calls out).
The comparator is already general enough for it; see the harness README.

### 2. WS7 / SCALE-09 — Resilience toolkit
`resilience.py` (new top-level module, **imported by nothing yet**):
- `classify_status` / `classify_exception` — retriable-vs-terminal split
  (timeout/conn-reset/429/5xx retriable; 4xx auth terminal).
- `RetryPolicy` — exponential backoff + equal jitter, capped attempts, honours
  `Retry-After`. Sleep/jitter injectable for deterministic tests.
- `CircuitBreaker` — thread-safe CLOSED/OPEN/HALF_OPEN per-key breaker; clock
  injectable.
- `guarded_call` — composes breaker + retry.
- 36/36 unit tests pass (`py tooling/test_resilience.py`).

This is the building block WS7 mounts inside the WS0 per-provider client wrappers.
It is intentionally **not wired in** — wiring touches the live request path and
needs the WS0 seam + your review first. **(Now mounted in the WS0 provider-client
scaffold below — still not wired to any live call site.)**

### 3. SCALE-00c (checker level) — HTTP record/replay + checker gate
The design treated a checker-level regression gate as **blocked on WS0** (you
can't intercept every call until it flows through one seam — its chicken-and-egg).
**That premise was wrong, and this breaks it.** An egress audit (2026-06-28) found
all outbound traffic funnels through `requests` (no urllib3/httpx/aiohttp/socket),
so the universal seam is `requests.sessions.Session.request` — one layer *below*
WS0. New files in `tooling/regression/`:
- `http_cassette.py` — record/replay over `Session.request`; canonical,
  secret-redacted request keys; replay serves responses with **zero network**;
  request-fidelity diff. 19/19 tests pass (`test_http_cassette.py`).
- `checker_gate.py` — `record_baseline(name, fn)` / `verify(name, fn)`: freeze a
  checker's outbound calls + result blob, then assert a refactor changed neither
  under replay. Catches all three WS0 failure modes (new/changed call → CassetteMiss,
  dropped call → fidelity, changed output → blob diff). 8/8 tests pass.
- **Consequence for sequencing:** WS0's *correctness evidence* (committed cassette
  + frozen blob) no longer needs durable infra to exist. This removes one of the
  two reasons the design made Phase −1 a hard predecessor of the WS0 refactor (the
  other — durable SQLite for live scans, WS1 — still stands).

### 4. WS0b — Per-provider client scaffold (`provider_client.py`)
New top-level module, **imported by no checker yet**. `ProviderClient` layers, over
raw `requests`: a per-provider token bucket (WS5a-ready), retry + circuit breaker
(mounts `resilience.py` via `guarded_call`), a result-cache slot (WS6b-ready,
disabled by default), and a metering hook (WS5b/SCALE-17 ledger plug). Returns a
`Response` or `None`-on-failure, matching the raw-site contract it will replace.
10/10 tests pass (`tooling/test_provider_client.py`). This is the seam the
call-site migration moves the 51 direct `requests.*` calls onto.

### Corrected egress inventory (supersedes the design's §1.4)
The design doc is stale. Verified 2026-06-28: **51 direct `requests.*` sites across
10 modules**, **19 providers** (design said ~6) — adds OSV.dev (×7), Snusbase,
LeakCheck, WhiteIntel, NVD, EPSS, ExploitDB, MSF, HudsonRock, Tranco. Worst module
is `checkers_threats.py` (39 direct + 7 already-on-seam — partially migrated, so
migrate call-site by call-site). `checkers_supply_chain.py` is the exemplar (7/7
on the seam). Full table is in the session notes; regenerate with a grep sweep
before the migration as it drifts.

---

## ⛔ Blocked on you (cannot be done unattended)
In rough priority order:
1. **API keys + a stable target, to record WS0 baselines.** The checker-level gate
   is built but its baselines must be captured against a real run (`record_baseline`
   makes one live scan per checker, needing the providers' API keys and a chosen
   target). This is the *only* thing standing between here and starting the WS0
   migration — and it no longer requires durable infra (the baseline is a committed
   file). Give me the keys/target (or run the capture yourself) and the migration
   can begin.
2. **Leave the Render free tier (Phase −1).** A billing decision. **Downgraded:**
   it is *no longer* a hard predecessor of the WS0 *refactor* — the committed
   cassette is the retained regression evidence the design worried free-tier
   couldn't keep. It **remains** a hard predecessor of **Phase 1 (WS1)**, which
   needs durable SQLite/Postgres for live scan state.
3. **Provision infrastructure + credentials:** Render Postgres, Redis, an
   object-storage bucket (R2/S3). WS1/WS2/WS5/WS6/WS8 all need these; I can't
   create them or hold their secrets.
4. **Confirm scope decisions** the design left open (§6): queue engine
   (RQ/Redis vs Postgres-queue), object store (R2 vs S3), and — from a prior
   session — whether the **single-tenant** scope (CRM/PII/multi-tenancy removed)
   is what you want long-term.

## WS0 migration — ✅ COMPLETE (branch `scaling/ws0-migration`)
**All 50 direct `requests.*` call sites across the scanner now route through the
seam** (`checkers_supply_chain` was already there). Done per-module, each gated
offline by a `tooling/regression/mig_<module>.py` (record original → migrate →
verify; synthetic transport, no keys/network):

| Module | Sites | Commit |
|---|---|---|
| `flag_inference` | 2 (apex → HTTP) | `5c1f29d` |
| `checkers_core` | 4 (apex → HTTP) | `d8fbc5c` |
| `related_domain_discovery` + `credential_export` | 2 (CRTSH, DEHASHED) | `644b2b4` |
| `origin_discovery` + `darkweb_providers` | 8 (ST, Shodan, IntelX, Snusbase, LeakCheck, WhiteIntel) | `349de12` |
| `checkers_network` | 7 (apex → HTTP, crt.sh) | `d6c66c2` |
| `checkers_threats` | 27 (apex + 15 providers) | `e51665b` |

`providers.py` is the registry: one `ProviderClient` per provider (19), all WS0
transparent pass-throughs (no retry, breaker off, gentle bucket, empty cache/meter
slots).

**Gate coverage (8 offline gates, all green):** `mig_flag_inference`,
`mig_checkers_core`, `mig_small_providers`, `mig_providers_2`, `mig_checkers_network`,
`mig_checkers_threats` (free feeds), `mig_threats_full` (every provider checker's
`check()` entry point — BreachChecker/Payment/VirusTotal/SecurityTrails/Dehashed/
HudsonRock/IntelX/WebRanking/Glasswing/ShodanVuln, dummy keys + DNS/socket/sleep
stubs + cache resets), `mig_network_takeover` (the CNAME-takeover HTTP probe). Each
records the **pre-migration** behaviour and diffs the migrated code under replay.
- One site is **gated by analogy, not directly**: crt.sh in `SubdomainChecker.check`
  (168) — byte-identical to the gated `related_domain_discovery` crt.sh pattern
  (sits behind brute-force DNS enumeration that isn't worth driving offline).
- Caveat that remains: gates use **synthetic** responses (real free-provider
  *shapes*; dummy keys for paid), so they prove request-fidelity + output-
  equivalence on the captured data, not every response-parsing branch. Real-key
  gold baselines (next step 1) would close that.

## ▶️ Recommended next steps
1. **Real-key gold baselines.** Run `record_baseline` against a live target with
   real API keys for the paid providers + the DNS/socket-bound takeover path, to
   upgrade those from review-gated to gold-gated. (The only thing keys are needed
   for now.)
2. **WS7 turn-on** (later): raise `ProviderClient` `max_attempts` / lower the
   breaker threshold in `providers.py` to activate retry + circuit-breaking — one
   edit per provider, no checker touched. Add tests for the new failure paths.
3. **WS5a**: tighten per-provider buckets / swap for the Redis distributed bucket.
4. Then **WS1** (Postgres, needs Phase −1) and the rest of the rollout.
2. **WS1** Postgres + Alembic + state machine (note the present-tense
   `SQLITE_BUSY` hazard — current `get_db()` has no pool/WAL). Needs Phase −1.
3. Then WS2 (queue) → WS4 (PDF worker) → WS6b (cache) → WS5/WS7 wiring, per the
   rollout table.

---

## Footprint (all new files; nothing existing modified)
Earlier sessions:
- `resilience.py`
- `tooling/regression/{result_diff,golden,test_result_diff}.py`, `README.md`,
  `baselines/*.json`
- `tooling/test_resilience.py`
- `docs/SCALING_DESIGN.md` + `.pdf`

2026-06-28 session (WS0 enablement):
- `tooling/regression/http_cassette.py` + `test_http_cassette.py` (19 tests)
- `tooling/regression/checker_gate.py` + `test_checker_gate.py` (8 tests)
- `provider_client.py` + `tooling/test_provider_client.py` (10 tests)
- this file + `README.md` updates

No runtime module (`app.py`, `scanner.py`, `checkers_*`, `scoring_analytics.py`,
the DB) was touched — `provider_client.py` is imported by nothing yet. Full suite:
**77 unit tests pass + the scoring golden gate**. Nothing committed — all changes
are uncommitted in the working tree for your review.
