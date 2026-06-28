# Phishield Scanner — Scaling & Enterprise-Readiness Design

> Status: **DRAFT v2** — adversarially reviewed (5-round critic/researcher
> convergence pass; all citations spot-checked against code), then scoped to the
> scanner engine (CRM, PII/compliance, and multi-tenancy removed). Target: turn
> the current single-instance, thread-per-scan service into a horizontally
> scalable, resumable platform without losing the correctness hardening already
> baked into the scanner.

---

## 0. TL;DR

- The unit of work (`run_scan`, `app.py:670`) is a fire-and-forget daemon
  thread gated by an **in-process** semaphore. It does not survive a restart,
  cannot scale out, and re-spends paid API credits on any retry. Note the
  semaphore bounds **concurrent execution per worker, not intake**: `POST
  /api/scan` spawns the thread and returns `202` *before* touching the semaphore
  (`app.py:1086`–`1108`), which is acquired later on the worker thread
  (`app.py:684`) and whose timeout surfaces only via a poll ~15 min later — so
  there is **no submit-time admission control today** (the Phase-2 queue-full
  `429` is the first, and is net-new — §WS2).
- The fix is staged in two milestones:
  - **Milestone A — "scales safely":** route all outbound traffic through one
    HTTP seam (WS0), externalize state (Postgres + object storage), move scans
    onto a job queue with a separate worker tier, add **distributed** politeness
    rate-limiting, two-layer caching with single-flight, and a real
    retry/circuit-breaker policy. Resumability via per-checker checkpoints.
  - **Milestone B — "proper enterprise":** durable workflow engine
    (Temporal-class) with per-checker activities, authz/secrets, DR,
    observability/SLOs, autoscaling.
- **The single most important constraint:** the per-apex politeness rate
  limiter (`http_client.py:101`) is in-process and exists *because* parallel
  probes tripped a real WAF on the 2026-05-15 test scan (`http_client.py:5`).
  **This is not a future risk — it is already violated in production.**
  The repo-root `render.yaml:6` runs `gunicorn --workers 2 --threads 4
  --timeout 600`, so today there are already 2 worker processes (each with its
  own `Semaphore(2)`, `app.py:67`, and its own `DomainRateLimiter`). The
  per-apex limiter therefore *already* fails to coordinate across the two live
  workers, and the per-IP API limiter is already ~2x its configured value (the
  `_RateLimiter` docstring at `app.py:129` says as much). Distributing the
  limiter (WS5a) is **remediation of an existing latent WAF risk**, not merely a
  precondition for a hypothetical scale-out. Until WS5a lands, pin scan work to a
  single worker (or accept the doubled burst rate as a known risk). (WS5 splits:
  WS5a = distributed token buckets, ships Phase 2; WS5b = per-day credit
  budget/kill-switch, gated on the SCALE-17 usage ledger — see §WS5/§5.)
- **Second caveat that changes the math everywhere:** the chokepoint story is
  incomplete. `HttpClient._request` (`http_client.py:384`) is the *intended*
  single egress point, but the paid providers and crt.sh do **not** flow through
  it — they call `requests.*` directly (see §1.4). Distributing the in-process
  limiter and implementing `ProbeCache` buys nothing for Shodan/HIBP/DeHashed/
  IntelX/VirusTotal/crt.sh until those call sites are refactored onto the
  chokepoint or given per-provider client wrappers. That refactor (WS0) is a
  prerequisite for WS5/WS6, not a detail.

---

## 1. Current architecture (the constraints to design around)

### 1.1 Lifecycle
`POST /api/scan` (`app.py:1086`) spawns a daemon `threading.Thread` running
`run_scan` (`app.py:670`), which:
1. acquires an in-process `Semaphore(MAX_CONCURRENT=2)` (`app.py:67`). Note this
   is **per process**, and `render.yaml:6` runs `--workers 2 --threads 4`, so
   production already runs up to 2×`Semaphore(2)` = 4 concurrent scans across
   two uncoordinated processes;
2. runs `scanner.scan(...)` — the ~510 s phased pipeline;
3. runs peer benchmarking (opens its own DB connection, `app.py:731`);
4. `update_scan` writes the full results JSON blob to `scans.results`
   (`app.py:554`);
5. **generates the full PDF synchronously** and archives to local disk
   (`app.py:745`);
6. post-scan bookkeeping.

### 1.2 The scan pipeline (`scanner.py`)
Phased and order-dependent:
```
IP discovery → domain checkers (ThreadPool mw=6) → heavy sequential (ssl, subdomains)
  → related-domain lite → IP-pool expansion (subdomain + verified origin IPs)
  → per-IP checkers (mw=4) → scoring / correlation
```
The accumulators are two plain dicts, `cat_results` and `per_ip_results`
(`scanner.py:458`). **These are the natural checkpoint payload.** Per-checker
timing already exists in `checker_durations` (`scanner.py:462`); the
single instrumentation seam for checkpoint/skip is `_run_with_timing`
(`scanner.py:471`) and `_run_ip_with_timing` (`scanner.py:582`).

### 1.3 Hard limits (each is a workstream)
| Concern | Current state | Ref |
|---|---|---|
| Job model | daemon thread, no `running` state, no retry, dies with process | `app.py:1086`, `app.py:586` |
| Concurrency | in-process `Semaphore(2)` **per gunicorn worker**; `render.yaml:6` runs `--workers 2 --threads 4` → already 4 concurrent scans across 2 processes | `app.py:67`, `render.yaml:6` |
| Egress chokepoint | `HttpClient._request` is the *intended* single seam, but paid providers + crt.sh + origin/related discovery bypass it with direct `requests.*` (see §1.4) | `http_client.py:384` |
| Persistence | single SQLite file, **no WAL**, ephemeral disk on Render free tier | `app.py:240` |
| Results | one JSON blob in `scans.results` | `app.py:561` |
| Progress | in-memory dict, worker-local, lost on restart | `app.py:74` |
| Rate limiting (target politeness) | in-process per-apex token bucket | `http_client.py:101` |
| Rate limiting (API endpoints) | in-process per-IP fixed window | `app.py:129` |
| HTTP probe cache | **designed but stubbed** (`_NullProbeCache`), SCN-026 | `http_client.py:258` |
| Paid-API result cache | **does not exist** | — |
| Retries | central client has **none** (`_request` swallows and returns `None`); crt.sh retries up to 2× with a fixed 2.0 s sleep (`related_domain_discovery.py:125`–`143`; note the `retries=2` default contradicts its own "Retry once" docstring at `:115`) | `http_client.py:408`, `related_domain_discovery.py:111`, `:143` |
| PDF | scan path renders **full tier only** inline; request path lazily renders the **one requested tier** on demand and caches per-tier; ~10–30 s, memory spike | `app.py:751`, `app.py:1202`–`1212` |
| External APIs | HIBP, DeHashed, IntelX, Shodan, VirusTotal, SecurityTrails — paid/quota'd, **all called via direct `requests.*`** (§1.4) | `app.py:45`, `checkers_threats.py`, `darkweb_providers.py` |
| Schema migrations | hand-rolled `ALTER TABLE … except OperationalError: pass` | `app.py:264` |

**Cost insight:** every checker spends paid API credits, so a whole-scan retry
re-spends them. Checkpointing and caching are **money** optimizations here, not
just latency ones.

### 1.4 The chokepoint is a goal, not a fact — direct `requests.*` call sites
`HttpClient` (`http_client.py:310`) *documents* itself as the single egress
seam, and its own docstring says "Direct `requests.get` calls bypass these
controls — refactor them whenever found." They are pervasive, and they include
**every paid provider** — i.e. exactly the traffic WS5/WS6 exist to throttle and
cache. The refactor surface:

| Call site | Provider / target | Lines |
|---|---|---|
| `darkweb_providers.py` | IntelX, DeHashed, HIBP/HudsonRock variants | `:130`, `:143`, `:188`, `:236`, `:286` |
| `checkers_threats.py` | HIBP (`:225`), Shodan full API (`:518`), Shodan InternetDB — **free** (`:558`), IntelX (`:2082`, `:2101`), NVD/EPSS/ExploitDB, etc. | `:225`, `:518`, `:558`, `:2082`, `:2101`, etc. |
| `checkers_core.py` | **scan target's own apex** — `https://{domain}` HSTS/CSP/header/WAF probes + `mta-sts.{domain}` | `:314`, `:668`, `:844`, `:970` |
| `flag_inference.py` | **scan target's own apex** — `https://{domain}` footer/title scrape | `:157`, `:565` |
| `checkers_network.py` | subdomain/HTTP probes | `:109`, `:168`, `:421`, `:728` |
| `origin_discovery.py` | SecurityTrails (paid), Shodan count (free, `:95`) + search (paid, `:102`) | `:55`, `:95`, `:102` |
| `related_domain_discovery.py` | crt.sh | `:127` (inside `_crtsh_query`) |
| `credential_export.py` | export delivery | `:110` |

**Provider labels are load-bearing.** WS0b/WS5/WS6b key per-provider budgets and
caches off these labels, so each tag is verified against the URL constant:
`checkers_threats.py:558` is `INTERNETDB_URL = "https://internetdb.shodan.io/…"`
(`:437`) — **Shodan InternetDB, free/unauthenticated**, *not* IntelX (the real
IntelX calls are `:2082`/`:2101`, `X-Key` against `free.intelx.io`, `:2033`).
Mislabeling a free call as a paid one would misroute the per-provider
budget/cache wrapper.

Counts (verified by grep): **8 modules bypass the seam** with direct
`requests.*` — `checkers_core`, `checkers_network`, `checkers_threats`,
`credential_export`, `darkweb_providers`, `flag_inference`, `origin_discovery`,
`related_domain_discovery` (plus `http_client` itself, which *is* the seam).
Only **4 modules** route through `HTTP.*` — `checkers_core`,
`checkers_supply_chain`, `checkers_threats`, `http_client`. **`checkers_threats.py`
appears in both lists** (28 direct `requests.*` calls *and* 6 `HTTP.*` calls at
`:2470`/`:2540`/`:2544`/`:2847`/`:2851`/`:2915`): it is **partially migrated**, so WS0
must not assume any module is wholly on or off the seam — migrate call site by
call site, not module by module.

**Consequence:** moving the in-process limiter and `ProbeCache` to Redis touches
only the `_request` path and therefore buys nothing for the providers above —
nor for the **target-apex probes in `checkers_core.py` / `flag_inference.py`**,
which are the parallel `https://{domain}` hits the per-apex limiter exists to
pace — the **same class of concurrent target-apex request** as the privacy-policy
probes whose parallelisation is the documented WAF trip (`http_client.py:9`; those
specific probes are now *already* on the seam via `HTTP.*`, `checkers_threats.py:2470`/
`:2540`/`:2544`, so the original incident is paced — these unmigrated apex probes
are the same failure mode waiting to recur). WS0 (below) closes this gap and is a
hard prerequisite for WS5 and WS6.

---

## 2. Target architecture

```
                    ┌─────────────┐   enqueue    ┌──────────────┐
  Frontend  ──────► │  Web (Flask)│ ───────────► │  Job queue   │
  (poll/SSE)        │  thin: API  │              │ (RQ/Redis or │
        ▲           └─────┬───────┘              │  Postgres)   │
        │ progress        │ read results         └──────┬───────┘
        │                 ▼                              │ dequeue
   ┌────┴─────┐    ┌──────────────┐              ┌───────▼────────┐
   │  Redis   │◄───│  Postgres    │◄─────────────│ Scan workers   │
   │ pub/sub  │    │ scans+ckpt   │  checkpoint  │ (N, autoscale) │
   │ +rate-lim│    │ +cache       │              │ light + heavy  │
   └──────────┘    └──────┬───────┘              └───────┬────────┘
                          │                              │ on complete
                   ┌──────▼───────┐              ┌────────▼───────┐
                   │ Object store │◄─────────────│  PDF workers   │
                   │ (R2/S3) PDFs │   upload     │ (separate pool)│
                   └──────────────┘              └────────────────┘
```

### Design principles
1. **Web tier does no work** — it enqueues and reads.
2. **Nothing important lives in process memory** — semaphore, rate limiter,
   progress, and cache all move to shared stores.
3. **One egress seam before politeness** — every paid call and crt.sh must flow
   through a controllable client (WS0) before distributed pacing/caching can do
   anything for them; then distributed per-apex pacing precedes further fan-out.
4. **Spend credits once** — caching + single-flight + checkpointing prevent
   re-paying providers.
5. **Degrade, don't fail** — a dead provider trips a breaker and the checker is
   marked `skipped` (scoring already redistributes weight, `scoring_analytics.py:687`).

---

## 3. Workstreams

### WS0 — Route ALL outbound traffic through one HTTP seam (**prerequisite for WS5/WS6**)
Today `HttpClient._request` (`http_client.py:384`) is bypassed by every paid
provider, crt.sh, **and the scan target's own apex probes** (§1.4). Distributed
rate-limiting and probe-caching are inert against that traffic until this lands.
Two acceptable shapes:
- **(a) Funnel onto `HTTP.*` (per-apex limiter):** refactor each direct
  `requests.*` call site in `checkers_network.py`, **`checkers_core.py`**
  (`:314`/`:668`/`:844`/`:970`), and **`flag_inference.py`** (`:157`/`:565`) to
  call `HTTP.get/post/head`. This is the right shape for **target-apex traffic**
  because those hits go to the *customer's* `https://{domain}` / `mta-sts.{domain}`,
  not to a paid provider — they need the per-apex politeness limiter, not a
  provider quota. Simplest, but a call routed here shares the generic apex limiter.
- **(b) Per-provider client wrappers:** give each paid provider a thin client
  that owns its own token bucket, credit budget, retry policy, and result cache.
  More code, but it's the natural home for WS5's per-provider budget and WS6b's
  result cache, and it decouples provider quota from politeness pacing.
- **Recommendation:** (b) for the five paid providers + crt.sh (where the money
  and provider quotas live); (a) for the plain HTTP probes in `checkers_network.py`
  **and the target-apex probes in `checkers_core.py` / `flag_inference.py`**.
- **WS5's WAF remediation is incomplete until every target-apex probe — not just
  the paid providers — flows through the seam.** The *documented* 2026-05-15 WAF
  trip was the **privacy-policy** probes (`http_client.py:9`), and those are
  **already** on the seam (`HTTP.get`/`HTTP.discover`, `checkers_threats.py:2470`/
  `:2540`/`:2544`) — so the original incident is already paced. The unmigrated
  parallel `https://{domain}` hits in `checkers_core.py` / `flag_inference.py` are
  the **same failure mode** (concurrent target-apex requests outside the per-apex
  limiter) — a latent recurrence, not the original culprit. The structural fix is
  identical regardless: if WS0 ships only the provider refactor, the WS5
  distributed per-apex limiter still won't pace those remaining apex probes, and
  the thesis (WS0 closes the gap so WS5 can remediate) is not satisfied.
- **Partial-migration footgun:** `checkers_threats.py` already mixes `requests.*`
  (28 sites) and `HTTP.*` (6 sites) (§1.4). WS0 must track migration at call-site
  granularity, not assume a module is wholly on or off the seam.
- Until WS0 lands, **the per-provider budget/kill-switch and paid-API cache
  cannot be implemented at all** — there is no seam to enforce them at.
- **Risk-ordering hazard: WS0 is a large pure refactor and must not land on the
  non-durable free tier.** WS0 rewrites the direct `requests.*` call sites across
  **8 modules** (§1.4: `checkers_core`, `checkers_network`, `checkers_threats`
  — 28 direct + 6 mixed `HTTP.*` sites — `credential_export`, `darkweb_providers`,
  `flag_inference`, `origin_discovery`, `related_domain_discovery`). A
  per-provider-wrapper refactor that subtly changes a checker's output shape would
  silently corrupt the `scans.results` blob. Sequencing this *behavior-preserving*
  refactor as **Phase 0 — before Phase −1 (leave free tier) and Phase 1
  (Postgres)** — runs it on the **least durable infra**, where the SQLite file and
  any regression evidence vanish on every restart/deploy (Open decision 5), so
  there is **no retained baseline to diff a regression against**. That inverts
  risk ordering: the riskiest pure refactor on the flimsiest substrate. Two ways
  to fix it, at least one **required**:
  1. **Re-sequence: make Phase −1 (leave free tier, durable disk) a hard
     predecessor of Phase 0 too**, not only of Phase 1. Then WS0 lands on durable
     storage with retained logs/results for regression diffing. **Preferred** —
     it costs only a phase reorder.
  2. **Gate WS0 behind a golden-output regression harness:** capture N current
     scan `results` blobs as fixtures, then assert structural/byte equivalence
     (modulo timestamps/durations) of each refactored checker's output
     pre/post-WS0, at call-site granularity. This is the **only** test strategy
     the WS0 refactor has anywhere — without it a shape change is undetectable on
     ephemeral infra. Build it regardless of (1); on durable infra it still guards
     the migration.

### WS1 — Externalize state (foundation; everything depends on it)
- **SQLite → Postgres** (Render Postgres). `get_db()` (`app.py:240`) is the
  single chokepoint — replace with a pooled `psycopg`/SQLAlchemy-core
  connection (add PgBouncer when worker count grows). Port `?` → `%s`,
  replace the hand-rolled migrations (`app.py:264`) with **Alembic**.
  - **This is a present-tense hazard, not only a scale ceiling.** `get_db()` opens
    a *bare* `sqlite3.connect(DB_PATH)` per call — no pool, no WAL pragma — while
    `--workers 2 --threads 4` (`render.yaml:6`) plus daemon scan threads each open
    their own connection (peer benchmarking opens a fresh `get_db()` *mid-scan*,
    `app.py:731`). Under concurrent writes, default rollback-journal locking
    already serializes writers and can raise `SQLITE_BUSY` **today**; the migration
    fixes a current correctness/latency risk, not just a future one.
  - The DB migration covers only the scanner tables (`scans`, the new
    `scan_checkpoints`, queue/heartbeat state). Since in-flight scans are already
    non-durable today, this can take a short hard cutover.
  - **The free tier makes the *current* state non-durable**, which is exactly
    why this can't be a casual cutover: Open decision 5 notes Render free tier
    has **ephemeral disk + idle spin-down**, so the live SQLite file is *already*
    lost on every deploy/restart. **Leaving the free tier is therefore a hard
    predecessor of Phase 1** (rollout Phase −1), surfaced as such in the rollout
    table — not a footnote.
- **State machine:** replace `pending|completed|failed` with
  `queued → running → completed|failed|cancelled`; add `started_at`,
  `attempts`, `worker_id`, `last_heartbeat`. The stale-scan hack
  (`app.py:595`) becomes heartbeat + visibility-timeout requeue.
- **Object storage** (Cloudflare R2 / S3) replaces the local `scans/<domain>/…`
  archive (`app.py:748`) and `_pdf_cache` (`app.py:1201`), both of which die on
  Render's ephemeral disk.

### WS2 — Job queue + worker tier (Milestone A core)
- **Recommendation: Redis + RQ** (tasks are long ~510 s and coarse). Alternative
  with zero new infra beyond Postgres: a `scan_jobs` table polled with
  `SELECT … FOR UPDATE SKIP LOCKED` (or `procrastinate`).
- **Lift-and-shift** the body of `run_scan` into a job function. `POST /api/scan`
  stops spawning a thread and enqueues `{scan_id, params}`; still returns `202`.
- **Delete the in-process semaphore** — concurrency = `worker_count ×
  per_worker_concurrency`.
  - **Name the replacement admission control — and be honest that the 429 is
    NET-NEW, not "preserved."** Correct a tempting misframing: the semaphore does
    **not** give request-time backpressure today. `POST /api/scan`
    (`app.py:1086`–`1108`) spawns the daemon thread and **unconditionally returns
    `202` before any semaphore interaction**; the `_semaphore.acquire(timeout=
    SCAN_QUEUE_TIMEOUT_S)` runs on the worker thread inside `run_scan`
    (`app.py:684`), and on timeout it `mark_failed`s the scan (`app.py:687`) —
    surfaced only via a later `GET /api/scan` poll (~15 min, `SCAN_QUEUE_TIMEOUT_S`),
    never in the submit response. **So today excess scans are already accepted
    (202) at the HTTP layer and fail only visibly via polling minutes later.**
    Admission is unbounded at submit time *now*. The semaphore bounds *concurrent
    execution per process*, not *intake*. Therefore the Phase-2 queue-full `429`
    is a **new synchronous admission capability**, not preservation of an existing
    property — and that is a reason to pull it forward, because the system gains
    submit-time rejection it never had. **Interim admission control = the queue's
    bounded length + the WS1 visibility-timeout/heartbeat** (a dead worker's job
    is requeued, not lost). **Pull the queue-full backpressure into Phase 2:**
    when the queue is full, `POST /api/scan` returns **`429` (or `202` "queued,
    ETA")** instead of accepting unbounded work — giving the system its first
    synchronous failure-at-submit, which the in-process semaphore never provided.
- **Job timeout is independent of `gunicorn --timeout`.** After WS2 the web
  worker only enqueues and returns `202` in milliseconds, so `--timeout 600`
  (`render.yaml:6`) governs request handling, *not* job duration — they are
  different tiers; don't equate them. Derive the RQ job timeout from the actual
  worst-case scan, **not** the round "510 s" figure. The pipeline budgets are
  sequential: lightweight batch (180 s pool timeout, `scanner.py:487`) →
  heavy checkers (`ssl` 75 s + `subdomains` 150 s, `scanner.py:435`/`:443`, plus
  crt.sh; +60 s if `fraudulent_domains`, `:447`) → related-domain lite (up to
  300 s, `scanner.py:526`) → per-IP batch (`scanner.py:605`).
  - **The per-IP term is not a flat 180 s — it scales with `|all_ips|`.** The
    180 s at `scanner.py:605` is a *soft* `as_completed` deadline, while each
    future's `future.result(timeout=DEFAULT_TIMEOUT * 2)` (`scanner.py:608`) is a
    per-future cap, and `all_ips` grows via subdomain + verified-origin expansion
    (`scanner.py:540`–`570`) running 4 checkers × N IPs at `max_workers=4`
    (`scanner.py:592`). So stragglers already running past the soft deadline are
    not hard-cut, and the per-IP phase tail grows with the discovered-IP count.
  - **Therefore the worst-case sum is not a fixed constant.** Size the RQ job
    timeout off the **max-IP scenario** (a fraudulent-domains + many-IP target can
    plausibly exceed 600 s, killing a long *legitimate* scan), and add a **hard
    per-job ceiling independent of the soft `as_completed` deadlines** so a
    pathological target can't run unbounded. Without checkpoints (WS3) a
    timeout-requeue **re-spends credits** (see below).
- **Idempotency** keyed by `scan_id` so a double-submit or requeue cannot run
  twice concurrently. **Ordering caveat:** WS2 ships in Phase 2 but WS3
  checkpoints land in Phase 5, so between those phases any requeue re-burns paid
  credits. Either pull a minimal checkpoint (WS3 Tier B) forward into Phase 2,
  or **explicitly accept credit re-spend on requeue until Phase 5** — don't
  leave it implicit.
- **Worker pool segmentation:** light checkers vs heavy (`sslyze` spawns
  subprocesses; `subdomains`) get separate pools sized for memory.

### WS3 — Resumability / checkpointing
Two tiers; phased pipeline gives clean seams.
- **Tier A (free):** queue requeues a dead worker's job → whole scan re-runs.
  Simple, but re-spends credits.
- **Tier B (the win):** `scan_checkpoints(scan_id, checker_name, result_json,
  completed_at)`. Before running a checker, skip-and-load if a checkpoint
  exists. Insertion point: `_run_with_timing` / `_run_ip_with_timing`. On
  requeue the scan resumes by skipping already-checkpointed checkers and **does
  not re-spend credits**.
- **"Last completed checker" is the wrong mental model inside a concurrent pool —
  resume granularity is "re-submit the un-checkpointed set."** Checkpoints are
  written *per checker*, but the lightweight domain checkers run in a
  `ThreadPoolExecutor(max_workers=6)` (`scanner.py:481`) and the per-IP checkers
  at `max_workers=4` (`scanner.py:592`). A worker that dies mid-phase therefore
  leaves a **ragged frontier** — some checkers in the batch completed and
  checkpointed, others were in-flight, others never started — not a single clean
  "last completed checker." Pin the resume contract:
  1. **Per-checker checkpoint writes are independent rows, each committed on its
     own** (one `INSERT` per checker as it finishes inside `_run_with_timing` /
     `_run_ip_with_timing`, `scanner.py:471`/`:582`). A partial pool is thus
     safely durable: every committed row is a complete checker result.
  2. **Resume rebuilds the same pool and re-submits only checkers with no valid
     checkpoint.** On requeue, the worker reconstructs the `domain_checkers` /
     `ip_checkers_templates` set exactly as `scan()` would, then for each checker
     skips-and-loads if a valid checkpoint row exists and submits the rest to a
     fresh `ThreadPoolExecutor`. There is no need to know which futures were
     in-flight vs never-started — both are simply un-checkpointed, so both are
     re-run.
  3. **In-flight-but-uncommitted checkers are re-run, never half-written.** A
     checker interrupted before its row commits leaves no checkpoint, so it is
     re-submitted on resume — no partial/half-written checkpoint can be loaded.
     (Combined with WS3's classify rule below, an interrupted checker also never
     poison-caches an `{"status":"error"}` blob: only non-failed results are
     written.)
  - **Net:** "clean seams" hold at **checker** granularity for *durability* (one
    committed row = one done checker) and at **pool-rebuild** granularity for
    *resume* (skip checkpointed, re-submit the rest). The phase ordering still
    gives clean *phase* seams for cross-phase dependencies (IP set, scoring);
    intra-pool there is no single seam, and none is needed.
- **The IP pool must be checkpointed, not recomputed.** Later phases depend on the
  discovered-IP set (`scanner.py:532`–`576`), and "just recompute it on resume" is
  **not** free: origin-IP expansion (`discover_origin_ips`, `scanner.py:560`–`567`)
  calls SecurityTrails (paid, `origin_discovery.py:55`) and Shodan (paid search,
  `:102`), and subdomain expansion reads `cat_results["subdomains"]`
  (`scanner.py:533`) whose heavy checker runs crt.sh. Recomputing therefore
  re-spends SecurityTrails/Shodan credits and re-hits crt.sh — contradicting
  Tier B's own "does not re-spend credits" guarantee. **Mandate:** checkpoint
  `discovered_ips` + `ip_sources` + the `origin_discovery` result.
  `origin_discovery` is also stored as `cat_results["origin_discovery"]`
  (`scanner.py:567`) and feeds scoring, so treat it as a checkpointed checker in
  its own right.
- **Bound checkpoint validity by the same data-type TTL as the WS6 result
  cache.** Checkpoint freshness and cache freshness are two different clocks for
  the *same* paid data. Without this, a scan resumed days later could load a
  stale `breaches` checkpoint and serve breach data **past its freshness
  window**, defeating the TTL the cache enforces — a long-resumed scan would
  silently report outdated breach findings. A checkpoint older than its data
  class's TTL is treated as absent (re-run), so the resumed scan reflects current
  data, not a stale vintage.
- **Partial-failure semantics:** a scan with N skipped checkers still completes;
  scoring redistributes weight. Record per-checker terminal vs retriable outcomes
  so resume knows what to re-attempt.
- **The classification cannot live at `_run_with_timing`.** Both
  `_run_with_timing` (`scanner.py:471`) and `_run_ip_with_timing`
  (`scanner.py:582`) catch *every* exception and flatten it to
  `{"status":"error","error":str(e),"issues":[]}` (`:477`, `:588`); the
  lightweight pool additionally maps pool-level timeouts to `{"status":"timeout"}`
  (`:499`). At that seam no exception type, HTTP status, or provider identity
  survives, so the checkpoint layer literally cannot tell terminal from
  retriable there. Two fixes, both required:
  1. **Classify upstream** — propagate a structured outcome (exception class /
     status code / provider) from the checkers or HTTP layer (post-WS0, where the
     original error still exists) up to the checkpoint writer.
  2. **Checkpoint-write rule: persist anything that is NOT a known failure.**
     The predicate must be the *negation of the failure shapes*, not
     `status == "success"`. Most successful checkers return domain-specific dicts
     with **no top-level `status` key at all** (e.g. `ssl` returns `{"score":…}`,
     `breaches` returns `{"breach_count":…}`); a naive `status == "success"` rule
     would refuse to checkpoint them and re-run every successful checker on
     resume, silently defeating the cost saving. Define "done" as
     `_is_failed(data)` is **False** *and* `status` is not in the skipped set —
     reusing `scoring_analytics`'s existing classification as the single source of
     truth: `_FAILED_STATUSES = {"error","timeout"}` (`scoring_analytics.py:659`),
     `_SKIPPED_STATUSES = {"no_api_key","auth_failed","disabled","skipped"}`
     (`:662`), surfaced via `_is_failed` (`:664`). This keeps checkpoint-write and
     weight-redistribution (`scoring_analytics.py:687`) agreeing on what "done"
     means. The flattening seams that *do* set status — `{"status":"error"}`
     (`scanner.py:477`/`:588`), `{"status":"timeout"}` (`:499`/`:620`) — are
     exactly the blobs this predicate must reject, so they are re-run on resume
     rather than poison-cached as "completed."

### WS4 — PDF decoupling ("knock out the PDFs")
- **Today neither path renders three tiers.** The scan-path archive calls
  `generate_pdf(results)` with the **default `report_type="full"` only**
  (`app.py:751`, default at `pdf_report.py:1747`); the request path lazily
  renders the **one** requested tier on demand and caches per-tier
  (`app.py:1202`–`1212`). So "render all three up front" would be a *new* 3×
  reportlab cost on every scan — the very memory spike WS4 is trying to relieve —
  paid even when the broker never downloads the assessment/summary tiers.
- **Keep generation lazy in the PDF worker.** On scan completion, enqueue a PDF
  job (own pool) that renders the tier(s) actually requested, on first request,
  and caches the bytes to object storage (replacing the ephemeral `_pdf_cache`,
  `app.py:1201`). Pre-render all three only if download-rate data justifies it;
  default is render-on-first-request.
- `GET /api/scan/<id>/pdf` (`app.py:1177`) becomes a lookup → signed object-store
  URL, or `409 generating`. No reportlab in the request path.
- Isolating reportlab's memory spike to its own pool relieves the 512 MB
  pressure that forced `MAX_CONCURRENT=2`.

### WS5 — Distributed rate-limiting + API-credit budgeting (depends on WS0)
**This workstream splits into two independently-shippable halves with different
dependencies — do not bundle them.** WS5a (token buckets) needs only WS0 + Redis
and ships early; WS5b (credit budget + kill-switch) additionally needs the
SCALE-17 usage ledger, which does not exist today, so it cannot ship with WS5a.

**WS5a — Distributed token buckets (Phase 2; no ledger needed).**
- **This remediates an existing prod risk, not a future one.** The in-process
  limiter (`http_client.py:101`) *already* fails to coordinate across the 2 live
  `--workers 2` processes (`render.yaml:6`); the per-IP API limiter is already
  ~2x its configured rate (`app.py:129` docstring). Treat WS5a as fixing a latent
  WAF/quota risk that exists today, and pin scans to one worker until it lands.
- **Move the per-apex token bucket to Redis** (`http_client.py:101` → shared).
  This only helps traffic that goes through `_request`; the paid providers and
  crt.sh do not (§1.4), so **WS0 must land first** for this to cover them.
- **Per-provider token bucket** (Shodan/HIBP/DeHashed/IntelX/VirusTotal),
  enforced in the per-provider client wrappers (WS0b), shared across workers.
- Both buckets are pure rate counters — they need no credit ledger, so WS5a is
  unblocked by WS0 alone and rides in Phase 2 with the queue.

**WS5b — Per-day credit budget + kill-switch (gated on SCALE-17 ledger; Phase 4
or explicitly deferred to Phase 7).**
- Has **no enforcement seam today**: the paid calls bypass any shared client
  (§1.4) and there is **no cost/credit ledger anywhere in the code**. It depends
  on **both** (a) the WS0 chokepoint refactor and (b) a usage-counting store
  (Redis counters keyed by `provider+day`) — that store **is SCALE-17 / FinOps**.
  Because WS5b cannot count spend without that ledger, it **cannot ship in
  Phase 2 with WS5a**. Pull it to **Phase 4** alongside the result cache (where
  the same per-provider client wrappers and counters already exist) or defer it
  to **Phase 7** with FinOps; the rollout table (§5) reflects this split.

### WS6 — Caching of API calls (two layers; **6b is the primary cost lever**)
- **(b) Paid-API result cache — do this first; it is where credits are spent.**
  This cache **does not exist** and is **independent of the HTTP `ProbeCache`**
  (6a never touches the paid providers — §1.4). It lives in the per-provider
  client wrappers (WS0b): cache DeHashed/IntelX/Shodan/HIBP/VirusTotal results
  keyed by `(provider, params)` with **data-type TTLs** (breach corpus → days;
  infostealer feeds → hours). The cache key is global — `(provider, params)` —
  so the same domain scanned twice coalesces onto one cached result.
  - **Single-flight / coalescing protocol (spec, not just a name).** A bare
    Redis `SETNX` does not by itself guarantee principle #4 ("spend credits
    once") under concurrent same-domain scans — the continuous-monitoring case.
    Pin the semantics:
    - **Lease, not a bare lock.** The lock holder writes
      `lock:(provider,params) = fencing_token` via `SET NX PX <ttl>`. The
      `ttl` must be **≥ the provider's worst-case call timeout** so the holder
      cannot lose the lease mid-call: the longest paid call is Shodan search at
      `timeout=20` (`origin_discovery.py:103`), with DeHashed full export at
      `timeout=30` (`credential_export.py:110`) and HIBP/IntelX in the same
      band — so a 60 s lease floor with **holder-side renewal** (extend the PX
      while the call is in flight, gated on the fencing token) covers the tail
      and survives a slow provider.
    - **Waiter rule (bounded, no deadlock, no stampede).** The waiter does
      **not** block on the lock indefinitely. It blocks on a Redis pub/sub
      `result-ready:(provider,params)` signal (reusing the WS8 pub/sub seam)
      **with a bounded timeout** while polling the 6b result cache; the holder's
      **result-cache write IS the completion signal** (publish-after-write, so
      the cache entry and the notification can't disagree). On signal or on a
      cache hit the waiter returns the cached value — paying zero. If the
      bounded wait elapses with no result (holder crashed before writing), the
      waiter **falls through to acquire the lease itself** and fetches. This
      bounds worst-case duplicate spend to *one* extra call per crash, never a
      stampede.
    - **Holder crash / fencing.** A crashed holder's lease simply expires (PX
      TTL); the next waiter's `SET NX` wins with a **new fencing token**. The
      stale holder, if it revives, fails its token check on cache-write and
      discards its result — so a zombie holder cannot clobber a fresher entry.
      No waiter deadlocks past the lease TTL.
    - **`force_refresh` = "bypass the read, still take the lease."** Define the
      WS6a `force_refresh` param (currently spec-only, `http_client.py:276`) so
      it skips the *cache read* but **still acquires the single-flight lease and
      writes the result**. Without this rule a `force_refresh` burst on one
      domain would have every request miss the cache and stampede the paid
      provider — exactly what single-flight exists to prevent.
    - **Freshness precedence: a checkpoint and a `force_refresh` cache miss must
      not coexist in one report (cross-WS3/WS6 rule).** A WS3 checkpoint is itself
      a cache of paid data, on a *different clock* than the 6b result cache. On a
      resumed scan, one checker could load a still-valid checkpoint (vintage T1)
      while another, run with `force_refresh`, fetches live (vintage T2) — serving
      **two freshness vintages of the same breach corpus inside one report.** Pin
      the precedence: **`force_refresh` is scan-scoped and dominates checkpoints.**
      If a scan is submitted `force_refresh` (or a resumed scan re-runs any
      provider with `force_refresh`), it **invalidates that scan's checkpoints for
      the same data class** and re-fetches, so the whole report reflects one
      vintage. Absent `force_refresh`, a valid (non-expired, per WS3's TTL bound)
      checkpoint is authoritative and is **not** re-fetched. The two clocks never
      mix within a single scan's output.
  - **Negative caching:** cache "no breach found" or re-pay on every clean
    re-scan. Negative entries are written and signalled through the same
    single-flight path so a clean domain is also coalesced.
- **(a) HTTP probe cache** — implement `ProbeCache` (SCN-026) against
  Redis/Postgres using the TTL table specced in the docstring
  (`http_client.py:266`): 2xx 24h, 404 7d, 5xx 1h, 403/451 6h, 429/503 30m
  (honour `Retry-After`). **Readiness check:**
  - The store/lookup wiring at `http_client.py:391` is real but only for the
    `_NullProbeCache` no-op path and only for traffic through `_request` — i.e.
    *not* the paid providers. So 6a's single-flight/negative-caching/data-type-
    TTL value props attach to a layer that doesn't see the expensive calls; they
    belong in 6b.
  - `force_refresh` is **specced in the `ProbeCache` docstring** (`:276`) only —
    it is **not implemented**: `POST /api/scan` (`app.py:1086`) has no
    `force_refresh` param and there is no invalidation path. The API param and
    the IP/ASN-change invalidation trigger are **unbuilt**; budget for them.
- This layer (chiefly 6b) is what makes **continuous monitoring** economically
  viable.

### WS7 — Retries / circuit breakers
Replace swallow-and-return-`None` (`http_client.py:408`) with a policy at the
HTTP chokepoint **and** the per-provider clients (WS0) — today the only retry
anywhere is crt.sh's hand-rolled `retries=2` loop
(`related_domain_discovery.py:111`, sleep at `:143`):
- **Classify:** retriable (timeout, conn reset, 429, 502/503/504) vs terminal
  (401/403/400). Don't retry terminal.
- **Exponential backoff + jitter**, capped attempts, honour `Retry-After`.
- **Circuit breaker per provider:** trip → mark checker `skipped` (weight
  redistributes, `scoring_analytics.py:687`) instead of dragging every scan.
- **Completeness floor — "degrade, don't fail" needs an N-ceiling, or it becomes
  "score on a fraction of the signal."** Principle #5 and the breaker→`skipped`
  path lean on weight redistribution (`scoring_analytics.py:687`), which scales
  remaining weights up so excluded checkers don't drag the score. Verified, but
  unbounded: redistribution will happily produce a confident-looking score from a
  sliver of coverage. If one provider outage trips breakers on, say,
  `breaches` + darkweb + `shodan_vulns` at once, the doc's "a scan with N skipped
  checkers still completes" has **no ceiling on N** — and for a cyber-**insurance**
  risk score, silently scoring on heavily degraded data is a liability, not
  graceful degradation. Mandate a **minimum-coverage admission rule**:
  - Define a coverage threshold off the weights already in `scoring_analytics`:
    the **`excluded_weight` fraction** (`excluded_weight` is already computed at
    `scoring_analytics.py:690`) must stay below a cap (e.g. < 0.30 of total
    weight), and/or a small set of **must-have checkers** must be present.
  - If coverage falls below the floor, the scan is marked **`partial` /
    `low-confidence`**, not `completed`, and the shortfall is surfaced to the
    broker. **Reuse the existing disclaimer
    plumbing:** the `WAFTracker` already drives a "partial coverage" disclaimer in
    the report renderers (`http_client.py:11`–`16`), and scoring already accepts
    `waf_apex_status` (`scoring_analytics.py:668`) — feed breaker-`skipped`
    coverage into the *same* disclaimer path so a degraded scan never emits a
    clean, unqualified score.
- **Retry budget** so a provider outage can't retry-storm into rate limits/cost.
  Scope it **per provider per rolling window**, and store the counter in the
  **same SCALE-17 Redis ledger** that backs WS5b's kill-switch (`provider+day`
  counters) — this is the *same* ledger dependency, so call it out here rather
  than implying a second counter store. No ledger ⇒ no enforceable retry budget,
  exactly as for WS5b.
- **Idempotency** at the job layer (keyed by `scan_id`, WS2).
- **Dead-letter queue — define the record, don't just name it.** Because
  checkpoints (WS3) and retries (WS7) co-ship in **Phase 5**, a DLQ entry for a
  *partially completed* scan must reference the surviving checkpoint set so a
  human/automated re-run resumes rather than restarts. The DLQ record carries:
  `scan_id`, the **last-good checkpoint set** (the `scan_checkpoints` rows that
  survived — WS3), the **failed checker**, the **terminal reason** (the
  classified terminal outcome, not the flattened `{"status":"error"}` blob — see
  WS3's classify-upstream rule), and **attempt count**. On replay, completed
  checkpoints are loaded and only the failed/unreached checkers re-run — so the
  DLQ does not re-spend credits on the part that already succeeded.
- **Poison-scan detection reuses WS1 state, not a new counter.** Trip "poison"
  off the `attempts` and `worker_id` fields already added to the scan state
  machine (WS1) — N failed attempts across distinct `worker_id`s ⇒ route to the
  DLQ and alert, rather than requeueing forever.

### WS8 — Progress across workers
- **The transport is replaced, not reused.** Today `on_progress` writes into a
  per-process in-memory `queue.Queue` (`app.py:676`–`682`) and the SSE endpoint
  reads the *same* process's `_scan_progress` dict (`app.py:74`, read at
  `app.py:1154`). After WS2 the worker and the web/SSE tier are different
  processes, so the existing callback wiring is **thrown away**: replace the
  in-process `queue.Queue` transport with **Redis pub/sub** (channel per
  `scan_id`); the worker publishes and the SSE endpoint subscribes. The
  `on_progress` *event shapes* (`scanner.py:493`) are reusable; the delivery path
  is rebuilt, and the in-memory `_scan_progress` / `_scan_progress_created` dict
  plus the TTL `_sweep` machinery (`app.py:74`–`93`) are deleted.
- **Pub/sub is fire-and-forget — reconcile late/reconnecting subscribers.**
  Redis pub/sub delivers only to clients subscribed *at publish time*, so an SSE
  client that connects after an interim event, or reconnects mid-scan, misses
  everything published before it subscribed. The current code at least replays
  **terminal** state from the DB row (`app.py:1143`–`1159` short-circuit
  completed/failed; the live path at `:1154` only sees events arriving after the
  in-process queue handle is fetched), but interim progress is lost on a
  mid-scan reconnect. Back the channel with replay: either a short **Redis
  Stream** per `scan_id` (subscriber `XREAD`s the backlog from last-seen id, then
  tails) or a **last-N progress snapshot column** (`progress_pct` /
  `current_checker` plus a small recent-events list) the SSE handler emits on
  connect before tailing pub/sub. Either way a late subscriber replays current
  progress instead of only future events.
- Interim: frontend already polls `GET /api/scan/<id>`; a `progress_pct` /
  `current_checker` column defers SSE until needed (and doubles as the snapshot
  above).
- **The Phase 2 → Phase 6 cutover window breaks live progress entirely — close
  it explicitly.** The moment WS2 (Phase 2) moves workers into separate processes,
  the worker no longer populates the web process's in-memory `_scan_progress`
  dict, but the SSE endpoint still reads it (`app.py:1154`). For every in-flight
  scan the lookup misses and the endpoint short-circuits to `empty_stream`,
  emitting a single `{'type':'complete'}` (`app.py:1155`–`1159`) — i.e. **live
  SSE progress returns "complete" immediately and is silently dark from Phase 2
  until WS8 ships in Phase 6**, not merely degraded. This is a four-phase gap, so
  it must be sequenced, not left implicit. Two acceptable resolutions:
  1. **Pull the minimal progress bridge forward into Phase 2** alongside WS2:
     ship the `progress_pct` / `current_checker` DB column *now* (the worker
     updates it from the `on_progress` callback, `scanner.py:493`) and have the
     SSE handler — and `GET /api/scan` — read it. This keeps a coarse progress
     signal alive through the whole window with no Redis dependency, and the
     column is reused as the WS8 snapshot later. **Preferred.**
  2. **Or explicitly accept SSE-dark and fall back to polling.** If the column is
     deferred, the frontend MUST stop using `/progress` SSE from Phase 2 and poll
     `GET /api/scan/<id>` (status `pending` → `completed`) for the entire Phase
     2–6 interval. State this in the rollout, not only as a WS8 interim: the
     polling fallback is the *active* progress path during the gap, not a
     post-WS8 nicety.

### WS9 — Observability / ops
- Distributed tracing (OpenTelemetry, correlation id = scan id), structured
  logs. Ship existing `checker_durations` (`scanner.py:462`) to metrics.
- Dashboards/alerts on queue depth, worker liveness (heartbeat), API-credit
  burn, failed-scan rate. Dead-letter visibility.
- **SLOs are numbers + an error budget, not a label — pin the headline four.**
  "SLOs" by itself is a dashboard heading; an enterprise verdict needs targets
  and a burn policy that *feeds* the WS10/SCALE-16 autoscaling and load-shedding
  decisions. Derive the latency target from the **verified worst-case pipeline
  budget**, not the round "510 s" the doc warns against (§WS2). The sequential
  phase budgets are: lightweight pool 180 s (`scanner.py:487`) → heavy `ssl` 75 s
  + `subdomains` 150 s (`scanner.py:435`/`:443`) + `fraudulent_domains` 60 s when
  enabled (`:447`) → related-domain lite up to 300 s, `min(300, 60×N)`
  (`scanner.py:526`) → per-IP soft deadline 180 s (`scanner.py:605`) that **grows
  with discovered-IP count** (§WS2). A no-fraud, few-IP target sums to ~600 s; a
  fraud + many-IP target exceeds it — so set the latency SLO on the *common*
  (no-fraud, ≤ small-IP) path and treat the worst case as the **hard job ceiling**
  (WS2), not the SLO. Headline targets (initial; tune against real percentiles):
  | SLO | Target | Drives |
  |---|---|---|
  | Scan completion p95 (common path) | **< 8 min** | job-timeout sizing (WS2), capacity |
  | Queue admission p99 (submit → 202/429) | **< 1 s** | WS2 web tier stays thin (enqueue-only) |
  | Availability (submit + results read) | **99.5%** monthly | paging |
  | Failed-scan rate (terminal, non-degraded) | **< 2%** rolling 7-day | breaker/DLQ health (WS7) |
  - **Error budget + burn policy.** The 99.5% availability and < 2% failed-scan
    targets define the budget; tie burn to action: **fast burn (budget consumed
    ≥ 10×) pages**; **sustained burn (failed-scan rate or queue-wait p95 breaching
    for > 1 h) triggers load-shedding** — the SCALE-16 queue-full `429`/ETA starts
    rejecting at submit rather than letting the queue grow unbounded. This is the
    explicit link from SLO breach → backpressure (WS2/SCALE-16) the doc otherwise
    leaves unstated.

### WS10 — Enterprise hardening
- **AuthN/AuthZ:** API-key auth → RBAC on the admin/results/export endpoints.
- **Secrets:** `.env`/env vars → vault (Doppler/Vault/cloud KMS) with rotation.
- **Schema migrations:** Alembic + zero-downtime migration discipline.
- **DR — name the numbers and solve the multi-store consistency problem this
  design creates.** "Defined RPO/RTO" is unnamed today; pin **RPO ≤ 15 min**
  (Postgres PITR / WAL archiving) and **RTO ≤ 1 h**. The harder problem is that
  the design now spreads data across **three stores**: Postgres (scans,
  checkpoints), object store (PDFs/exports, WS4), and Redis
  (cache + usage ledger + progress streams). A naive restore recovers Postgres to
  T but the object store to T−Δ (or loses Redis entirely), yielding orphaned
  PDFs and mis-attributed spend that no longer match surviving copies. Pin the
  reconciliation:
  - **Postgres is the single source of truth on divergence.** Object-store PDFs
    and the Redis ledger are *derivable*; the authoritative scan state lives in
    Postgres.
  - **Object store reconciles to `scans` after PITR.** PDFs are content-addressed
    or keyed by `scan_id`; after a Postgres PITR, a sweep drops object-store
    blobs whose `scan_id` no longer exists (incl. erased scans) and re-enqueues
    PDF jobs (WS4) for completed scans missing their blob. PDFs are regenerable
    from `scans.results`, so a T−Δ object store is recoverable, not a data loss.
  - **The Redis usage ledger must be reconstructable — a volatile-only billing
    ledger is itself a FinOps risk.** Do **not** treat the SCALE-17
    `provider+day` counters as the durable record of spend: mirror each metered
    call to an append-only **`usage` table in Postgres**, so the Redis counters
    are a fast cache rebuildable by replaying that table. A lost Redis then loses
    only the rate-limit window, not the billing/attribution history.
- **Autoscaling & backpressure:** queue-depth-driven worker autoscaling; admission
  control / load shedding returns "queued, ETA" instead of OOM. **Note the
  interim backpressure (queue-full → 429/ETA) already ships in Phase 2 with WS2**
  — this is the system's *first* synchronous admission control (today's
  in-process semaphore bounds execution, not intake — §WS2), so this workstream
  is the autoscaling/load-shedding build-out on top of that new capability.
- **Egress reputation:** outbound requests hit *customer* infra — egress IP
  management, abuse handling, keep `/scanner-info` self-identification legit
  (`http_client.py:327`) to avoid blocklisting.
- **FinOps:** hard budget caps on paid APIs; depends on the WS0 provider-client
  seam + the usage/credit ledger (SCALE-17, which also backs WS5b's budget and
  WS7's retry budget).
- **Queryable results:** the single JSON blob (`app.py:561`) is fine for
  rendering; add structured columns or a warehouse export for reporting.

---

## 4. Milestone A vs B — model decision

| | **Model A — one job per scan** | **Model B — task DAG (per checker)** |
|---|---|---|
| Orchestration | simple; keeps intra-scan ThreadPools | coordinator + dependency graph |
| Resumability | per-checker checkpoints (WS3) | automatic at task granularity |
| Retries | per-job + per-call policy (WS7) | per-task, isolated |
| Memory isolation | per-pool (light/heavy) | per-task, finest-grained |
| Rate limiting | WS0 egress seam + distributed limiter still required | WS0 + distributed limiter **mandatory** |
| Complexity / cost | low | high |
| When | thousands of scans/day | latency- or memory-bound at high volume |

**Recommendation:** ship **Model A** first. Move to **Model B only when** single-
scan latency or per-pool memory forces it — and then **don't hand-roll the
orchestrator**: adopt a durable workflow engine (**Temporal**, or Inngest / AWS
Step Functions). Temporal gives per-activity (= per-checker) execution, retry
policies, timeouts, heartbeating for long activities, and replay-based
resumability for free — replacing most hand-rolled checkpoint/retry/queue code.

---

## 5. Phased rollout

| Phase | Deliverable | Unblocks |
|---|---|---|
| **−1 (hard predecessor)** | **Leave Render free tier** — persistent disk + no idle spin-down (Open decision 5) | makes the SQLite file durable enough to migrate; **precondition for BOTH Phase 0 and Phase 1** (WS0 is a large refactor that needs retained results/logs to regression-diff against — see WS0) |
| 0 | **Route all egress through one HTTP/provider-client seam (WS0)** — **gated on the golden-output regression harness** (capture-N-blobs, assert per-checker output equivalence) | makes WS5/WS6 enforceable at all |
| 1 | Postgres + object storage + state machine + Alembic (WS1) | durability, multi-instance |
| 2 | **Distributed token buckets (WS5a)** + queue & worker tier (WS2, incl. minimal queue-full → 429/ETA backpressure) | safe horizontal scale + interim admission control |
| 3 | PDF as separate job → object store (WS4) | removes memory spike, raise concurrency |
| 4 | Two-layer cache + single-flight (WS6; 6b first) + **SCALE-17 usage ledger + WS5b credit budget/kill-switch** | stop re-paying providers; enables monitoring; budget enforceable |
| 5 | Retry / circuit-breaker policy (WS7, DLQ references checkpoint set) + per-checker checkpoints (WS3) | resilient + resumable |
| 6 | Progress (WS8, with late-subscriber replay) + observability (WS9) | UX + operability |
| 7 | Enterprise ops: authz, secrets, DR, FinOps (WS10) | "proper enterprise" |
| 8 | (if needed) Temporal task-DAG (Model B) | latency/memory at extreme scale |

Notes:
- **Phase −1 (leave free tier) gates everything — including Phase 0.** Render
  free tier has ephemeral disk + idle spin-down, so the live SQLite file is
  already non-durable; migrating off it (WS1) is meaningless until persistent
  storage exists. It is *also* a predecessor of **Phase 0**: WS0 is a large
  behavior-preserving refactor and must not land where its regression evidence
  (results blobs, logs) vanishes on restart (see WS0). Hard predecessor, not a
  parallel nicety (Open decision 5).
- **WS0 is Phase 0** because WS5 and WS6 are inert against the paid providers and
  crt.sh until their direct `requests.*` calls (§1.4) route through a
  controllable client — **but it ships *after* Phase −1 and behind a
  golden-output regression harness** (§WS0). Landing an 8-module refactor on
  ephemeral infra with no retained baseline to diff against inverts risk
  ordering; the harness + durable disk are the two guards.
- **WS5 splits across phases.** WS5a (token buckets) ships in Phase 2 on WS0 +
  Redis alone. **WS5b (per-day credit budget + kill-switch) cannot ship in
  Phase 2** — it needs the SCALE-17 `provider+day` usage ledger, which does not
  exist until Phase 4 (or Phase 7 with FinOps). The table places WS5b in Phase 4
  alongside the cache and ledger; do not read "WS5 in Phase 2" as shipping the
  kill-switch.
- **The WAF risk is already live.** Production runs `--workers 2` (`render.yaml:6`),
  so the in-process limiter already fails to coordinate across two processes
  *today*. Until WS5a lands, **pin scan work to a single worker** (or accept the
  doubled burst as a known risk) — WS5a is remediation of an existing defect, not
  a guard for a future scale-out.
- **WS2-before-WS3 credit gap:** between Phase 2 (queue) and Phase 5
  (checkpoints), a job timeout/requeue re-spends paid credits. Either pull a
  minimal WS3 Tier-B checkpoint into Phase 2 or accept the re-spend explicitly.
- **WS2-before-WS8 progress gap:** the instant workers become separate processes
  (Phase 2), the in-memory SSE path goes dark — `app.py:1154` misses and returns
  an immediate `complete` (`app.py:1155`–`1159`) — and stays dark until WS8 ships
  in Phase 6. Close it: ship the `progress_pct`/`current_checker` column with
  WS2 (Phase 2), or make the frontend fall back to `GET /api/scan` polling for
  the whole Phase 2–6 window (§WS8). Do not leave the four-phase gap implicit.

---

## 6. Open decisions
1. **Queue:** Redis + RQ vs Postgres-as-queue (`SKIP LOCKED`). RQ recommended.
   Postgres-as-queue does high-churn writes (requeues, heartbeats, checkpoint
   writes); if chosen, isolate queue + checkpoints in a separate schema,
   otherwise prefer RQ/Redis.
2. **Milestone B engine:** Temporal vs Celery-canvas vs Step Functions — defer
   until Model A is in production and volume justifies it.
3. **Object store:** Cloudflare R2 (egress-free) vs S3.
4. **Render plan:** must leave free tier (persistent disk + no idle spin-down)
   before Phase 1 matters — this is **rollout Phase −1, a hard predecessor of
   Phase 1**, not a deferred decision. The free-tier ephemeral disk means the
   live SQLite file is already non-durable today.

---

## 7. Appendix — initial ticket list
- SCALE-00 Route all egress through a controllable client — paid providers +
  crt.sh via per-provider wrappers (shape b), **and the target-apex probes in
  `checkers_core.py` (`:314`/`:668`/`:844`/`:970`) + `flag_inference.py`
  (`:157`/`:565`) onto `HTTP.*` (shape a, per-apex limiter)**. Prerequisite for
  SCALE-04a/04b/08/17 and for SCALE-04a's WAF remediation to cover ALL target
  traffic (§1.4 call sites). **Lands on durable infra (after SCALE-00b) and gated
  on SCALE-00c regression harness** — it is an 8-module refactor that can silently
  reshape `scans.results`
- SCALE-00b **Leave Render free tier** (persistent disk + no spin-down) —
  Phase −1, hard predecessor of **both SCALE-00 and SCALE-01** (the live SQLite
  file and any WS0 regression evidence are non-durable on free tier)
- SCALE-00c **Golden-output regression harness for WS0** — capture N current scan
  `results` blobs as fixtures; assert per-checker structural/byte equivalence
  (modulo timestamps/durations) pre/post-refactor, at call-site granularity.
  Hard gate on SCALE-00
- SCALE-01 **Postgres + Alembic for the scanner tables** (`scans`,
  `scan_checkpoints`, queue state) — Alembic baseline replaces the hand-rolled
  migrations
- SCALE-02 Scan state machine (`attempts`, `worker_id`, `last_heartbeat`) +
  heartbeat/visibility-timeout
- SCALE-03 Object-storage adapter (archive + PDF cache)
- SCALE-04a Distributed per-apex + per-provider **token buckets** (Redis) —
  Phase 2, no ledger needed (WS5a)
- SCALE-04b Per-day **credit budget + kill-switch** (WS5b) — gated on SCALE-17
  ledger; Phase 4 or deferred to Phase 7
- SCALE-05 RQ queue + scan worker service; web enqueues only; **queue-full →
  429/queued-with-ETA** — the system's FIRST synchronous submit-time admission
  control (today's semaphore bounds execution on the worker thread, not intake;
  `POST /api/scan` already returns 202 before the semaphore, `app.py:1086`–`1108`/
  `:684`). NET-NEW capability, not "preserved"
- SCALE-06 Worker pool segmentation (light/heavy)
- SCALE-07 PDF job + signed-URL serving
- SCALE-08a Paid-API result cache (per-provider, in WS0 clients) + **single-flight
  lease (fencing token + TTL ≥ provider worst-case + holder-side renewal),
  pub/sub-or-poll waiter, `force_refresh` = bypass-read-but-take-lease** —
  primary cost lever; independent of the HTTP ProbeCache. **Cache key is global
  `(provider, params)`. `force_refresh` is scan-scoped and invalidates that
  scan's same-data-class checkpoints so one report = one freshness vintage**
- SCALE-08b ProbeCache impl (SCN-026) HTTP path + `force_refresh` API param +
  IP/ASN-change invalidation (both currently unbuilt)
- SCALE-09 Retry policy + per-provider circuit breakers + **DLQ record
  (`scan_id`, last-good checkpoint set, failed checker, terminal reason,
  attempts)**; retry-budget counters reuse the SCALE-17 ledger; poison-scan
  detection off `attempts`/`worker_id`. **Completeness floor: if breaker-`skipped`
  coverage exceeds the cap (excluded_weight fraction, `scoring_analytics.py:690`),
  mark scan `partial`/`low-confidence` (not `completed`) and route
  through the existing WAFTracker "partial coverage" disclaimer
  (`http_client.py:11`–`16`; scoring already takes `waf_apex_status`,
  `scoring_analytics.py:668`) — no clean score on heavily degraded data**
- SCALE-10 Per-checker checkpoint table + skip-and-load (**one committed row per
  checker; resume rebuilds the pool and re-submits only un-checkpointed checkers;
  in-flight-uncommitted are re-run**); **checkpoint rows TTL-bounded to the WS6
  data-type TTL so a long-resumed scan can't serve stale data (freshness)**
- SCALE-11 Redis pub/sub progress + SSE refactor + **late-subscriber replay
  (Redis Stream or last-N snapshot column)**. **Ship the
  `progress_pct`/`current_checker` column with SCALE-05 (Phase 2)** or accept
  SSE-dark + polling fallback for Phase 2–6 — the in-memory SSE path
  (`app.py:1154`) goes dark the moment workers split out (returns immediate
  `complete`, `:1155`–`1159`)
- SCALE-12 OpenTelemetry tracing + metrics + dashboards + **headline SLO targets
  (scan p95 < 8 min common-path, admission p99 < 1 s, availability 99.5%,
  failed-scan rate < 2%) + error-budget burn → load-shed/page policy feeding
  SCALE-16**
- SCALE-14 Secrets vault + rotation
- SCALE-16 Autoscaling + admission control/backpressure (the queue-full 429 of
  SCALE-05 is the interim; this is the autoscaling/load-shedding build-out)
- SCALE-17 FinOps: usage/credit ledger (Redis counters `provider+day`) +
  kill-switch (depends on SCALE-00) — **also backs SCALE-04b's budget and
  SCALE-09's retry budget**. **Mirror every metered call to an append-only
  Postgres `usage` table** so the Redis counters are a rebuildable cache, not the
  durable billing record (volatile-only ledger is a FinOps + DR risk)
- SCALE-18 DR: **RPO ≤ 15 min (Postgres PITR/WAL) + RTO ≤ 1 h**; multi-store
  restore reconciliation — Postgres is source of truth, object-store PDFs swept +
  regenerated against `scans` after PITR, Redis ledger rebuilt from the SCALE-17
  `usage` table
