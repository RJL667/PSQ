# Session handoff — 2026-06-11 — operational hardening shipped (SCN-030/031)

**Master tip: `bd66ade`** (was `2b91c00`), pushed to BOTH remotes (origin =
brafter12345-cmyk/PSQ, rjl667 = RJL667/PSQ). Render auto-deploy triggered by
the origin push. One commit, 130 files.

## What shipped

**SCN-030 — app self-protection (Phase 1):**
- SSRF guard: `client_ips` restricted to publicly routable IPs (`is_global`),
  cap 25, rejects echoed in the 202 response
- `run_scan` acquires the scan semaphore with `SCAN_QUEUE_TIMEOUT_S` (900s
  default) — hung scans fail visibly (DB + SSE error) instead of queueing forever
- SSE progress-queue TTL sweep (2h); stale "pending" scans expire to failed on
  poll (`STALE_PENDING_SCAN_S`, 45 min)
- `results["schema_version"] = "1.0"` (scanner.py, `RESULTS_SCHEMA_VERSION`)
- **Opt-in** API auth: `X-Api-Key` required only when `SCANNER_API_KEY` env set
  (currently UNSET → behaviour unchanged); in-house per-IP rate limiting live
  (30 scans/h, 120 light/h, env-tunable)
- Per-tier PDF cache in `download_pdf` (scans/_pdf_cache/, type whitelisted)

**SCN-031 — report integrity + maintainability (Phases 0,2,3,4,5,6-lite):**
- Single Rand-savings authority: `cat_remediation` shows RSI deltas only;
  `cat_risk_mitigations` is the one Rand view (back-test #16 closed)
- brand.json drives ALL identity strings in every tier + invoices (new keys:
  report_header_text, footer_fsp_text, doc_author, contact_text,
  disclaimer_fsp_sentence, invoice_*). CAUTION: file must stay BOM-free —
  loader silently falls back to defaults on parse error
- "Not assessed" muted cards for origin discovery / S-1 / third-party JS
- review-by markers on ALL curated intel tables; OVERDUE now FAILS the wiring
  gate (was warn-only). CMS signatures de-duplicated (module-level table in
  checkers_threats.py)
- **pdf_report.py split**: pdf_data (65) / pdf_helpers (433) / pdf_cards
  (3,926) / pdf_report (2,135 — orchestrator). Proven byte-identical by NEW
  `tooling/pdf_snapshot.py` guard (--save/--check; baseline JSON committed;
  6 fixture×tier hashes). RE-BASELINE (--save) after any deliberate render change
- **Pre-push hook** live: `core.hooksPath = security_scanner/tooling/hooks`;
  fast gates (wiring + dropdown + app-hardening) every push, + live smoke on
  master pushes. First real run passed on today's pushes. Bypass: --no-verify
- Smoke test now FAILS (not warns) on production-shape breaks: schema_version,
  `_overall_score == overall_risk_score` coupling, MC p50 > 0, risk_probability
- Archive sweep: 75 `_apply_*`/`_proto_*` → tooling/_archive/; v1 sensitivity
  chain, gen_gap_v9.cjs, _spec_workspace/, _sub_ind_js.txt → _archive/
- Docs: BACKTEST/RETEST status banners (all 17 bugs FIXED, code-verified);
  OUTSTANDING.md refreshed; gap analysis v10 regenerated with SCN-030/031 rows,
  FIN-9 marked Retired (2026-06-04), 4c marked Partial; OUTSTANDING.docx regen

## Gate suite (all green at ship)
wiring 28/28 · dropdown 410/410 · app-hardening 18/18 (NEW) ·
pdf snapshot 6/6 (NEW) · smoke PASS + shape OK

## Open items
- **Enable auth**: set `SCANNER_API_KEY` on Render AND add `X-Api-Key` header
  to Vercel frontend (frontend first, else 401s). Tracked in OUTSTANDING §1
- **vendor_breaches.json `marketo` row** exits 5-yr lookback ~2026-06-21 —
  refresh or prune (gate warns until then; will it FAIL? No — drift check is
  warn-only; review-by check is the failing one)
- **Deferred refactors** (separate change-sets): scoring_analytics.py split
  AFTER calibration sign-off (docs cite its line numbers); checkers_threats.py
  split second; pdf_cards.py / app.py CRM blueprint only if they grow
- Colleague-gated calibration items unchanged (p_breach base 0.3, curve shape,
  bands 200/400/600, warm annual loss ~3.5%)
