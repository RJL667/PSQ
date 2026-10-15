# Corporate Rating Engine: session notes and the VM / Veilguard app plan

Written 2026-10-13. Collects the discussion points from the earlier sessions (June handoff, July
deployment chat, 12 October build session) and the options for putting all three tools behind a
Veilguard app. `HANDOFF.md` is the June note and its NEXT list is partly out of date; this file
supersedes it where they differ.

---

## 1. The three tools today

**Where each tool runs**

| Tool | Runs as | Public path | Data store |
|---|---|---|---|
| Security scanner | host service | `/scanner/` | its own Postgres database |
| SME rating engine | host service | `/smerating/` | its own Postgres database |
| Corporate rating engine | host service (authored 12 Oct) | `/corprating/` | SQLite on the host |

Hostnames, ports, service names and database names are kept in the private deployment docs, not in
this public repo.
Whether the corporate unit is live on the VM was **not re-checked this session**.

**Bridge that already exists.** `corp-rating-mcp` is an MCP server registered
as a *system* app in Veilguard's app catalog. It calls the engine over HTTP and
exposes `assess_proposal_form`, `questionnaire_schema`, `map_assessment`, `list_quotes`,
`get_quote` and `create_quote`. It forwards the conversation and user ids for audit and redaction.
There is no equivalent bridge yet for the scanner or the SME engine.

---

## 2. Decisions already made (do not re-litigate)

1. **Spreadsheet is the source of truth** for rates. Regenerate `corporate-data.js` with
   `tools/gen_corporate_data.py`, then rerun `node test-engine.js`. Expected final premium
   R457,460.93. Never fabricate financial figures.
2. **Two data lanes.** Real inputs go only to the internal scanner. Text that goes to Claude is
   redacted first, through the Veilguard pii-proxy (redact, Claude, rehydrate). The engine holds no
   Anthropic key and fails closed if redaction is unavailable. This replaced the June plan of a
   separate `REDACTION_URL` server plus an engine-held key.
3. **Never send raw page images to Claude vision.** Scanned forms are OCR'd inside the closed
   environment first. The engine already detects scanned pages per page and refuses to map a
   document with un-OCR'd pages.
4. **Output is both** a gap report attached to the quote and an auto-filled posture step.
5. **Public URL** is the `/corprating/` path, behind the same staff sign-in as `/scanner`, with
   `/health` left open for uptime probes.
6. **Packaging.** July chose "own container" in the compose stack. On 12 October this changed to a
   **host service**, matching the SME engine. The container is retired and the MCP bridge points
   at the host service.
7. **Claude billing.** Claude API (Console key, pay as you go) is separate from the Max
   subscription. The org sits under the insurer; billing on the consulting company's card.
8. **Nothing is committed, pushed or deployed** until the owner says so.

---

## 3. What was built on 12 October

- **Questionnaire evaluator** (`questionnaire.py`, `questionnaire_model.json`). Reads the broker's
  fillable proposal PDF, scores the answers exactly as the rating workbook does (posture, maturity
  band, premium modifier) and gates on the **conditions of cover**. The modifier only applies once
  every applicable condition is met. Otherwise it lists what failed or what to ask the broker.
- **MDR handling.** MDR tiers appear in the condition-of-cover wording. Sophos MDR tiers are
  recognised. MDR from other vendors is treated conservatively. Firewall answers can be inferred.
  The outage row was fixed.
- **Casebook** (`casebook.py`, `casebook.html/js`). Past deals become test cases. The rater's premium
  is compared with the real quote, and corrections are logged as mapping examples.
- **Tests** in `tests/` (questionnaire and casebook), plus a Dockerfile and a fuller `app.py`.

---

## 4. Open work on the engine (refreshed NEXT list)

| # | Item | State |
|---|---|---|
| 1 | Confirm the corporate host unit is live: the health route returns 200 and the MCP bridge reaches it | not verified this session |
| 2 | Live Claude mapping through the pii-proxy on a **sample** form, then a real one | path built, live run not recorded |
| 3 | OCR execution for scanned forms, inside the closed environment (redaction server or app-side `rapidocr-onnxruntime`) | detection done, execution open |
| 4 | Gap-report PDF in the "True View" layout (scorecard plus threat surface), attached to the quote | open |
| 5 | Wire the scanner: queue an external scan seeded from the form's domain, render the threat surface | client code exists, not wired |
| 6 | Replicate the ingestion and scan layer for the SME engine | open |
| 7 | Move corporate quotes from SQLite to Postgres, to match the other two tools | new, only if the app plan below needs it |
| 8 | Commit this folder to PSQ and decide which remote it lives on | waiting for owner |

---

## 5. How Veilguard handles apps (read from veilguard-stack)

Source: `veilguard/docs/agentic-platform/WORKSPACE_APPS_SPEC.md` and `services/corp-rating-mcp/`.

There are **two kinds** of app.

**System apps.** A system entry in the app catalog, pointing at an MCP server the
operator runs (for example `corp-rating-mcp`). They appear in the dashboard gallery and
their tools are available in chat. This is how the corporate bridge works today.

**Workspace apps (built by the agent).** Flow: `app_templates`, `app_scaffold`, edit, `app_test`,
`app_submit`, approve the review card, `offer_app_connect`. They run in a hidden per-owner **Apps
workspace** VM under a supervisor (`vg-appd`). The facts that matter for this plan:

- The app speaks **stdio** to `vg-appd`, which exposes it as MCP over HTTP. **No app binds its own
  port**, so a workspace app cannot serve a web UI such as the rating wizard.
- Egress is **default deny**. Only hosts declared in the manifest are reachable.
- The VM **cannot reach the host's internal ports** (the "hostwall"). That rules out direct access
  to the pii-proxy, the engine databases or the engines' internal ports.
- v1 dependencies are **the template lockfile only** (`mcp`, `httpx`, `pydantic`). PyMuPDF,
  openpyxl and the Flask stack cannot be installed in the app.
- The VM suspends after 30 minutes idle and hibernates after an hour. VM slots are capped at 8.
- Secrets are entered on the app's connect form and never reach the model.

---

## 6. Options for "all three tools on a VM, reached through a Veilguard app"

**Option A: Keep the engines on the host, one system-app bridge for all three (recommended).**
Extend `corp-rating-mcp` into a single bridge, for example `phishield-underwriting`, with tool groups
for the scanner (queue scan, get result), SME rating (rate, save, fetch) and corporate rating (the
existing tools). Each engine keeps writing to its own database. The dashboard shows one app; the
web UIs stay at `/scanner`, `/smerating` and `/corprating`.
- Works with what exists: pii-proxy reachable, databases unchanged, no hostwall problem.
- Least new code: the bridge pattern and catalog registration already exist.
- Cost: the engines remain host processes, not isolated in a VM.

**Option B: Engines on the host, bridge built as a workspace app in the Apps VM.**
Scaffold from `mcp-python-fastmcp@1` and call the engines through their public HTTPS URLs, with
the public engine host as the only egress host and a service token as the app's secret.
- Gives the review card, per-tool approval and the sandbox for the bridge itself.
- Needs a machine-to-machine token on each engine's API, because the Caddy staff sign-in is
  basic-auth for people.
- Traffic leaves and re-enters through the public edge. The first call after idle waits for the
  VM to wake.

**Option C: Engines themselves inside a VM.**
Not possible with the Apps workspace as built: no listening ports, template-only dependencies, and
no route to the host databases or pii-proxy. It would need either a new kind of "service VM" in
sandboxd, or a separate cloud VM with its own Postgres and its own route to the pii-proxy. That is a
platform project, not an app.

**Where the data lands in every option.** The bridge never writes to a database itself. It calls
each engine's API, and the engine writes to its own store: scanner and SME in their Postgres
databases, corporate quotes in SQLite (or Postgres, if item 7 is done).

---

## 7. Decision needed

Which option to build: **A** (fastest, uses the existing pattern), **B** (bridge in the sandbox,
needs service tokens on three APIs), or **C** (a new VM platform). Before building, confirm item 1
in section 4, because both A and B depend on the corporate unit being live on the host.
