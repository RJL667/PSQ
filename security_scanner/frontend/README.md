# Phishield CyberRisk Dashboard (frontend)

React + Vite + TypeScript app that renders the **results dashboard** for the
security scanner. It is mounted *inside* the existing Flask app — not a separate
SPA — so every backend route, the PDF pipeline, and the SSE scan-progress stream
are untouched.

## How it's wired

- Flask serves `templates/results.html`, a thin shell that injects
  `window.RESULTS` / `window.SCAN_META` / `window.CHECKER_MANIFEST` (the same
  server-side data contract the legacy template used) and loads
  `/static/dashboard/app.{js,css}`.
- `vite build` outputs to `../static/dashboard/`, which Flask serves from its
  default `/static` handler. No new routes, no API contract change.
- The React app reads `window.RESULTS` through the selector layer
  (`src/data/`) — components never touch the raw payload directly.

## Develop

```bash
npm install
npm run dev        # http://localhost:5174  (uses src/dev/sampleResults.json)
npm run typecheck
```

`src/dev/sampleResults.json` is a **dev-only** fixture: a real captured
phishield.com scan enriched with the newer backend blocks
(`_scan_completeness`, `compliance`, `peer_benchmarking`) in their exact
documented shapes, so the coverage banner / compliance matrix / peer empty-state
can be developed without a live scan. It never ships to production.

## Build & deploy

```bash
npm run build      # writes ../static/dashboard/{app.js,app.css,assets/*}
```

**The build output in `../static/dashboard/` is committed to the repo.** The
Render service is pure-Python (no Node toolchain in the deploy), so committing
the bundle keeps the deploy unchanged. After any frontend change: run
`npm run build` and commit the regenerated `static/dashboard/` alongside the
source.

## Structure

```
src/
  data/         selectors, checker-state normalisation, formatters (the data layer)
  types/        RESULTS payload types + CheckerState union
  components/
    primitives/ Panel, Status badges, EmptyState  (shared surface only)
    shell/      AppShell, Sidebar, CommandBar, CategoryTabs, Footer, StatusScreen
    overview/   the executive strip + every analytical panel
    drawer/     EvidenceDrawer (right-side drill-down)
  pages/        OverviewPage, CategoryDetailPage
```
