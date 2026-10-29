// Regression: reproduce every October Veilguard-priced quote option through the one-call pricer.
// Run: node regress_october.mjs  -> prints a table and writes regress_october.json
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { priceQuote } from "./price_quote.mjs";
const here = path.dirname(fileURLToPath(import.meta.url));
const recs = JSON.parse(fs.readFileSync(path.join(here, "october_set.json"), "utf8"));
const rows = [];
const t0 = performance.now();
for (const rec of recs) {
  const q = priceQuote(rec);
  for (const o of q.options) {
    const checks = [["quoted", rec.expect?.[String(o.limit)], o.premium_ex_rm]];
    if (rec.expect_no_mdr) checks.push(["no-MDR fallback", rec.expect_no_mdr[String(o.limit)], o.no_mdr_fallback?.premium_ex_rm]);
    for (const [what, want, got] of checks) {
      if (want == null) continue;
      const d = got - want, pct = 100 * d / want;
      const status = Math.abs(d) <= 0.01 ? "exact" : Math.abs(pct) < 0.5 ? "near" : "not reproduced";
      rows.push({ id: rec.id, limit: o.limit / 1e6 + "M", what, route: o.route, auto_route: o.auto_route,
        want, got, diff: +d.toFixed(2), pct: +pct.toFixed(4), status, ms: q.ms });
    }
  }
}
const ms = +(performance.now() - t0).toFixed(1);
console.table(rows);
const tally = rows.reduce((a, r) => ((a[r.status] = (a[r.status] || 0) + 1), a), {});
console.log("tally", tally, "total ms", ms);
fs.writeFileSync(path.join(here, "regress_october.json"), JSON.stringify({ rows, tally, ms }, null, 1));
