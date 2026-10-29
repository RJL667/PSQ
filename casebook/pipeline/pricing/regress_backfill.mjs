// Regression on back-filled historical quote options (casebook/tools/build_backfill.py -> backfill.jsonl).
// Each option with turnover + sub-industry is priced through price_quote.mjs:
//   1. "today" = the current rules with the email's stated inputs (Moderate, no MDR, stated excess / FP / PCI).
//   2. "search" = the inputs the underwriter set by hand and the email does not record (route, posture band,
//      MDR tier, excess rated R0 / R500k per the training rule), to find what reproduces the quoted figure.
// Veilguard-priced October options are excluded here (regress_october.mjs covers them).
// Run: node regress_backfill.mjs  -> regress_backfill.json + table
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { priceQuote, resolveSub, FLOOR } from "./price_quote.mjs";
const here = path.dirname(fileURLToPath(import.meta.url));
const recs = fs.readFileSync(path.join(here, "backfill.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));

const POSTURES = ["Very Strong", "Strong", "Moderate", "Weak", "Very Weak"];
const MDRS = [0, 0.1, 0.15, 0.2, 0.3];
const rows = [];
const t0 = performance.now();
let calls = 0;

function price(base, over) {
  calls++;
  try {
    const q = priceQuote({ ...base, ...over });
    return q.options[0];
  } catch (e) { return { error: e.message }; }
}

for (const r of recs) {
  if (r.source !== "backfill_email" || !r.turnover || !r.sub_industry || !r.cover || !r.quoted_premium) continue;
  const sub = resolveSub(r.sub_industry, r.main_industry);
  const row = { ref: r.quote_ref, company: (r.company_name || "").slice(0, 32), product: r.product, turnover: r.turnover,
    sub_email: r.sub_industry, sub_rated: sub, limit: r.cover, excess: r.excess, fp: r.fp_authorised, quoted: r.quoted_premium,
    variant: r.basis?.variant || "", status_email: r.status };
  if (!sub) { rows.push({ ...row, status: "no inputs", reason: "sub-industry in the email does not map to a rater industry" }); continue; }
  const end = (r.endorsements || []).join("\n");
  const pci = /PCI[^\n]*\bis\s+N\/A/i.test(end) ? false : /PCI[^\n]*\bis\s+R/i.test(end) ? true : false;
  const cbi = !/Contingent[^\n]*\bis\s+N\/A/i.test(end);
  const base = { id: r.quote_ref, turnover: r.turnover, sub_industry: sub, main_industry: r.main_industry, limits: [r.cover],
    excess: r.excess ?? undefined, fp_authorised: r.fp_authorised ?? undefined, pci, cbi, posture: "Moderate", mdr: 0,
    product: r.product === "sme" ? "sme" : "corporate" };
  // 1. today's rules, stated inputs
  const today = price(base, {});
  row.today_route = today.route; row.today_ex_rm = today.premium_ex_rm;
  row.today_pct = today.premium_ex_rm ? +(100 * (today.premium_ex_rm / r.quoted_premium - 1)).toFixed(2) : null;
  // 2. search the hand-set inputs
  const routes = r.product === "sme" ? ["sme"] : r.turnover < FLOOR ? ["corporate", "corporate@floor", "hybrid", "sme_plus_20"] : ["corporate"];
  const excesses = [...new Set([r.excess, 0, 500000].filter((x) => x != null && x <= r.cover / 2))];
  const hits = [];
  let best = null;
  for (const route of routes)
    for (const posture of POSTURES)
      for (const mdr of route.startsWith("corporate") || route === "hybrid" ? MDRS : [0])
        for (const excess of excesses)
          for (const p of [pci, !pci]) {
            const over = { posture, mdr, excess, pci: p, route: route === "corporate@floor" ? "corporate" : route,
              turnover: route === "corporate@floor" ? FLOOR : r.turnover };
            if (r.main_industry && /public admin/i.test(r.main_industry) && mdr > 0.15) continue;
            const o = price(base, over);
            if (o.error || o.premium_ex_rm == null) continue;
            const d = o.premium_ex_rm - r.quoted_premium;
            const cand = { route, posture, mdr, excess, pci: p, got: o.premium_ex_rm, diff: +d.toFixed(2), pct: +(100 * d / r.quoted_premium).toFixed(3),
              pciChanged: p !== pci, excessChanged: excess !== r.excess };
            if (Math.abs(d) <= 0.01) hits.push(cand);
            const score = Math.abs(d) + (cand.pciChanged ? 1e-6 : 0) + (cand.excessChanged ? 1e-6 : 0);
            if (!best || score < best.score) best = { ...cand, score };
          }
  // prefer an exact hit that keeps the email's PCI and excess, then the fewest changes
  hits.sort((a, b) => (a.pciChanged + a.excessChanged + (a.mdr > 0)) - (b.pciChanged + b.excessChanged + (b.mdr > 0)));
  const pickd = hits[0] || best;
  row.n_exact_fits = hits.length;
  if (pickd) Object.assign(row, { fit_route: pickd.route, fit_posture: pickd.posture, fit_mdr: pickd.mdr, fit_excess: pickd.excess,
    fit_pci: pickd.pci, fit_ex_rm: pickd.got, fit_diff: pickd.diff, fit_pct: pickd.pct });
  row.status = hits.length ? "exact" : pickd && Math.abs(pickd.pct) < 0.5 ? "near" : "not reproduced";
  rows.push(row);
}
const ms = +(performance.now() - t0).toFixed(0);
const tally = rows.reduce((a, r) => ((a[r.status] = (a[r.status] || 0) + 1), a), {});
console.table(rows.map(({ ref, company, limit, quoted, today_route, today_pct, status, n_exact_fits, fit_route, fit_posture, fit_mdr, fit_excess, fit_pci, fit_pct }) =>
  ({ ref: ref.slice(3), company: company.slice(0, 22), lim: limit / 1e6, quoted, today_route, today_pct, status, fits: n_exact_fits,
     route: fit_route, posture: fit_posture, mdr: fit_mdr, exc: fit_excess, pci: fit_pci, pct: fit_pct })));
console.log("tally", tally, "options", rows.length, "pricer calls", calls, "ms", ms, "ms/call", (ms / calls).toFixed(2));
fs.writeFileSync(path.join(here, "regress_backfill.json"), JSON.stringify({ rows, tally, calls, ms }, null, 1));
