#!/usr/bin/env node
// price_quote.mjs - one call from a structured quote record to every requested option, priced.
//
// Usage:  node price_quote.mjs record.json [record2.json ...]   (or "-" for stdin)
//         node price_quote.mjs --table record.json              (compact table instead of JSON)
//         import { priceQuote } from "./price_quote.mjs"
//
// Runs the workspace engines locally (Corporate Rating Engine/corporate-engine.js and
// sme_rating_engine/frontend/src/rating-engine.js). Writes nothing, posts nothing.
//
// Rules encoded (casebook/underwriting_nuances.md, skills on hybrid pricing and the instruction email):
//  - Turnover >= R250M: corporate rater on actual turnover.
//  - Turnover < R250M (corporate product): hybrid = C36 at R250M x (FP-matched SME premium on ACTUAL turnover / SME premium at R250M), plus the mandatory
//    sanity check (SME on actual turnover with matching FP and micro exclusion, SME +15%, SME +20%, hybrid,
//    straight run). New quote: hybrid, comparison shown. SME-to-corporate conversion of our own SME policy
//   (current_premium set): hybrid if it is +15-20% over the current premium, else SME +20% with matching benefits.
//   Every route is a suggestion; the underwriter's instructed rate is final.
//  - SME +20% issued on the corporate wording is a corporate quote (product stays "corporate").
//  - Posture: corporate maturity override band; SME posture discount mirrors the band (Strong = 15%).
//  - Group quotes: SME base loaded with the sub-industry risk factor (= corporate industryFac, workbook
//    'Look Up Tables_2026' col S) instead of the average modifier; unrounded (group-quote precedent, Oct 2026).
//  - Records loading: only Third Party Claims and Data Restoration, 1 + log10(declared / typical),
//    carried onto SME +20% as a corporate-formula ratio (records-loading precedent, Oct 2026).
//  - Public administration: Sophos MDR condition, discount capped at 15%, no-MDR fallback priced too;
//    excess at least 2% of the limit.
//  - CBI = 50% of BI unless excluded (no price effect). Funds Protect unauthorised = 2 x authorised.
//  - Outputs incl. RM, excl. RM (/1.06) and monthly excl. RM, plus the rule that chose the route and flags.
import { createRequire } from "module";
import path from "path";
import fs from "fs";
import { fileURLToPath, pathToFileURL } from "url";

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(here, "../../..");
const require = createRequire(import.meta.url);
const CD = require(path.join(ROOT, "Corporate Rating Engine", "corporate-data.js"));
globalThis.CORP_DATA = CD;
const E = require(path.join(ROOT, "Corporate Rating Engine", "corporate-engine.js"));
const S = await import(pathToFileURL(path.join(ROOT, "sme_rating_engine/frontend/src/rating-engine.js")).href);
const SD = await import(pathToFileURL(path.join(ROOT, "sme_rating_engine/frontend/src/rating-data.js")).href);

export const FLOOR = 250e6, RM = 1.06, SME_TURNOVER_CAP = 200e6, SME_MAX_COVER = 15e6, SME_FP_MAX = 5e6,
  MICRO_MAX = 5e6, PA_MDR_CAP = 0.15, PA_MIN_EXCESS_PCT = 0.02;

// Workbook 'Standard Premium Tables' (risk-rated SME product specification), annual, VAT incl., RM incl.,
// standard FP incl. Bands 1-8 (band 8 = R200M-R250M is not in the SME rater), limits R1M..R50M.
const TBL_COLS = [1e6, 2.5e6, 5e6, 7.5e6, 10e6, 15e6, 25e6, 50e6];
const TBL_STD_FP = [2100, 2616, 3144, 4800, 9108, 15756, 15756, 15756]; // 25M/50M: assumed R1.5M (records-loading precedent, Oct 2026)
const TBL_MAX = [10e6, 25e6, 50e6, 75e6, 100e6, 150e6, 200e6, 250e6];
const TBL = [
  [7872, 9060, 11160, 15816, 20184, 27816, 30972, 42708],
  [9612, 11268, 14148, 19428, 23988, 31788, 35340, 49296],
  [11340, 13464, 17124, 23028, 27792, 35760, 39696, 55872],
  [14040, 17172, 24072, 30228, 35436, 41928, 52524, 68184],
  [16488, 22440, 28332, 33660, 39480, 47832, 59124, 77208],
  [18804, 24144, 30300, 37476, 43248, 52824, 66204, 84264],
  [22608, 28116, 33396, 41112, 46644, 58524, 72552, 94608],
  [25716, 31596, 37368, 45444, 52092, 65028, 86748, 125064],
];

const r2 = (x) => (x == null || !isFinite(x) ? x : Math.round(x * 100) / 100);
const lerp = (L, a, b, va, vb) => va + (vb - va) * (L - a) / (b - a);
const fmtM = (L) => "R" + (L / 1e6) + "M";
const isCrime = (n) => /computer crime/i.test(n);
const isPci = (n) => /^pci/i.test(n);
const LOADED = CD.BENEFITS.filter((b) => /third party/i.test(b.name) || /data restoration/i.test(b.name)).map((b) => b.name);
const NO_MDR = CD.MDR_OPTIONS.find((m) => m.discount === 0).label;

// ---------- industry resolution ----------
const norm = (s) => String(s).toLowerCase().replace(/&/g, " and ").replace(/\bmisc\b\.?/g, "miscellaneous")
  .replace(/[^a-z0-9]+/g, " ").trim();
const ALIAS = { "healthcare": "health services", "it s public admin": "", "software technology": "software and technology" };
export function resolveSub(name, main) {
  if (!name) return null;
  const exact = CD.INDUSTRIES.find((i) => i.sub === name);
  if (exact) return exact.sub;
  const n = ALIAS[norm(name)] ?? norm(name);
  if (!n) return null;
  const tail = (i) => norm(i.sub.split(" - ").slice(1).join(" "));
  let c = CD.INDUSTRIES.filter((i) => tail(i) === n);
  if (!c.length) c = CD.INDUSTRIES.filter((i) => tail(i).startsWith(n) || norm(i.sub).includes(n));
  if (c.length > 1 && main) {
    const m = norm(main).split(" ")[0];
    const f = c.filter((i) => norm(i.main).startsWith(m));
    if (f.length) c = f;
  }
  return c.length ? c[0].sub : null;
}

// ---------- per-limit values: number | {pct} | {"<limit>": value} ----------
function pick(v, L, dflt) {
  if (v == null) return dflt;
  if (typeof v === "number") return v;
  if (v.pct != null) return v.pct * L;
  if (v[String(L)] != null) return v[String(L)];
  return dflt;
}

function withLoad(load, fn) {
  if (!load || load === 1) return fn();
  const saved = LOADED.map((n) => CD.BENEFITS.find((b) => b.name === n).contribution);
  LOADED.forEach((n, k) => { CD.BENEFITS.find((b) => b.name === n).contribution = saved[k] * load; });
  try { return fn(); } finally { LOADED.forEach((n, k) => { CD.BENEFITS.find((b) => b.name === n).contribution = saved[k]; }); }
}

function mdrLabel(m) {
  if (m == null || m === 0) return NO_MDR;
  if (typeof m === "number") {
    const o = CD.MDR_OPTIONS.find((x) => Math.abs(x.discount - m) < 1e-9);
    if (!o) throw new Error("No MDR tier with discount " + m);
    return o.label;
  }
  return m;
}

// ---------- context ----------
function buildCtx(rec) {
  const flags = [];
  const sub = resolveSub(rec.sub_industry, rec.main_industry);
  if (!sub) throw new Error("Unknown sub-industry: " + rec.sub_industry);
  const ind = CD.INDUSTRIES.find((i) => i.sub === sub);
  const posture = rec.posture || "Moderate";
  if (!rec.posture) flags.push("Posture not given: rated Average (Moderate) per the uncalibrated-posture rule.");
  const band = CD.MATURITY_BANDS.find((m) => m.label === posture);
  if (!band) throw new Error("Unknown posture band: " + posture);
  const smePosture = rec.sme_posture_discount ?? +(1 - band.multiplier).toFixed(6);
  if (band.multiplier > 1 && rec.sme_posture_discount == null)
    flags.push(`SME loading of ${Math.round((band.multiplier - 1) * 100)}% mirrors the corporate ${posture} band; no ruling yet on SME loadings.`);
  if (!Array.isArray(rec.limits) || !rec.limits.length) throw new Error("limits[] required");
  if (rec.excess == null) flags.push("Excess not given: 0.5% of limit used as the starting point; ask the client.");
  const pci = rec.pci == null ? true : !!rec.pci;
  if (rec.pci == null) flags.push("PCI not decided: priced with PCI; confirm whether card data is stored.");
  const fundsProtect = rec.funds_protect !== false;
  const excl = (rec.exclude_benefits || []).map((x) => x.toLowerCase());
  const sublim = rec.sublimits || {};
  const benefits = CD.BENEFITS.map((b) => {
    const key = Object.keys(sublim).find((k) => b.name.toLowerCase().includes(k.toLowerCase()));
    const included = isCrime(b.name) ? !fundsProtect : isPci(b.name) ? pci : !excl.some((x) => b.name.toLowerCase().includes(x));
    return { name: b.name, included, sublimitRatio: key ? sublim[key] : 1 };
  });
  const publicAdmin = ind.main === "Public Administration";
  let load = 1;
  if (rec.records && rec.records.declared > rec.records.typical) {
    const ratio = rec.records.declared / rec.records.typical;
    const method = rec.records.method || "log10";
    load = method === "log10" ? 1 + Math.log10(ratio) : method === "sqrt_cap3" ? Math.min(3, Math.sqrt(ratio)) : method === "sqrt" ? Math.sqrt(ratio) : +method;
    flags.push(`Records loading x${load.toFixed(3)} (${method}, ${ratio.toFixed(1)}x typical) on Third Party Claims and Data Restoration only; method pending a ruling.`);
  }
  const subTail = sub.split(" - ").slice(1).join(" - ");
  const smeIdx = SD.INDUSTRIES.findIndex((i) => i.sub.toLowerCase() === subTail.toLowerCase());
  const smeRefer = publicAdmin || /health/i.test(subTail) || (smeIdx >= 0 && SD.INDUSTRIES[smeIdx].referForUW);
  const ctx = {
    rec, flags, sub, ind, posture, smePosture, pci, fundsProtect, benefits, publicAdmin, load,
    turnover: rec.turnover, limits: rec.limits.map(Number),
    excessFor: (L) => pick(rec.excess, L, 0.005 * L),
    fpFor: (L) => pick(rec.fp_authorised, L, 0.1 * L),
    fpStandard: !!rec.fp_standard,
    mdrLabel: mdrLabel(rec.mdr ?? (publicAdmin ? PA_MDR_CAP : 0)),
    discretionary: rec.discretionary || 0,
    smeDiscretionary: rec.sme_discretionary ?? rec.discretionary ?? 0,
    smeUw: rec.sme_uw_loading || 0,
    aon: !!rec.aon, group: !!rec.group, rf: ind.industryFac,
    smeIdx, smeRefer,
    microExcluded: rec.limits.some((L) => L > MICRO_MAX),
    prec: rec.precedent || {},
  };
  if (rec.turnover == null || !(rec.turnover > 0)) throw new Error("turnover required");
  return ctx;
}

// ---------- corporate rater (interpolated on limit between rater covers, target's own excess and FP) ----------
function neighbours(L) {
  const C = CD.COVER_OPTIONS;
  if (C.includes(L)) return [L];
  const a = [...C].reverse().find((c) => c < L), b = C.find((c) => c > L);
  if (a == null || b == null) throw new Error(`${fmtM(L)} is outside the corporate cover options`);
  return [a, b];
}
function corp(ctx, turnover, L, over = {}) {
  const excess = over.excess ?? ctx.excessFor(L);
  const run = (cover) => withLoad(over.load ?? ctx.load, () => {
    const r = E.computePremium({ turnover, cover, subIndustry: ctx.sub, vat: 0.15, benefits: ctx.benefits, excess,
      fpAdjustableAmount: ctx.fpStandard ? 0 : ctx.fpFor(L), fundsProtect: ctx.fundsProtect,
      mdr: over.mdr ?? ctx.mdrLabel, maturityOverride: ctx.posture, discretionary: ctx.discretionary, riskBursary: ctx.aon });
    if (!r.ok) throw new Error(r.error);
    return r;
  });
  const ns = neighbours(L);
  if (ns.length === 1) { const r = run(L); return { final: r.finalPremium, r, interp: null }; }
  const [a, b] = ns, ra = run(a), rb = run(b);
  return { final: lerp(L, a, b, ra.finalPremium, rb.finalPremium), r: ra, interp: [a, b] };
}

// ---------- SME pieces ----------
function smeFpCost(fpA, L, flags) {
  const F = SD.FP_COSTS;
  const e = F.find((f) => f.limit === fpA);
  if (fpA > SME_FP_MAX) flags.push(`Funds Protect ${fpA.toLocaleString("en-ZA")} is above the SME maximum of R5M.`);
  if (e) return e.cost;
  let j = F.findIndex((f) => f.limit > fpA);
  if (j <= 0) j = j === 0 ? 1 : F.length - 1;
  flags.push(`SME Funds Protect cost for ${fpA.toLocaleString("en-ZA")} interpolated (not an SME tier).`);
  return lerp(fpA, F[j - 1].limit, F[j].limit, F[j - 1].cost, F[j].cost);
}
const tblBand = (t) => { const i = TBL_MAX.findIndex((m) => t <= m); if (i < 0) throw new Error("turnover above R250M has no SME band"); return i; };
function tblCol(arr, L) {
  const i = TBL_COLS.indexOf(L);
  if (i >= 0) return arr[i];
  const j = TBL_COLS.findIndex((c) => c > L);
  if (j <= 0) throw new Error(`${fmtM(L)} is outside the SME table limits (R1M-R50M)`);
  return lerp(L, TBL_COLS[j - 1], TBL_COLS[j], arr[j - 1], arr[j]);
}
const tableExFp = (b, L) => tblCol(TBL[b].map((v, i) => v - TBL_STD_FP[i]), L);

// SME price on ACTUAL turnover with the corporate quote's Funds Protect (authorised limit), micro exclusion applied.
function smeQuote(ctx, turnover, L) {
  const flags = [];
  const fpA = ctx.fpFor(L);
  const disc = (1 - ctx.smePosture) * (1 - ctx.smeDiscretionary);
  const ci = SD.COVER_LIMITS.findIndex((c) => c.value === L);
  const inRater = ci >= 0 && turnover <= SME_TURNOVER_CAP && !ctx.prec.sme_basis_table;
  const fpCost = smeFpCost(fpA, L, flags);
  if (ci >= 0 && fpA < SD.BASE_FP_BY_COVER[SD.COVER_LIMITS[ci].key])
    flags.push("Funds Protect is below the SME minimum for this limit.");
  let base, basis, bandIdx;
  if (inRater) {
    const key = SD.COVER_LIMITS[ci].key;
    bandIdx = S.findRevenueBand(turnover);
    const micro = !ctx.microExcluded && !ctx.group && S.checkMicroSME(ctx.smeIdx, bandIdx, ci);
    if (micro) {
      const fpIndex = S.fpIndexForLimit(key, fpA);
      const st = { revenueBandIndex: bandIdx, industryIndex: ctx.smeIdx, actualTurnover: turnover, uwLoadingPct: ctx.smeUw,
        postureDiscount: ctx.smePosture, discretionaryDiscount: ctx.smeDiscretionary, fpSelections: { [ci]: fpIndex } };
      const c = S.calculatePremium(ci, st, { fpIndex });
      return { total: c.annual, ex: c.annual / RM, basis: "SME rater, Micro table", micro: true, fpCost: c.fpCost, flags };
    }
    const F = SD.PREMIUM_FORMULAS[key];
    base = bandIdx === 0 ? SD.SME_PREMIUMS[0][ci] - SD.getBaseFPCost(key) : F.rateCoeffs[bandIdx - 1] * turnover + F.adjustments[bandIdx - 1];
    basis = `SME rater standard band ${bandIdx + 1}` + (ctx.microExcluded && bandIdx <= 2 && L <= MICRO_MAX ? " (micro excluded: request has a limit above R5M)" : "");
  } else {
    bandIdx = tblBand(turnover);
    base = tableExFp(bandIdx, L);
    basis = `workbook table band ${bandIdx + 1} (band top)` + (TBL_COLS.includes(L) ? "" : ", limit interpolated");
    if (!ctx.prec.sme_basis_table) flags.push(`SME rater does not cover ${turnover > SME_TURNOVER_CAP ? "turnover above R200M" : fmtM(L)}; workbook table used.`);
  }
  if (L > SME_MAX_COVER) flags.push(`${fmtM(L)} is above the SME maximum cover of R15M.`);
  if (turnover > SME_TURNOVER_CAP) flags.push("Turnover is above the SME cap of R200M.");
  const mod = ctx.group ? 1 + ctx.rf : S.getIndustryModifier(ctx.smeIdx, Math.min(bandIdx, 6));
  let total = (base * mod * (1 + ctx.smeUw) + fpCost) * disc;
  if (!ctx.group && !ctx.prec.sme_unrounded) total = Math.round(total);
  const ex = ctx.prec.sme_table_ex_rm ? total : total / RM;
  return { total, ex, basis: basis + (ctx.group ? `, group risk factor x${mod.toFixed(4)}` : mod !== 1 ? `, industry modifier x${mod}` : ""), micro: false, fpCost, base, mod, flags };
}

// SME premium on ACTUAL turnover, excl. the standard FP, average modifier, no posture or discounts:
// numerator of the hybrid ratio (underwriter 30.10.2026: actual premium, not the band only).
function smeActualExFp(ctx, T, L, flags) {
  const ci = SD.COVER_LIMITS.findIndex((c) => c.value === L);
  const rater = (t) => {
    const key = SD.COVER_LIMITS[ci].key, b = S.findRevenueBand(t), F = SD.PREMIUM_FORMULAS[key];
    return { base: b === 0 ? SD.SME_PREMIUMS[0][ci] - SD.getBaseFPCost(key) : F.rateCoeffs[b - 1] * t + F.adjustments[b - 1], band: b + 1 };
  };
  if (ci >= 0 && !ctx.prec.hybrid_ratio_band_top) {
    if (T <= SME_TURNOVER_CAP) { const r = rater(T); return { base: r.base, basis: `SME rater on actual turnover (band ${r.band})` }; }
    flags.push("Turnover above R200M: SME premium interpolated between the rater at R200M and the table at R250M.");
    return { base: lerp(T, SME_TURNOVER_CAP, FLOOR, rater(SME_TURNOVER_CAP).base, tableExFp(7, L)), basis: "interpolated R200M-R250M" };
  }
  if (!ctx.prec.hybrid_ratio_band_top) flags.push(`${fmtM(L)} is not an SME rater limit: hybrid ratio uses the workbook band-top table.`);
  return { base: tableExFp(tblBand(T), L), basis: "workbook band-top table" };
}

function hybridCalc(ctx, L) {
  const flags = [];
  const c36 = corp(ctx, FLOOR, L).final;
  const b = tblBand(ctx.turnover);
  const match = ctx.prec.hybrid_ratio_fp_match === false ? tblCol(TBL_STD_FP, L) : smeFpCost(ctx.fpFor(L), L, flags);
  const num = smeActualExFp(ctx, ctx.turnover, L, flags);
  let ratio = (num.base + match) / (tableExFp(7, L) + match);
  if (ctx.prec.hybrid_ratio_dp != null) ratio = +ratio.toFixed(ctx.prec.hybrid_ratio_dp);
  return { c36, ratio, band: b + 1, ratio_basis: num.basis, incl: c36 * ratio, ex: c36 * ratio / RM, flags };
}

// Corporate-formula ratio carried onto SME +20%: the requested excess and records loading against the
// reference basis SME +20% stands for (0.5% excess, no loading; records-loading precedent, Oct 2026).
function sme20Factor(ctx, turnover, L) {
  const refPct = ctx.prec.sme20_ref_excess_pct ?? 0.005;
  if (ctx.load === 1 && Math.abs(ctx.excessFor(L) - refPct * L) < 0.5) return 1;
  return corp(ctx, turnover, L).final / corp(ctx, turnover, L, { excess: refPct * L, load: 1 }).final;
}

// ---------- one option ----------
function priceOption(ctx, L, mdrOverride) {
  const c = mdrOverride != null ? { ...ctx, mdrLabel: mdrLabel(mdrOverride) } : ctx;
  const flags = [];
  const T = c.turnover, below = T < FLOOR;
  const straight = corp(c, T, L);
  if (straight.interp) flags.push(`${fmtM(L)} is not a rater limit: corporate figures interpolated between ${fmtM(straight.interp[0])} and ${fmtM(straight.interp[1])}.`);
  for (const w of [straight.r.warning, ...(straight.r.benefitWarnings || [])]) if (w && !/Public administration risk: put the Sophos/.test(w)) flags.push(w);
  let hybrid = null, sme = null, f = 1, sanity = null;
  const product = c.rec.product || "corporate";
  if (below || product === "sme") {
    try { sme = smeQuote(c, T, L); flags.push(...sme.flags); } catch (e) { flags.push("SME figure not available: " + e.message); }
  }
  if (below && product !== "sme") {
    hybrid = hybridCalc(c, L); flags.push(...hybrid.flags);
    if (sme) {
      f = sme20Factor(c, T, L);
      const s15 = sme.ex * 1.15 * f, s20 = sme.ex * 1.2 * f;
      sanity = { sme_ex_rm: r2(sme.ex), sme_basis: sme.basis, sme_plus15_ex_rm: r2(s15), sme_plus20_ex_rm: r2(s20),
        hybrid_ex_rm: r2(hybrid.ex), hybrid_pct_of_sme20: +(100 * hybrid.ex / s20).toFixed(1),
        straight_ex_rm_reference_only: r2(straight.final / RM), c36_at_floor: r2(hybrid.c36), band_ratio: +hybrid.ratio.toFixed(4),
        sme_band: hybrid.band, excess_records_factor: +f.toFixed(4) };
    }
  }
  // route
  let route, rule;
  const forced = c.rec.route && c.rec.route !== "auto" ? c.rec.route : null;
  if (product === "sme") { route = "sme"; rule = "SME product requested: SME rater"; if (c.smeRefer) flags.push("SME rater refers this industry for underwriting."); }
  else if (!below) { route = "corporate"; rule = "Turnover at or above R250M: corporate rater on actual turnover"; }
  else if (!sme) { route = "hybrid"; rule = "Below R250M, no SME figure available: hybrid (C36 at R250M x SME band ratio)"; }
  else if (c.smeRefer) { route = "hybrid"; rule = "Below R250M and the SME rater refers this industry: hybrid; underwriter to confirm"; }
  else {
    const cur = c.rec.current_premium;
    const conv = cur && cur.annual && (!cur.limit || cur.limit === L);
    if (conv) {
      const hyb = cur.basis === "ex_rm" ? sanity.hybrid_ex_rm : r2(hybrid.incl);
      const up = 100 * (hyb / cur.annual - 1);
      sanity.current_premium = cur.annual; sanity.hybrid_pct_over_current = +up.toFixed(1);
      const inBand = up >= 15 - 1e-6 && up <= 20 + 1e-6;
      route = inBand ? "hybrid" : "sme_plus_20";
      rule = `SME-to-corporate conversion below R250M: hybrid is ${up.toFixed(1)}% over the current premium, ` +
        (inBand ? "inside +15-20%, so the hybrid is suggested" : "outside +15-20%, so SME +20% with matching benefits is suggested") + " (underwriter decides)";
    } else {
      route = "hybrid";
      rule = `New quote below R250M: hybrid suggested (${sanity.hybrid_pct_of_sme20}% of SME +20%); comparison shown, underwriter decides`;
    }
  }
  const autoRoute = route;
  if (forced) { rule = `Route set on the record: ${forced} (auto rule would give ${autoRoute}: ${rule})`; route = forced; }
  // premium on the route
  let incl, ex, aonBursary = null;
  if (route === "corporate") { incl = straight.final; ex = incl / RM; if (below) flags.push("Straight corporate run below R250M: the rules say never quote it; set only by the record."); }
  else if (route === "hybrid") { if (!hybrid) hybrid = hybridCalc(c, L); incl = hybrid.incl; ex = hybrid.ex; }
  else if (route === "sme_plus_20") {
    if (!sme) sme = smeQuote(c, T, L);
    if (f === 1 && !sanity) f = sme20Factor(c, T, L);
    ex = sme.ex * 1.2 * f; incl = ex * RM;
    if (c.mdrLabel !== NO_MDR) flags.push("MDR discount is not applied on the SME +20% route.");
  } else if (route === "sme") { if (!sme) sme = smeQuote(c, T, L); incl = sme.total; ex = sme.total / RM; }
  else throw new Error("Unknown route " + route);
  if (c.aon && route === "corporate") { aonBursary = r2(straight.final * 0.8 * 0.1); ex = null; }
  if (c.publicAdmin && c.excessFor(L) < PA_MIN_EXCESS_PCT * L) flags.push("Public administration: excess is below 2% of the limit.");
  const fpA = c.fpFor(L);
  return {
    limit: L, route, rule, product: route === "sme" ? "sme" : "corporate",
    premium_incl_rm: r2(incl), premium_ex_rm: r2(ex), monthly_ex_rm: ex == null ? null : r2(ex / 12),
    monthly_ex_rm_ceil: ex == null ? null : Math.ceil(ex / 12),
    aon_bursary: aonBursary, aon_quoted_premium: aonBursary != null ? r2(straight.final) : undefined,
    mdr: c.mdrLabel === NO_MDR ? "No MDR" : c.mdrLabel, mdr_discount: straight.r.mdrDiscount,
    excess: c.excessFor(L), fp_authorised: fpA, fp_unauthorised: 2 * fpA,
    bi: L, cbi: c.rec.cbi === false ? "N/A" : L / 2, waiting_period_h: c.rec.waiting_period_h ?? 12,
    pci: c.pci ? L : "N/A", sanity, auto_route: autoRoute, flags: [...new Set(flags)],
  };
}

export function priceQuote(rec) {
  const t0 = performance.now();
  const ctx = buildCtx(rec);
  const options = [];
  for (const L of ctx.limits) {
    const o = priceOption(ctx, L);
    if (ctx.publicAdmin && o.route !== "sme" && o.mdr_discount > 0) {
      const fb = priceOption(ctx, L, 0);
      o.no_mdr_fallback = { premium_incl_rm: fb.premium_incl_rm, premium_ex_rm: fb.premium_ex_rm, monthly_ex_rm: fb.monthly_ex_rm };
    }
    options.push(o);
  }
  // One route per request (group-quote precedent, Oct 2026): when any below-floor option is outside SME +15-20%,
  // the whole request goes to SME +20%, so the broker never sees a mix of methods on one quote.
  const forcedReq = rec.route && rec.route !== "auto";
  if (!forcedReq && rec.route_per_option !== true && options.some((o) => o.route === "sme_plus_20")) {
    for (let k = 0; k < options.length; k++) {
      if (options[k].route !== "hybrid" || !options[k].sanity) continue;
      const c2 = { ...ctx, rec: { ...rec, route: "sme_plus_20" } };
      const o2 = priceOption(c2, options[k].limit);
      o2.rule = `Request-level route: another option on this request is outside SME +15-20%, so every option goes to SME +20% (this option alone: hybrid at ${options[k].sanity.hybrid_pct_of_sme20}% of SME +20%)`;
      o2.auto_route = "hybrid";
      options[k] = o2;
    }
  }
  const flags = [...ctx.flags];
  if (ctx.publicAdmin) flags.push("Public administration: Sophos MDR condition of cover, MDR discount capped at 15%, no-MDR price is the fallback; check turnover against the AFS and the CBI grant threshold.");
  if (ctx.group) flags.push(`Group quote: SME base loaded with the sub-industry risk factor ${ctx.rf.toFixed(4)}.`);
  const cur = rec.current_premium;
  if (cur && cur.annual) {
    for (const o of options) {
      if (cur.limit && cur.limit !== o.limit) continue;
      const mine = cur.basis === "ex_rm" ? o.premium_ex_rm : o.premium_incl_rm;
      flags.push(`Current premium: ${fmtM(o.limit)} is ${(100 * (mine / cur.annual - 1)).toFixed(1)}% vs R${cur.annual.toLocaleString("en-ZA")}. SME-to-corporate conversion: +15-20% is usually defensible (Funds Protect and broader benefits). Like-for-like SME renewal: price below it (softened market).`);
    }
  }
  return {
    id: rec.id || null, entity: rec.entity || null, turnover: ctx.turnover, sub_industry: ctx.sub, main_industry: ctx.ind.main,
    posture: ctx.posture, sme_posture_discount: ctx.smePosture, below_floor: ctx.turnover < FLOOR,
    micro_excluded: ctx.microExcluded, sme_refers: ctx.smeRefer, options, flags,
    basis_note: "Annual, VAT incl. Excl. RM = incl. RM / 1.06; quotes go out without the 6% RM fee.",
    ms: +(performance.now() - t0).toFixed(1),
  };
}

// ---------- CLI ----------
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2), table = args.includes("--table");
  const files = args.filter((a) => a !== "--table");
  const read = (f) => JSON.parse(f === "-" ? fs.readFileSync(0, "utf8") : fs.readFileSync(f, "utf8"));
  const recs = files.flatMap((f) => { const d = read(f); return Array.isArray(d) ? d : [d]; });
  const out = recs.map((r) => { try { return priceQuote(r); } catch (e) { return { id: r.id, error: e.message }; } });
  if (!table) console.log(JSON.stringify(out.length === 1 ? out[0] : out, null, 1));
  else for (const q of out) {
    if (q.error) { console.log(q.id, "ERROR", q.error); continue; }
    console.log(`\n${q.entity || q.id} | T/O R${q.turnover.toLocaleString("en-ZA")} | ${q.sub_industry} | ${q.posture}`);
    console.table(q.options.map((o) => ({ limit: fmtM(o.limit), route: o.route, incl_rm: o.premium_incl_rm, ex_rm: o.premium_ex_rm,
      pm_ex_rm: o.monthly_ex_rm, no_mdr_ex_rm: o.no_mdr_fallback?.premium_ex_rm, hyb_pct_sme20: o.sanity?.hybrid_pct_of_sme20 })));
    for (const f of q.flags) console.log("  flag:", f);
    for (const o of q.options) for (const f of o.flags) console.log(`  ${fmtM(o.limit)}:`, f);
  }
}
