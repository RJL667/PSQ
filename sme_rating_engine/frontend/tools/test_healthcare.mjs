/**
 * Healthcare on SME (owner decision 2026-10-30).
 *
 * Healthcare below R15M turnover is rated on SME through the normal SME path:
 * Micro rates at R1M-R5M cover, the standard band calculator above that. On top
 * of whichever path applies: +20% data-subject loading on the full premium incl.
 * Funds Protect, and a sensitive-records loading (1 + log10(declared / expected)
 * on the Third Party Claims + Data Restoration share) when declared records
 * exceed the expected average. R15M turnover or more stays referred.
 *
 *   node tools/test_healthcare.mjs
 */
import { pathToFileURL, fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const E = await import(pathToFileURL(resolve(__dirname, '..', 'src', 'rating-engine.js')).href);
const D = await import(pathToFileURL(resolve(__dirname, '..', 'src', 'rating-data.js')).href);

let failed = 0;
const check = (cond, msg) => { if (!cond) { failed++; console.error('  x ' + msg); } };

const hc = D.INDUSTRIES.findIndex((i) => i.sub === 'Healthcare Services');
const ci5 = D.COVER_LIMITS.findIndex((c) => c.value === 5_000_000);
const ci75 = D.COVER_LIMITS.findIndex((c) => c.value === 7_500_000);
const key5 = D.COVER_LIMITS[ci5].key;
const st = (to, records) => ({ revenueBandIndex: E.findRevenueBand(to), industryIndex: hc, actualTurnover: to,
  uwLoadingPct: 0, fpSelections: {}, postureDiscount: 0, discretionaryDiscount: 0, sensitiveRecords: records });

// Eligibility
check(E.healthcareSmeStatus(hc, 9e6).eligible === true, 'R9M healthcare should be SME-eligible');
check(E.healthcareSmeStatus(hc, 14e6).eligible === true, 'R14M healthcare should be SME-eligible');
check(E.healthcareSmeStatus(hc, 15e6).eligible === false, 'R15M healthcare should be referred');
check(E.healthcareSmeStatus(D.INDUSTRIES.findIndex((i) => i.sub === 'eCommerce'), 9e6) === null, 'non-healthcare has no status');

// Micro still applies at R1M-R5M cover for every healthcare band below R15M
for (const b of [0, 1]) check(E.checkMicroSME(hc, b, 1) === true, `healthcare band ${b} should keep Micro at R2.5M cover`);

// Reference: R14M, R5M cover, FP R2M, no records loading -> Micro base + FP, +20% = R41,458 incl. RM
const fp = E.fpIndexForLimit(key5, 2_000_000);
const base = E.calculatePremium(ci5, st(14e6, 0), { fpIndex: fp });
check(base.isMicro === true, 'reference case must use the Micro table');
check(base.annual === 41458, `reference annual expected 41458, got ${base.annual}`);
check(base.breakdown.some((b) => /data-subject loading \(\+20%/.test(b.desc)), 'breakdown must disclose the +20% loading');
check(base.healthcare === true && base.recordsLoading === 1, 'no records loading at 0 records');

// Records loading on the Micro path: none at/below expected; above expected sub-linear and disclosed
const atExp = E.calculatePremium(ci5, st(14e6, E.HEALTHCARE_SME.expectedRecords), { fpIndex: fp });
check(atExp.annual === base.annual, 'records at expected must not load');
const big = E.calculatePremium(ci5, st(14e6, 1_000_000), { fpIndex: fp });
check(big.annual > base.annual, 'records above expected must load');
check(big.breakdown.some((b) => /Sensitive records loading/.test(b.desc)), 'breakdown must disclose the records loading');
check(big.recordsLoading > 1 && big.recordsLoading < 2, `records loading should be sub-linear, got ${big.recordsLoading}`);

// Above R5M cover: standard band calculator, same loadings
if (ci75 >= 0) {
  const std = E.calculatePremium(ci75, st(14e6, 1_000_000), {});
  check(std.isMicro === false, 'R7.5M cover must use the standard band calculator');
  check(std.breakdown.some((b) => /data-subject loading/.test(b.desc)) && std.breakdown.some((b) => /Sensitive records loading/.test(b.desc)),
    'standard path must carry both healthcare loadings');
}

// Non-healthcare unchanged by the records field
const ec = D.INDUSTRIES.findIndex((i) => i.sub === 'eCommerce');
const a = E.calculatePremium(ci5, { ...st(14e6, 0), industryIndex: ec }, { fpIndex: fp });
const b2 = E.calculatePremium(ci5, { ...st(14e6, 1_000_000), industryIndex: ec }, { fpIndex: fp });
check(a.annual === b2.annual && a.healthcare === undefined, 'records field must not affect non-healthcare');

console.log('healthcare SME: eligibility, Micro kept, reference premium, records loading, standard path, non-healthcare isolation');
if (failed === 0) { console.log('HEALTHCARE TESTS OK'); process.exit(0); }
console.error(`HEALTHCARE TESTS FAILED — ${failed}.`);
process.exit(1);
