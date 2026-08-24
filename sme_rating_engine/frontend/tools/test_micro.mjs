/**
 * Cases for Micro SME eligibility (checkMicroSME).
 *
 * Owner decision 2026-08-24: Micro SME is a DISCOUNT — bands 0-2 are all charged
 * at the bottom bracket, plus a further cut beneath it — and it assumes revenue
 * proxies the size of the business. For most of Finance that fails: they declare
 * fee income, not the value they handle, so a modest revenue does not mean a
 * small business. Only Real Estate and Holding And Other Investment Offices keep
 * the discount (the latter PROVISIONALLY, pending further debate).
 *
 * Software and Technology deliberately REMAINS eligible — flagged for possible
 * removal, not yet decided. The case below pins that so it cannot drift silently.
 *
 *   node tools/test_micro.mjs
 */
import { pathToFileURL, fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const E = await import(pathToFileURL(resolve(__dirname, '..', 'src', 'rating-engine.js')).href);
const D = await import(pathToFileURL(resolve(__dirname, '..', 'src', 'rating-data.js')).href);

const idx = (sub) => D.INDUSTRIES.findIndex((x) => x.sub === sub);

const EXPECT = [
  // [sub-industry, band, micro-eligible?, why]
  ['Real Estate', 0, true,  'sole full finance exception — commission tracks agency size'],
  ['Real Estate', 1, true,  'Real Estate keeps micro across bands 0-2'],
  ['Real Estate', 2, true,  'Real Estate keeps micro across bands 0-2'],

  ['Insurance Agents, Brokers, And Service', 0, true,  'START-UP GRACE: micro in band 0 only'],
  ['Insurance Agents, Brokers, And Service', 1, false, 'grace ends above R10M'],
  ['Insurance Agents, Brokers, And Service', 2, false, 'grace ends above R10M'],

  ['Software and Technology', 0, true,  'START-UP GRACE: micro in band 0 only'],
  ['Software and Technology', 1, false, 'grace ends above R10M'],
  ['Software and Technology', 2, false, 'grace ends above R10M'],

  ['Holding And Other Investment Offices', 0, true,  'START-UP GRACE: a genuinely tiny passive holdco is a real case'],
  ['Holding And Other Investment Offices', 1, false, 'grace ends above R10M — the bucket is mostly fees-on-assets'],
  ['Holding And Other Investment Offices', 2, false, 'grace ends above R10M'],

  ['Depository Institutions', 0, false, 'fee income understates the business'],
  ['Non-depository Credit Institutions', 0, false, 'fee income understates the business'],
  ['Security And Commodity Brokers, Dealers, Exchanges, And Services', 0, false, 'fee income understates the business'],
  ['Insurance Carriers', 0, false, 'fee income understates the business'],

  ['eCommerce', 0, true, 'control: ordinary industry keeps micro'],
  ['eCommerce', 2, true, 'control: ordinary industry keeps micro across bands 0-2'],
];

let failed = 0;
for (const [sub, band, expected, why] of EXPECT) {
  const i = idx(sub);
  if (i < 0) { failed++; console.error(`  x sub-industry not found: ${sub}`); continue; }
  const got = E.checkMicroSME(i, band, 1);   // cover R2.5M — inside the cover window
  if (got !== expected) {
    failed++;
    console.error(`  x ${sub} band ${band}: micro=${got}, expected ${expected}  (${why})`);
  }
}

// The two axis limits must still hold for an eligible industry.
const re = idx('Real Estate');
const axis = [
  [E.checkMicroSME(re, 3, 2), false, 'band 3 (R50M-R75M) is outside the micro window'],
  [E.checkMicroSME(re, 2, 3), false, 'cover R7.5M is outside the micro window'],
  [E.checkMicroSME(re, 0, 0), true,  'band 0 + R1M cover is inside'],
];
for (const [got, expected, why] of axis) {
  if (got !== expected) { failed++; console.error(`  x axis check: got ${got}, expected ${expected} (${why})`); }
}

// An excluded finance industry must actually price higher, not just flip a flag.
const dep = idx('Depository Institutions');
const st = { revenueBandIndex: 2, industryIndex: dep, actualTurnover: 40e6, uwLoadingPct: 0,
  fpSelections: {}, postureDiscount: 0, discretionaryDiscount: 0 };
const calc = E.calculatePremium(2, st, {});
if (calc.isMicro !== false) { failed++; console.error('  x Depository Institutions still returns isMicro=true'); }
if (!(calc.annual > 13266)) { failed++; console.error(`  x expected a higher premium than the old micro R13 266, got R${calc.annual}`); }

console.log(`micro eligibility: ${EXPECT.length} industry/band cases + ${axis.length} axis checks + premium effect`);
if (failed === 0) { console.log('MICRO TESTS OK'); process.exit(0); }
console.error(`MICRO TESTS FAILED — ${failed}.`);
process.exit(1);
