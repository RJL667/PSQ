/**
 * Cases for the premium-comparison basis (src/lib/comparison.js).
 *
 * Regression this guards: renewals followed the Step 3 "does the competitor
 * quote include a FP equivalent?" toggle, which defaults to No. A renewal has no
 * competitor — the benchmark is the client's own expiring Phishield policy,
 * which always includes Funds Protect — so every renewal compared a new premium
 * EX-FP against a with-FP existing premium. 15 live renewals were affected,
 * swings of 19-44 points, several reporting a saving where the premium had
 * actually risen.
 *
 *   node tools/test_comparison.mjs
 */
import { pathToFileURL, fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const C = await import(pathToFileURL(resolve(__dirname, '..', 'src', 'lib', 'comparison.js')).href);

// Consort Technical Underwriters, CPB-20260819-1428 — the quote that exposed it.
const calc = { annual: 62737, annualExFP: 46981, fpCost: 15756 };
const EXISTING = 57096;

const CASES = [
  // [state, expected basis, expected compare amount, why]
  [{ quoteType: 'renewal', competitorHasFP: false }, 'with FP', 62737,
   'RENEWAL: existing Phishield policy always includes FP, toggle must be ignored'],
  [{ quoteType: 'renewal', competitorHasFP: true }, 'with FP', 62737,
   'RENEWAL: same answer whichever way the toggle sits'],
  [{ quoteType: 'new', competitorHasFP: false }, 'ex-FP', 46981,
   'NEW BUSINESS vs a competitor with no FP equivalent: strip FP so it is comparable'],
  [{ quoteType: 'new', competitorHasFP: true }, 'with FP', 62737,
   'NEW BUSINESS vs a competitor that does include an FP equivalent'],
  [{ quoteType: 'competing', competitorHasFP: false }, 'ex-FP', 46981,
   'COMPETING QUOTE follows the toggle, unchanged'],
];

let failed = 0;
for (const [state, basis, amount, why] of CASES) {
  const gotBasis = C.compareBasisLabel(state);
  const gotAmount = C.compareAmountFor(state, calc);
  if (gotBasis !== basis || gotAmount !== amount) {
    failed++;
    console.error(`  x ${state.quoteType}/competitorHasFP=${state.competitorHasFP}: got ${gotBasis} ${gotAmount}, expected ${basis} ${amount}`);
    console.error(`      ${why}`);
  }
}

// The headline number the broker reads must be the like-for-like one.
const renewalDelta = C.compareAmountFor({ quoteType: 'renewal' }, calc) - EXISTING;
const renewalPct = Math.round(renewalDelta / EXISTING * 100);
if (renewalPct !== 10) {
  failed++;
  console.error(`  x Consort renewal delta: got ${renewalPct}%, expected +10% (was reported as -18%)`);
}

console.log(`comparison basis: ${CASES.length} cases + the Consort renewal delta`);
if (failed === 0) { console.log('COMPARISON TESTS OK'); process.exit(0); }
console.error(`COMPARISON TESTS FAILED — ${failed}.`);
process.exit(1);
