/**
 * Cases for parseCurrency / sanitizeCurrencyInput.
 *
 * The regression that prompted these: a currency field stripped every non-digit
 * on each keystroke, so "57 096.00" was stored as 5709600 and a live renewal
 * quote compared against a premium 100x too large. Any change to the currency
 * helpers must keep every row below passing.
 *
 *   node tools/test_format.mjs
 */
import { pathToFileURL } from 'node:url';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const { parseCurrency, sanitizeCurrencyInput } =
  await import(pathToFileURL(resolve(__dirname, '..', 'src', 'lib', 'format.js')).href);

const CASES = [
  // [input, expected, why]
  ['57096',          57096,   'plain digits'],
  ['57096.00',       57096,   'THE BUG: decimal cents must not become 5709600'],
  ['57 096.00',      57096,   'en-ZA spaces + cents'],
  ['R57,096.00',     57096,   'currency symbol + thousands comma + decimal dot'],
  ['R57 096',        57096,   'symbol + space grouping'],
  ['57,096',         57096,   'comma as THOUSANDS (3 digits follow)'],
  ['57.096',         57096,   'dot as THOUSANDS (3 digits follow)'],
  ['1,234,567',      1234567, 'repeated comma = thousands'],
  ['1 234 567',      1234567, 'spaces = thousands'],
  ['57 096,50',      57096.5, 'en-ZA comma decimal'],
  ['57096.50',       57096.5, 'dot decimal with cents'],
  ['57096.5',        57096.5, 'single decimal digit'],
  ['57096.99',       57096.99, 'two decimal places (accounting standard) preserved by the parser'],
  ['0.00',           0,       'zero with cents'],
  ['57096.',         57096,   'trailing separator mid-typing must not explode'],
  ['.50',            0.5,     'leading decimal'],
  ['57096.00.00',    57096,   'junk tolerance: repeated dots are not a valid amount'],
  ['57,096.00.00',   57096,   'mixed separators then a repeated decimal'],
  ['1.234.567,89',   1234567.89, 'European style'],
  ['1,234,567.89',   1234567.89, 'US/UK style'],
  ['',               0,       'empty'],
  [null,             0,       'null'],
  [undefined,        0,       'undefined'],
  ['abc',            0,       'no digits'],
  ['R',              0,       'symbol only'],
  [57096,            57096,   'already a number'],
  [57096.5,          57096.5, 'already a float'],
  [0,                0,       'zero'],
];

let failed = 0;
for (const [input, expected, why] of CASES) {
  const got = parseCurrency(input);
  const ok = Math.abs(got - expected) < 0.005;
  if (!ok) {
    failed++;
    console.error(`  x parseCurrency(${JSON.stringify(input)}) = ${got}, expected ${expected}  (${why})`);
  }
}

// The keystroke cleaner must preserve separators so typing is not fought.
const SANITIZE = [
  ['57096.00',  '57096.00'],
  ['R57 096',   '57096'],
  ['57096.',    '57096.'],     // mid-typing
  ['57,096.00', '57,096.00'],
  ['abc12x3',   '123'],
];
for (const [input, expected] of SANITIZE) {
  const got = sanitizeCurrencyInput(input);
  if (got !== expected) {
    failed++;
    console.error(`  x sanitizeCurrencyInput(${JSON.stringify(input)}) = ${JSON.stringify(got)}, expected ${JSON.stringify(expected)}`);
  }
}

console.log(`currency helpers: ${CASES.length} parse cases + ${SANITIZE.length} sanitize cases`);
if (failed === 0) { console.log('FORMAT TESTS OK'); process.exit(0); }
console.error(`FORMAT TESTS FAILED — ${failed} case(s).`);
process.exit(1);
