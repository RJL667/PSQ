/**
 * Guard: the PDF audit annexure must ask the same questions the broker was asked.
 *
 * Step1Client.jsx renders the questionnaire from inline literals (that component
 * is byte-verified against the legacy UI, so we deliberately do not refactor it).
 * src/lib/uwQuestions.js carries the same wording for the Annexure A audit page.
 * Two copies can drift — and a drifted annexure would misstate the question a
 * client actually answered, which is exactly what an audit page must not do.
 *
 * This check parses the question labels out of Step1Client.jsx and asserts that,
 * for every answer key, the annexure's "<num> <text>" equals the form's label.
 *
 *   node tools/check_uw_question_sync.mjs
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(__dirname, '..', 'src');

const { UW_QUESTIONS_FLAT } = await import(pathToFileURL(resolve(SRC, 'lib', 'uwQuestions.js')).href);
const step1 = readFileSync(resolve(SRC, 'steps', 'Step1Client.jsx'), 'utf8');

// Rather than parse JSX structure (brittle — arrow functions, .map() templates),
// assert the invariant that actually matters: every question sentence printed on
// the annexure must appear VERBATIM in the Step 1 source, and every answer key
// the form collects must have an annexure entry.
let problems = 0;
for (const q of UW_QUESTIONS_FLAT) {
  if (!step1.includes(q.text)) {
    console.error(`  x ${q.key}: annexure wording not found verbatim on the Step 1 form`);
    console.error(`      annexure: ${q.text}`);
    problems++;
  }
}

// Every key the form binds an answer to (setAns('<key>', ...) or a ['<key>', …]
// tuple) must be represented on the annexure.
const formKeys = new Set();
for (const m of step1.matchAll(/\['(q[0-9a-z-]+)',\s*'/g)) formKeys.add(m[1]);
for (const m of step1.matchAll(/setAns\('(q[0-9a-z-]+)'/g)) formKeys.add(m[1]);
for (const key of formKeys) {
  if (!UW_QUESTIONS_FLAT.some((q) => q.key === key)) {
    console.error(`  x ${key}: collected by the Step 1 form but MISSING from the annexure`);
    problems++;
  }
}

console.log(`UW question sync: ${UW_QUESTIONS_FLAT.length} annexure questions vs ${formKeys.size} answer keys collected by the form`);
if (problems === 0) {
  console.log('UW QUESTION SYNC OK — the annexure asks exactly what the form asks.');
  process.exit(0);
}
console.error(`UW QUESTION SYNC FAILED — ${problems} problem(s).`);
process.exit(1);
