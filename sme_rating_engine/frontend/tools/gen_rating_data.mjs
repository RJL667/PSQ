/**
 * gen_rating_data.mjs — generate src/rating-data.js (ESM) from the legacy
 * vanilla data layer `SME Rating Engine/sme-data.js`, WITHOUT hand-transcription.
 *
 * The legacy file is a classic <script> (top-level `const`/`function` in the
 * global scope). We produce an ESM module by prefixing each top-level
 * declaration with `export ` — nothing else is changed, so the values are
 * byte-for-byte identical. `tools/parity.mjs` then proves the generated
 * exports deep-equal the values the legacy file evaluates to.
 *
 * Re-run this whenever the legacy sme-data.js changes (before Render retirement,
 * the legacy file remains the single source of truth for the rating DATA).
 *
 *   node tools/gen_rating_data.mjs
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..', '..'); // sme_rating_engine/frontend/tools -> repo root
const SRC = resolve(REPO_ROOT, 'SME Rating Engine', 'sme-data.js');
const OUT = resolve(__dirname, '..', 'src', 'rating-data.js');

const legacy = readFileSync(SRC, 'utf8');

// DEAD legacy declarations that are deliberately NOT carried into the ESM
// module. Only for things the legacy itself never used — dropping them keeps
// them from being mistaken for live data. Everything else is copied verbatim,
// and parity.mjs still deep-equals every remaining export against the legacy,
// so an over-eager exclusion here fails the gate loudly.
//
// UNDERWRITING_QUESTIONS: never referenced by the legacy app either, and its
// wording is two renumberings out of date (Q1 as a single question, FP at Q7.x,
// prior cover at Q9). The live questionnaire wording is src/lib/uwQuestions.js.
const EXCLUDE = new Set(['UNDERWRITING_QUESTIONS']);

// Prefix `export ` on every TOP-LEVEL declaration (column 0). Continuation
// lines of multi-line arrays/objects are indented or are closing brackets, so
// they never match — only the declaration head does.
const DECL = /^(const|let|var|function)\s/;
const DECL_NAME = /^(?:const|let|var|function)\s+([A-Za-z0-9_$]+)/;

const outLines = [];
let skippingUntilClose = null;   // name of the excluded block being skipped
for (const line of legacy.split('\n')) {
  if (skippingUntilClose) {
    // Top-level declarations start at column 0, so the block's closing bracket
    // is the first line at column 0 that closes it.
    if (/^[)\]}];?\s*$/.test(line)) skippingUntilClose = null;
    continue;
  }
  if (DECL.test(line)) {
    const name = (line.match(DECL_NAME) || [])[1];
    if (name && EXCLUDE.has(name)) {
      skippingUntilClose = name;
      outLines.push(`// ${name} intentionally NOT exported — dead in the legacy app,`);
      outLines.push('// superseded by src/lib/uwQuestions.js. See tools/gen_rating_data.mjs.');
      continue;
    }
    outLines.push('export ' + line);
    continue;
  }
  outLines.push(line);
}
if (skippingUntilClose) {
  throw new Error(`gen_rating_data: never found the end of excluded block ${skippingUntilClose}`);
}
const transformed = outLines.join('\n');
for (const name of EXCLUDE) {
  if (new RegExp(`^export (?:const|let|var|function) ${name}\\b`, 'm').test(transformed)) {
    throw new Error(`gen_rating_data: ${name} was supposed to be excluded but still exported`);
  }
}

const banner = `/**
 * rating-data.js — GENERATED, DO NOT EDIT BY HAND.
 * Source of truth: ../../../SME Rating Engine/sme-data.js  (legacy vanilla app).
 * Regenerate:      node tools/gen_rating_data.mjs
 * Parity-locked:   node tools/parity.mjs  (deep-equals every export vs the legacy values).
 */
`;

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, banner + transformed, 'utf8');

const nExports = transformed.split('\n').filter((l) => l.startsWith('export ')).length;
console.log(`wrote ${OUT}`);
console.log(`  from ${SRC}`);
console.log(`  ${nExports} top-level exports`);
