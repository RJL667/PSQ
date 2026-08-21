// Currency parse/format.
//
// These fields take free text typed by a human working from a policy schedule,
// so they must cope with however the amount happens to be written: "57096",
// "57 096.00", "R57,096.00", "57 096,50". The rand amount they mean has to come
// out the same every time.
//
// History: the first React port stripped every non-digit on each keystroke,
// which silently deleted the decimal point — "57 096.00" became 5 709 600, a
// 100x error that reached a live renewal quote (CPB-20260819-1428). Hence the
// explicit separator handling below, and tools/test_format.mjs.

// Characters that could be part of a number. Everything else (R, spaces,
// letters, stray symbols) is noise and is dropped.
const NOISE = /[^\d.,]/g;

/**
 * Permissive cleaner for what a user is CURRENTLY typing. Deliberately keeps
 * separators — including a trailing one — so the field never fights someone
 * midway through entering "57096." + "00". Interpretation happens in
 * parseCurrency, not here.
 */
export function sanitizeCurrencyInput(raw) {
  return String(raw ?? '').replace(NOISE, '');
}

/** Are the groups after the first all exactly 3 digits? ("1,234,567") */
function looksLikeThousands(parts) {
  return parts.length > 1
    && parts[0].length >= 1 && parts[0].length <= 3
    && parts.slice(1).every((p) => p.length === 3);
}

/**
 * Interpret a typed amount as a number of rand.
 *
 * Which separator is the decimal one is decided as follows:
 *   - both "." and "," present  -> the LAST one is the decimal ("57,096.00")
 *   - one separator, used once  -> decimal, UNLESS exactly 3 digits follow it,
 *                                  which reads as a thousands group ("57,096")
 *   - one separator, repeated   -> thousands if every group is 3 digits
 *                                  ("1,234,567"), otherwise the FIRST is the
 *                                  decimal and the rest are typos ("57096.00.00")
 */
export function parseCurrency(str) {
  if (typeof str === 'number') return Number.isFinite(str) ? str : 0;
  if (!str) return 0;
  const s = String(str).replace(NOISE, '');
  if (!s) return 0;

  const lastDot = s.lastIndexOf('.');
  const lastComma = s.lastIndexOf(',');
  let decIdx = -1;

  if (lastDot !== -1 && lastComma !== -1) {
    // Whichever character appears last is the decimal one; the other groups
    // thousands. Take its FIRST occurrence so a repeated decimal ("57,096.00.00")
    // is read as a typo in the fraction rather than shifting the whole amount.
    const decChar = lastDot > lastComma ? '.' : ',';
    decIdx = s.indexOf(decChar);
  } else {
    const sep = lastDot !== -1 ? '.' : lastComma !== -1 ? ',' : null;
    if (sep) {
      const parts = s.split(sep);
      const count = parts.length - 1;
      if (count === 1) {
        // "57,096" reads as a thousands group; "57096.00" / "57096." do not.
        decIdx = parts[1].length === 3 ? -1 : s.lastIndexOf(sep);
      } else {
        decIdx = looksLikeThousands(parts) ? -1 : s.indexOf(sep);
      }
    }
  }

  const whole = (decIdx === -1 ? s : s.slice(0, decIdx)).replace(/[.,]/g, '');
  const frac = decIdx === -1 ? '' : s.slice(decIdx + 1).replace(/[.,]/g, '');
  const n = parseFloat((whole || '0') + (frac ? '.' + frac : ''));
  return Number.isFinite(n) ? n : 0;
}

// Grouped thousands for display inside numeric inputs (en-ZA uses spaces).
export function formatThousands(n) {
  const v = typeof n === 'number' ? n : parseCurrency(n);
  if (!v) return '';
  return Math.round(v).toLocaleString('en-ZA');
}
