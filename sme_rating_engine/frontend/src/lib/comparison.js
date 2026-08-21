/**
 * Which premium is compared against the benchmark — the one INCLUDING Funds
 * Protect, or the one stripped of it?
 *
 * NEW BUSINESS / COMPETING QUOTE: the broker decides, via the Step 3 toggle
 * "Does the competitor quote include a FP equivalent?". Comparing ex-FP is
 * deliberate and is the point of that toggle — Funds Protect is a market
 * differentiator, so when a rival's quote carries no FP equivalent, stripping
 * FP out is what makes the two figures comparable.
 *
 * RENEWAL: there is no competitor. "Renewal" in this engine means the client is
 * ALREADY on a Phishield policy, which by definition includes Funds Protect —
 * the wizard will not let a renewal proceed until its existing FP sub-limit is
 * captured. So the existing premium is always a with-FP figure, and the broker
 * should not be asked about an FP equivalent at all.
 *
 * Until 2026-08-21 renewals followed the competitor toggle, which defaults to
 * No. Every renewal therefore compared the new premium EX-FP against a with-FP
 * existing premium, understating the movement by roughly the FP cost — 15 live
 * renewals were affected, swings of 19-44 points, several showing a saving
 * where the premium had in fact risen.
 */
export function comparesWithFP(state) {
  if (state && state.quoteType === 'renewal') return true;   // existing policy always carries FP
  return !!(state && state.competitorHasFP);
}

/** Suffix shown next to a delta, e.g. "Delta (with FP)". */
export function compareBasisLabel(state) {
  return comparesWithFP(state) ? 'with FP' : 'ex-FP';
}

/** The Phishield figure to put up against the benchmark. */
export function compareAmountFor(state, calc) {
  return comparesWithFP(state) ? calc.annual : calc.annualExFP;
}
