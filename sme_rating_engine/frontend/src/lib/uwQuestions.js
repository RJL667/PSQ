/**
 * Single source of truth for the CURRENT underwriting questions.
 *
 * The wording here is what the broker is actually asked on Step 1 and what gets
 * printed in the PDF audit annexure — the two must never drift, or the annexure
 * would misstate the question a client answered.
 *
 * HISTORY: the legacy data layer had an `UNDERWRITING_QUESTIONS` array that was
 * two renumberings out of date (Q1 as a single question, FP at Q7.x, prior cover
 * at Q9) and was never referenced by the legacy app either. It used to be copied
 * into rating-data.js and was an easy thing to mistake for the live list, so it
 * is now excluded at generation time (tools/gen_rating_data.mjs EXCLUDE). It
 * still exists in the frozen legacy `SME Rating Engine/sme-data.js`; do not
 * resurrect it.
 *
 * `key` matches the uwAnswers key persisted to Postgres (quotes.uw_answers).
 */

// Q1 sub-parts — baseline security controls. A "No" is a condition of cover
// (since 2026-08-04; previously Q1.1/Q1.2 declined outright).
export const Q1_INTRO =
  'Does your business have a comprehensive, paid-for internet security software subscription installed and up to date on all computer systems and access devices? This must include at a minimum:';

export const UW_QUESTION_GROUPS = [
  {
    heading: '1. Internet Security Software',
    intro: Q1_INTRO,
    questions: [
      { key: 'q1-1', num: '1.1', text: 'Antivirus/anti-malware with real-time endpoint detection and response (EDR)' },
      { key: 'q1-2', num: '1.2', text: 'A network firewall configured to filter incoming and outgoing traffic' },
      { key: 'q1-3', num: '1.3', text: 'An email security solution that filters for phishing, malware and malicious attachments' },
      { key: 'q1-4', num: '1.4', text: 'A web-filtering solution that blocks access to known malicious or suspicious websites' },
    ],
  },
  {
    heading: '2. Data Back-Up',
    questions: [
      { key: 'q2-1', num: '2.1', text: 'Do you back up your data on a weekly basis?' },
      { key: 'q2-2', num: '2.2', text: 'Do you perform recovery testing at least once per year?' },
    ],
  },
  {
    heading: '3-5. Security Practices',
    questions: [
      { key: 'q3', num: '3', text: 'Is your data stored separately from your main computer e.g. via the cloud or on an offline hard disk?' },
      { key: 'q4', num: '4', text: 'Do you regularly update and patch your computers so that they always have the latest security patches installed?' },
      { key: 'q5', num: '5', text: 'Are your employees regularly advised about the secure use of their workplace computer, especially regarding the dangers of using the internet/email?' },
    ],
  },
  {
    heading: '6-7. Funds Protect (cover above R250 000)',
    fpDependent: true,
    questions: [
      { key: 'q6-1', num: '6.1', text: 'Vetting of new vendors/customers/payees?' },
      { key: 'q6-2', num: '6.2', text: 'To verify new beneficiaries loaded onto your business’s banking profiles for funds transfers?' },
      { key: 'q6-3', num: '6.3', text: 'To verify requests to amend existing beneficiary payment details?' },
      { key: 'q7', num: '7', text: 'Does your business utilise account verification services offered by your bank or third-party provider?' },
    ],
  },
  {
    heading: '8. Prior Cover',
    questions: [
      { key: 'q8', num: '8', text: 'Have you been covered for cyber liability risks in the last 12 months prior to the inception date of this policy?' },
    ],
  },
];

// Flat list in display order — convenient for the PDF annexure.
export const UW_QUESTIONS_FLAT = UW_QUESTION_GROUPS.flatMap((g) =>
  g.questions.map((q) => ({ ...q, heading: g.heading, fpDependent: !!g.fpDependent })));

/** Render a stored answer for audit: explicit about "never answered". */
export function answerLabel(value) {
  if (value === true) return 'Yes';
  if (value === false) return 'No';
  return 'Not answered';
}
