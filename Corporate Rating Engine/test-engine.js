/* Headless test: reproduce the workbook's embedded example end-to-end.
 * Run: node "test-engine.js"   (expect Final Premium R457,460.93)
 */
const CORP_DATA = require("./corporate-data.js");
global.CORP_DATA = CORP_DATA;
const Engine = require("./corporate-engine.js");

const benefitsAllButPCIandCrime = [
  { name: "Business Interruption Loss", included: true, sublimitRatio: 1 },
  { name: "Multimedia Liability Claims", included: true, sublimitRatio: 1 },
  { name: "Regulatory Expenses and Penalties", included: true, sublimitRatio: 1 },
  { name: "Third Party Claims", included: true, sublimitRatio: 1 },
  { name: "Emergency Response Costs", included: true, sublimitRatio: 1 },
  { name: "Data Restoration Costs", included: true, sublimitRatio: 1 },
  { name: "Cyber Extortion Costs", included: true, sublimitRatio: 1 },
  { name: "PCI Fines and Penalties", included: false, sublimitRatio: 1 },
  { name: "Computer Crime", included: false, sublimitRatio: 1 },
];

const example = {
  turnover: 7200000000,
  cover: 50000000,
  subIndustry: "Manufacturing - Fabricated Metal Products, Except Machinery And Transportation Equipment",
  maturityOverride: "Moderate",
  vat: 0.15,
  benefits: benefitsAllButPCIandCrime,
  excess: 2000000,
  fpAdjustableAmount: 2000000,
  mdr: "No MDR",
};

const r = Engine.computePremium(example);

function approx(got, want, tol = 1) { return Math.abs(got - want) <= tol; }
const checks = [
  // Oracle updated 2026-10-15: Funds Protect tables re-read from the workbook ('Look Up Tables' rows 69-75).
  // Old FP R2M cost 24,420 -> 26,640; premium moves by (26,640-24,420)/0.94 = 2,361.70.
  ["Final premium",         r.finalPremium,       459822.63],
  ["Base premium",          r.basePremium,        459822.63],
  ["Funds Protect (R2M)",   r.fundsProtect,       26640],
  ["Expected breach cost", r.expectedBreachCost, 28332757.38],
  ["Maturity multiplier", r.maturityMultiplier, 1.0],
];

console.log("=== Embedded example ===");
let allOk = true;
for (const [label, got, want] of checks) {
  const ok = approx(got, want, Math.max(1, Math.abs(want) * 1e-4));
  allOk = allOk && ok;
  console.log(`  [${ok ? "OK " : "XX "}] ${label.padEnd(24)} got=${got.toLocaleString("en-ZA", { maximumFractionDigits: 2 }).padStart(16)}  want=${want.toLocaleString("en-ZA")}`);
}

console.log("\n=== Step trace ===");
for (const s of r.steps) {
  console.log(`  ${s.label.padEnd(36)} ${Number(s.value).toLocaleString("en-ZA", { maximumFractionDigits: 2 }).padStart(16)}   ${s.note}`);
}

// Sanity sweep: a few extra cases just to ensure no crashes + monotonic behaviour
console.log("\n=== Sanity sweep (no oracle, just sane outputs) ===");
for (const cover of [5000000, 10000000, 100000000]) {
  for (const band of ["Very Strong", "Moderate", "Very Weak"]) {
    const rr = Engine.computePremium({ ...example, cover, maturityOverride: band });
    console.log(`  cover=${(cover/1e6)+"M"} band=${band.padEnd(11)} final=${Engine.zar(rr.finalPremium)}`);
  }
}

// Real quotes reproduced from the underwriter's workbook snapshots (case b1_02, Premier, 2026-10-15).
console.log("\n=== Real quotes (workbook snapshots) ===");
const hotels = "Services - Hotels, Rooming Houses, Camps, And Other Lodging Places";
const hotelSub = CORP_DATA.INDUSTRIES.find((i) => /Hotels/.test(i.sub)).sub;
const essEndpoints = CORP_DATA.MDR_OPTIONS.find((m) => m.discount === 0.15).label;
for (const [id, cover, base, mdrAmt, final, exRM] of [
  ["Premier R5M", 5000000, 189892.03, 28483.80, 161408.22, 152271.91],
  ["Premier R10M", 10000000, 236638.33, 35495.75, 201142.58, 189757.15],
]) {
  const q = Engine.computePremium({
    turnover: 1137000000, cover, subIndustry: hotelSub || hotels, maturityOverride: "Moderate", vat: 0.15,
    benefits: benefitsAllButPCIandCrime, excess: 500000, fpAdjustableAmount: 0, mdr: essEndpoints,
  });
  for (const [label, got, want] of [["base", q.basePremium, base], ["MDR discount", q.mdrAmount, mdrAmt],
    ["final", q.finalPremium, final], ["without RM fee", q.premiumExRM, exRM]]) {
    const ok = approx(got, want, 0.01);
    allOk = allOk && ok;
    console.log(`  [${ok ? "OK " : "XX "}] ${(id + " " + label).padEnd(30)} got=${got.toFixed(2).padStart(12)} want=${want.toFixed(2)}`);
  }
}

// Public administration: Sophos MDR condition flagged automatically, discount capped at 15% (underwriter 2026-10-29).
console.log("\n=== Public administration MDR flag ===");
{
  const paSub = CORP_DATA.INDUSTRIES.find((i) => i.main === "Public Administration").sub;
  const complete = CORP_DATA.MDR_OPTIONS.reduce((a, m) => (m.discount > a.discount ? m : a));
  const base = { turnover: 97606799, cover: 5000000, subIndustry: paSub, maturityOverride: "Moderate", vat: 0.15,
    benefits: benefitsAllButPCIandCrime, excess: 100000, fpAdjustableAmount: 0 };
  const none = Engine.computePremium({ ...base, mdr: "No MDR" });
  const capped = Engine.computePremium({ ...base, mdr: complete.label });
  const priv = Engine.computePremium({ ...example, mdr: "No MDR" });
  for (const [label, ok] of [
    ["no MDR: condition required + warning", none.mdrConditionRequired && none.benefitWarnings.some((w) => /Sophos MDR condition/.test(w))],
    ["top tier capped at 15%", capped.mdrCapped && capped.mdrDiscount === 0.15],
    ["private risk not flagged", !priv.mdrConditionRequired && !priv.benefitWarnings.some((w) => /Sophos MDR/.test(w))],
  ]) { allOk = allOk && ok; console.log(`  [${ok ? "OK " : "XX "}] ${label}`); }
}

console.log("\n" + (allOk ? "ALL CHECKS PASSED ✓" : "*** CHECKS FAILED ***"));
process.exit(allOk ? 0 : 1);
