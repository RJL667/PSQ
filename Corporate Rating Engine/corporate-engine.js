/* corporate-engine.js — pure premium-calculation engine for the Corporate Rating Engine.
 *
 * Faithful port of the "Premium Calculation" sheet from
 * 'Phishield Corporate Rarting Engine with Sec Questions_13_03_2026.xlsx'.
 * Validated step-by-step against the workbook's cached values (Final Premium R457,460.93).
 *
 * Runs in both the browser (global CorpEngine) and Node (module.exports) so the
 * math can be unit-tested headlessly.
 */
(function (global) {
  "use strict";
  const D = (typeof global.CORP_DATA !== "undefined" && global.CORP_DATA) ||
            (typeof require !== "undefined" ? require("./corporate-data.js") : null);
  if (!D) throw new Error("CORP_DATA not loaded");
  const K = D.CONSTANTS;
  // Aon risk bursary, workbook 'Summary & Input Flieds' E36 = C36 + C36*0.8*0.1:
  // 10% of the net premium (80% of the final). Aon quotes carry no RM fee.
  const BURSARY_RATE = 0.1, BURSARY_NET_SHARE = 0.8;

  // Exact-match lookup (mirrors XLOOKUP(...,,0) with match-mode 0)
  function xlookup(key, keys, vals, dflt) {
    for (let i = 0; i < keys.length; i++) {
      if (keys[i] === key) return vals[i];
    }
    return dflt === undefined ? null : dflt;
  }

  // --- table accessors ---
  const PUBLIC_ADMIN_MDR_CAP = 0.15;
  function industryByLabel(label) {
    return D.INDUSTRIES.find((r) => r.sub === label) || null;
  }
  function basePremiumConstant(cover) {
    const row = D.BASE_PREMIUM.find((b) => b.cover === cover && b.constant != null);
    return row ? row.constant : null;
  }
  function benefitContribution(name) {
    const b = D.BENEFITS.find((x) => x.name === name);
    return b ? b.contribution : 0;
  }
  function maturityByLabel(label) {
    return D.MATURITY_BANDS.find((m) => m.label === label) || null;
  }

  // Adjustable Funds Protect cost for ANY amount, by piecewise-linear interpolation
  // across the spreadsheet's FP table anchors (which include the (0,0) point).
  // Exact table amounts return the exact cost; in-between amounts are interpolated.
  function fpAdjustableCost(amount) {
    const A = D.FP_ADJUSTABLE.amounts, C = D.FP_ADJUSTABLE.costs;
    const idx = A.indexOf(amount);
    if (idx !== -1) return { cost: C[idx], interpolated: false };
    if (amount <= A[0]) return { cost: C[0], interpolated: amount !== A[0] };
    for (let i = 0; i < A.length - 1; i++) {
      if (amount >= A[i] && amount <= A[i + 1]) {
        const t = (amount - A[i]) / (A[i + 1] - A[i]);
        return { cost: C[i] + t * (C[i + 1] - C[i]), interpolated: true };
      }
    }
    const n = A.length - 1;
    const slope = (C[n] - C[n - 1]) / (A[n] - A[n - 1]);
    return { cost: C[n] + slope * (amount - A[n]), interpolated: true };
  }

  // C12: computed maturity multiplier from a 0..1 posture score, banded by AS/AT thresholds.
  function computedMaturityMultiplier(posture) {
    const m = D.MATURITY_BANDS;
    if (posture >= m[0].gte) return m[0].multiplier;
    for (const i of [1, 2, 3]) {
      if (m[i].gte != null && m[i].lt != null && posture >= m[i].gte && posture < m[i].lt) return m[i].multiplier;
    }
    return m[4].multiplier;
  }

  /**
   * Compute a full corporate premium. See README / ENGINE_ANALYSIS.md for the input shape.
   * Returns { ok, warning?, finalPremium, basePremium, monthly, ..., steps:[{label,value,kind,note}] }
   * step kinds: "zar" (currency) | "pct" (percentage) | "mult" (bare multiplier).
   */
  function computePremium(inp) {
    const steps = [];
    const push = (label, value, kind, note) => steps.push({ label, value, kind: kind || "zar", note: note || "" });

    const vat = inp.vat != null ? inp.vat : K.DEFAULT_VAT;
    const ind = industryByLabel(inp.subIndustry);
    if (!ind) return { ok: false, error: "Unknown sub-industry: " + inp.subIndustry };

    // C6 — Base premium (rate)
    const baseConst = basePremiumConstant(inp.cover);
    if (baseConst == null) return { ok: false, error: "No base-premium constant for cover " + inp.cover };
    const exponent = K.EXPONENT_A * Math.log(inp.turnover) + K.EXPONENT_B;
    const C6 = baseConst * Math.pow(inp.turnover / inp.cover, exponent);
    push("Base premium (rate)", C6, "zar", "constant × (turnover/cover)^power");

    // C8 industry risk modifier, C9 BI contribution modifier
    const C8 = ind.industryFac;
    const C9 = ind.biFac;
    push("Industry risk modifier", C8, "pct");
    push("Business-interruption modifier", C9, "pct");

    // C12/C13 — maturity multiplier (override band, or computed from posture when override = N/A)
    const override = inp.maturityOverride || "N/A";
    const computedMat = inp.posture != null ? computedMaturityMultiplier(inp.posture) : null;
    const overrideBand = maturityByLabel(override);
    const overrideMult = overrideBand ? overrideBand.multiplier : 1;
    const maturityMult = override === "N/A" ? (computedMat != null ? computedMat : 1) : overrideMult;
    push("Cyber-maturity multiplier", maturityMult, "mult", override === "N/A" ? "from questionnaire posture" : override);

    // C15 — Adjusted premium
    const C15 = (C6 * (1 + C8) * (1 + C9) * maturityMult) / K.C15_DIVISOR * (1 + vat);
    push("Adjusted premium", C15, "zar", "industry × BI × maturity, VAT-normalised");

    // C16 — ransomware-inclusive
    const cyberExtBenefit = (inp.benefits || []).find((b) => b.name === "Cyber Extortion Costs");
    const cyberExtD = cyberExtBenefit && cyberExtBenefit.included ? benefitContribution("Cyber Extortion Costs") : 0;
    const C16 = C15 / K.RANSOM_DIV + cyberExtD + C15;
    push("Adjusted premium (ransomware incl.)", C16, "zar");

    // Benefits D19..D27 -> D28 (baseline), H28 (sub-limit adjusted)
    let Dsum = 0, Hsum = 0, HsumExcess = 0;
    const benefitRows = [];
    for (const b of inp.benefits || []) {
      let d = 0;
      if (b.included) {
        d = b.name === "Business Interruption Loss" ? ind.biFac : benefitContribution(b.name);
      }
      const ratio = b.sublimitRatio != null ? b.sublimitRatio : 1;
      const h = b.included && ratio ? d * Math.sqrt(ratio) : 0;
    // Excess applies to this benefit unless explicitly switched off (workbook column "Excess Included").
    // Business Interruption has its own TIME excess (waiting period, 12-hour steps), which the workbook
    // does not price. Its loading stays in the rand-excess credit exactly as the workbook does.
    const excessIncluded = b.name === "Business Interruption Loss" || b.excessIncluded !== false;
    Dsum += d;
    Hsum += h;
    if (excessIncluded) HsumExcess += h;
    benefitRows.push({ name: b.name, included: !!b.included, excessIncluded, contribution: d, ratio, adjusted: h, subLimit: ratio * inp.cover });
    }
    push("Σ benefit contributions", Hsum, "pct");

    // C30 (sub-limit adjusted), C31 yearly market adjustment
    const C30 = C16 * Hsum;
    const C31 = C30 * (1 + K.YEARLY_MARKET_ADJ);
    push("Yearly market-adjusted premium", C31, "zar", pctStr(K.YEARLY_MARKET_ADJ) + " market factor");

    // Excess / deductible credit
    const C42 = K.SA_BREACH_FACTOR;
    const C45 = ind.breachZAR * C42; // expected average industry breach cost
    let C38, warning = null;
    if (inp.excess <= K.EXCESS_HALF_COVER * inp.cover) {
      C38 = C45 < inp.cover ? inp.excess / C45 : Math.pow(inp.excess / inp.cover, K.EXCESS_POWER);
    } else {
      warning = "Selected cover may result in partial self-insurance. Please review your cover amount.";
      C38 = 0;
    }
  // Any rand amount is accepted (the workbook only offered R500k steps). The credit is then scaled to the
  // share of the benefit loading that actually carries the excess: a benefit with no excess gets no credit.
  // With the excess on every included benefit (the workbook default) this equals the workbook exactly.
  const excessShare = Hsum > 0 ? HsumExcess / Hsum : 1;
  const C38full = C38;
  C38 = C38full * excessShare;
  push("Excess / self-insurance credit", C38, "pct", warning || (excessShare < 1 ? pctStr(C38full) + " × " + pctStr(excessShare) + " of benefits carrying the excess" : ""));
  const C48 = C31 * (1 - C38);
    push("Premium after excess credit", C48, "zar");

  // Funds Protect: none (Computer Crime instead), adjustable (>0), else standard (10% of cover).
  // Underwriter 2026-10-15: Funds Protect covers more than Computer Crime, so the two never go together.
  // With Funds Protect the Computer Crime benefit is left out; without it, Computer Crime is added
  // and the Funds Protect cost is left out of the premium.
  const fundsProtectIncluded = inp.fundsProtect !== false;
  let fp = 0, fpKind = "None", fpInterpolated = false, fpBelowMin = false;
  if (!fundsProtectIncluded) {
    fpKind = "Not included (Computer Crime benefit instead)";
  } else if (inp.fpAdjustableAmount && inp.fpAdjustableAmount > 0) {
      const fr = fpAdjustableCost(inp.fpAdjustableAmount);
      fp = fr.cost; fpInterpolated = fr.interpolated;
      fpBelowMin = inp.fpAdjustableAmount < 0.10 * inp.cover;
      fpKind = "Adjustable FP @ " + zar(inp.fpAdjustableAmount) + (fr.interpolated ? " (interpolated)" : "");
    } else {
      fp = xlookup(inp.cover * 0.1, D.FP_STANDARD.amounts, D.FP_STANDARD.costs, 0) || 0;
      fpKind = "Standard FP (10% of cover)";
    }
    push("Funds Protect contribution", fp, "zar", fpKind);
  const crime = (inp.benefits || []).find((b) => b.name === "Computer Crime");
  const benefitWarnings = [];
  if (fundsProtectIncluded && crime && crime.included)
    benefitWarnings.push("Computer Crime is ticked while Funds Protect is included. Funds Protect already covers it; untick Computer Crime.");
  if (!fundsProtectIncluded && !(crime && crime.included))
    benefitWarnings.push("No Funds Protect on this quote, so Computer Crime should be ticked.");

    // Depository-institution modifier (only for Depository Institutions sub-industry)
    let depository = 0;
    if (inp.subIndustry === D.DEPOSITORY_SUB) {
      for (const band of D.DEPOSITORY_BANDS) {
        const lo = band.gte, hi = band.lt;
        if (hi == null ? inp.turnover >= lo : inp.turnover >= lo && inp.turnover < hi) {
          depository = band.modifier;
          break;
        }
      }
    }

    // C53 — base premium (pre-discount), C56/C57 — MDR discount & final
    const C53 = ((C48 + fp) / (1 - K.RISK_MGMT_FEE)) * (depository > 0 ? depository : 1);
    push("Base premium", C53, "zar", depository > 0 ? "incl. depository ×" + depository : "incl. 6% risk-mgmt fee");
    let mdrDiscount = xlookup(inp.mdr || "No MDR", D.MDR_OPTIONS.map((m) => m.label), D.MDR_OPTIONS.map((m) => m.discount), 0) || 0;
    // Underwriter 2026-10-15 / 2026-10-29: every public administration risk (SOEs, municipalities,
    // government-owned entities) carries the Sophos MDR condition of cover, and the MDR discount is
    // capped at 15%. The MDR route is tried first; the No MDR price is the fallback if the client pushes back.
    const mdrConditionRequired = ind.main === "Public Administration";
    let mdrCapped = false;
    if (mdrConditionRequired) {
      if (mdrDiscount === 0) {
        benefitWarnings.push("Public administration risk: put the Sophos MDR condition of cover on the quote (Sophos MDR Complete on all access devices and the entire network, with endpoints deployed, or a comparable MDR programme the client must specify) and price with the MDR discount, capped at " + pctStr(PUBLIC_ADMIN_MDR_CAP) + ". Keep this No MDR price as the fallback if the client pushes back.");
      } else if (mdrDiscount > PUBLIC_ADMIN_MDR_CAP) {
        benefitWarnings.push("MDR discount capped at " + pctStr(PUBLIC_ADMIN_MDR_CAP) + " for public administration (selected tier allows " + pctStr(mdrDiscount) + ").");
        mdrDiscount = PUBLIC_ADMIN_MDR_CAP;
        mdrCapped = true;
      }
    }
    const C56 = C53 * mdrDiscount;
    const premiumPreDisc = C53 - C56; // C57 — final before any discretionary adjustment
    if (mdrDiscount > 0) push("Sophos MDR discount", -C56, "zar", pctStr(mdrDiscount) + " — " + inp.mdr + (mdrCapped ? " (public administration cap)" : ""));

    // Discretionary adjustment (positive = discount, negative = loading), applied to the final premium.
    const discretionary = inp.discretionary || 0;
    const discretionaryAmount = premiumPreDisc * discretionary;
    const finalPremium = premiumPreDisc - discretionaryAmount;
    if (discretionary !== 0) {
      push("Premium before discretionary", premiumPreDisc, "zar");
      const verb = discretionary >= 0 ? "discount" : "loading";
      push("Discretionary " + verb, -discretionaryAmount, "zar", pctStr(Math.abs(discretionary)) + " (manual)");
    }
    push("Final premium", finalPremium, "zar");

    const riskBursary = !!inp.riskBursary;
    const bursaryAmount = riskBursary ? finalPremium * BURSARY_NET_SHARE * BURSARY_RATE : 0;
    const premiumInclBursary = finalPremium + bursaryAmount;
    if (riskBursary) push("Aon risk bursary", bursaryAmount, "zar", "10% of net premium (80% of final); no RM fee");

    // Summary-row derivations (on the final, post-discretionary premium)
    const monthly = finalPremium / 12;
    // "Premium without RM Fee" — the figure captured on the admin platform, which then adds
    // a 6% RM fee to reach the final premium. Matches the workbook's "Excl. RM" line (D36 = C36/1.06).
    const premiumExRM = finalPremium / 1.06;
    const monthlyExRM = Math.ceil(premiumExRM / 12);
    const exFP = finalPremium - fp;
    const smeEquivalent = (finalPremium * 0.8) / (1 + vat); // F36 ex-FP / ex-VAT SME-equivalent
    const smeRatio = finalPremium * K.SME_CORP_RATIO; // I36

    return {
      ok: true, warning,
      finalPremium, premiumPreDiscretionary: premiumPreDisc, basePremium: C53, fundsProtect: fp,
      monthly, premiumExRM, monthlyExRM, exFP, smeEquivalent, smeRatio,
      riskBursary, bursaryAmount, premiumInclBursary,
    fundsProtectIncluded, benefitWarnings, excessCredit: C38, excessCreditFull: C38full, excessShare,
      // The figure the underwriter quotes: without the 6% RM fee, or for Aon the full premium (bursary shown on top).
      quotedPremium: riskBursary ? finalPremium : premiumExRM,
      quoteBasis: riskBursary ? "aon_full_plus_bursary" : "ex_rm_fee",
      mdrDiscount, mdrAmount: C56, mdrConditionRequired, mdrCapped, discretionary, discretionaryAmount,
      fpInterpolated, fpBelowMin, depositoryModifier: depository, expectedBreachCost: C45,
      industry: ind, maturityMultiplier: maturityMult, benefitRows, vat, steps,
    };
  }

  // Compute the premium for the given inputs across every cover option (for the comparison view).
  function computeAcrossCovers(inp) {
    return D.COVER_OPTIONS.map((c) => {
      const r = computePremium(Object.assign({}, inp, { cover: c }));
      return r.ok
        ? { cover: c, finalPremium: r.finalPremium, monthly: r.monthly, fundsProtect: r.fundsProtect, warning: r.warning, fpBelowMin: r.fpBelowMin }
        : { cover: c, error: r.error };
    });
  }

  function pctStr(x) { return (x * 100).toFixed(2) + "%"; }
  function zar(n) { return "R" + Math.round(n).toLocaleString("en-ZA"); }

  const ENGINE = { xlookup, computePremium, computeAcrossCovers, fpAdjustableCost, computedMaturityMultiplier, industryByLabel, basePremiumConstant, zar };
  if (typeof module !== "undefined" && module.exports) module.exports = ENGINE;
  global.CorpEngine = ENGINE;
})(typeof window !== "undefined" ? window : globalThis);
