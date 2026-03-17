/* ===== Pricing Data ===== */
const REVENUE_BANDS = [
  "R0 – R10M", "R10M – R25M", "R25M – R50M",
  "R50M – R75M", "R75M – R100M", "R100M – R150M",
  "R150M – R200M", "Over R200M"
];
const COVER_LIMITS = [
  "R1M", "R2.5M", "R5M", "R7.5M", "R10M", "R15M", "Over R15M"
];

// Matrix: Row = Revenue Band, Column = Cover Limit (annual premiums)
const PRICING = [
  [6264, 8520, 11052, 15816, 20184, 27816],   // R0 – R10M
  [6264, 8520, 11052, 19428, 23988, 31788],   // R10M – R25M
  [6264, 8520, 11052, 23028, 27792, 35760],   // R25M – R50M
  [14040, 17172, 24072, 30228, 35436, 41928], // R50M – R75M
  [16488, 22440, 28332, 33660, 39480, 47832], // R75M – R100M
  [18804, 24144, 30300, 37476, 43248, 52824], // R100M – R150M
  [22608, 28116, 33396, 41112, 46644, 58524]  // R150M – R200M
];

// SA industry breach cost data
const INDUSTRY_DATA = {
  "Agriculture":                        { breachCost: "R38.2M",  costPerRecord: "R2,850",  riskMultiplier: 0.30 },
  "Construction":                       { breachCost: "R42.1M",  costPerRecord: "R3,100",  riskMultiplier: 0.35 },
  "Finance, Insurance and Real Estate": { breachCost: "R89.3M",  costPerRecord: "R5,200",  riskMultiplier: 0.80 },
  "Healthcare":                         { breachCost: "R95.6M",  costPerRecord: "R5,800",  riskMultiplier: 0.90 },
  "Manufacturing":                      { breachCost: "R52.4M",  costPerRecord: "R3,400",  riskMultiplier: 0.50 },
  "Mining":                             { breachCost: "R48.7M",  costPerRecord: "R3,200",  riskMultiplier: 0.45 },
  "Public Administration":              { breachCost: "R76.7M",  costPerRecord: "R4,600",  riskMultiplier: 0.85 },
  "Retail":                             { breachCost: "R56.8M",  costPerRecord: "R3,600",  riskMultiplier: 0.55 },
  "Services":                           { breachCost: "R44.5M",  costPerRecord: "R3,000",  riskMultiplier: 0.35 },
  "Software and Technology":            { breachCost: "R82.1M",  costPerRecord: "R4,900",  riskMultiplier: 0.75 },
  "Transportation":                     { breachCost: "R50.3M",  costPerRecord: "R3,300",  riskMultiplier: 0.45 },
  "Wholesale":                          { breachCost: "R41.8M",  costPerRecord: "R2,950",  riskMultiplier: 0.30 },
  "Other":                              { breachCost: "R45.0M",  costPerRecord: "R3,100",  riskMultiplier: 0.40 }
};

/* ===== State ===== */
const state = {
  currentStep: 1,
  industry: null,
  revenueIndex: 0,
  coverIndex: 0,
  hasMDR: false,
  mdrDiscount: 0,
  mdrType: ''
};

/* ===== DOM Helpers ===== */
const $ = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);

/* ===== Formatting ===== */
function formatR(n) {
  return 'R' + Math.round(n).toLocaleString('en-ZA');
}

/* ===== Number Animation ===== */
function animateNumber(el, target, prefix = '', suffix = '') {
  const current = parseInt((el.textContent || '0').replace(/[^\d]/g, ''), 10) || 0;
  if (current === target) return;

  el.classList.add('changing');
  setTimeout(() => {
    el.textContent = prefix + Math.round(target).toLocaleString('en-ZA') + suffix;
    el.classList.remove('changing');
  }, 150);
}

/* ===== Gauge Animation ===== */
function setGauge(riskMultiplier) {
  const arc = $('gaugeArc');
  const label = $('gaugeLabel');
  const totalLen = 157; // approx half-circle length
  const fillLen = Math.max(5, riskMultiplier * totalLen);

  arc.style.transition = 'stroke-dasharray 0.8s cubic-bezier(0.4,0,0.2,1)';
  arc.setAttribute('stroke-dasharray', `${fillLen} ${totalLen}`);

  let riskText = 'Low';
  if (riskMultiplier >= 0.75) riskText = 'Critical';
  else if (riskMultiplier >= 0.6) riskText = 'High';
  else if (riskMultiplier >= 0.4) riskText = 'Medium';

  label.textContent = riskText;
}

/* ===== Calculate Premium ===== */
function getPremium() {
  const ri = state.revenueIndex;
  const ci = state.coverIndex;
  const ind = state.industry;
  const isExcluded = (ind === "Public Administration" || ind === "Healthcare");
  const isOverRevenue = ri === 7;
  const isOverCover = ci === 6;

  if (isOverRevenue || isOverCover || isExcluded) {
    return { annual: null, monthly: null, contact: true };
  }

  let annual = PRICING[ri][ci];
  if (state.hasMDR && state.mdrDiscount > 0) {
    annual *= (1 - state.mdrDiscount);
  }
  return { annual, monthly: annual / 12, contact: false };
}

function getBasePremium() {
  const ri = state.revenueIndex;
  const ci = state.coverIndex;
  if (ri >= 7 || ci >= 6) return null;
  return PRICING[ri][ci];
}

/* ===== Update Pricing Display ===== */
function updatePricing() {
  const p = getPremium();
  const pdAnnualNum = $('pdAnnualNum');
  const pdMonthlyNum = $('pdMonthlyNum');
  const pdAmounts = document.querySelector('.pd-amounts');
  const pdContact = $('pdContact');
  const ticker = $('quoteTicker');
  const tickerAmount = $('tickerAmount');

  if (p.contact) {
    if (pdAmounts) pdAmounts.style.display = 'none';
    if (pdContact) pdContact.style.display = 'block';
    ticker.classList.remove('visible');
  } else {
    if (pdAmounts) pdAmounts.style.display = 'flex';
    if (pdContact) pdContact.style.display = 'none';
    animateNumber(pdAnnualNum, p.annual);
    animateNumber(pdMonthlyNum, p.monthly);

    // Ticker
    if (state.currentStep >= 2) {
      ticker.classList.add('visible');
      tickerAmount.textContent = formatR(p.monthly) + '/mo';
    }
  }
}

/* ===== Update Savings Viz ===== */
function updateSavingsViz() {
  const base = getBasePremium();
  const viz = $('savingsViz');

  if (!state.hasMDR || base === null) {
    viz.classList.remove('visible');
    return;
  }

  viz.classList.add('visible');

  const discounted = base * (1 - state.mdrDiscount);
  const savings = base - discounted;
  const pct = discounted / base * 100;

  // Animate bars after a tick
  requestAnimationFrame(() => {
    $('svBarBase').style.width = '100%';
    $('svBarDiscount').style.width = pct + '%';
  });

  $('svBaseAmount').textContent = formatR(base) + '/yr';
  $('svDiscountAmount').textContent = formatR(discounted) + '/yr';
  $('svSavingsAmount').textContent = formatR(savings);
}

/* ===== Step Navigation ===== */
function goToStep(n) {
  if (n < 1 || n > 5) return;
  if (n === state.currentStep) return;

  // Hide current
  const current = $('step' + state.currentStep);
  if (current) current.classList.remove('active');

  // Show next
  if (n === 5) {
    $('successPanel').classList.add('active');
  } else {
    const next = $('step' + n);
    if (next) next.classList.add('active');
  }

  state.currentStep = n;

  // Update progress bar
  const fillPct = ((n - 1) / 3) * 100;
  $('progressFill').style.width = fillPct + '%';

  for (let i = 1; i <= 4; i++) {
    const stepEl = $('pStep' + i);
    stepEl.classList.remove('active', 'completed');
    if (i < n) stepEl.classList.add('completed');
    else if (i === n) stepEl.classList.add('active');
  }

  // Ticker visibility
  const ticker = $('quoteTicker');
  const p = getPremium();
  if (n >= 2 && n <= 4 && !p.contact) {
    ticker.classList.add('visible');
  } else {
    ticker.classList.remove('visible');
  }

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ===== Populate Final Summary ===== */
function populateSummary() {
  $('fsIndustry').textContent = state.industry || '--';
  $('fsRevenue').textContent = state.revenueIndex === 7
    ? `Over R200M (${$('customTurnover').value || 'N/A'})`
    : REVENUE_BANDS[state.revenueIndex];
  $('fsCover').textContent = state.coverIndex === 6
    ? `Over R15M (${$('customCover').value || 'N/A'})`
    : COVER_LIMITS[state.coverIndex];

  const p = getPremium();
  if (p.contact) {
    $('fsAnnual').textContent = 'Contact Required';
    $('fsMonthly').textContent = 'Contact Required';
  } else {
    $('fsAnnual').textContent = formatR(p.annual);
    $('fsMonthly').textContent = formatR(p.monthly);
  }

  const mdrEl = $('fsMdr');
  if (state.hasMDR && state.mdrDiscount > 0) {
    mdrEl.textContent = `${Math.round(state.mdrDiscount * 100)}% MDR Discount Applied (${state.mdrType})`;
  } else {
    mdrEl.textContent = '';
  }
}

/* ===== STEP 1: Industry Selection ===== */
const industrySelect = $('industrySelect');
const riskInsight = $('riskInsight');
const industryDisclaimer = $('industryDisclaimer');
const nextBtn1 = $('nextBtn1');

industrySelect.addEventListener('change', () => {
  const selected = industrySelect.options[industrySelect.selectedIndex];
  state.industry = selected.value;
  const data = INDUSTRY_DATA[state.industry];
  const risk = selected.dataset.risk;

  // Risk insight
  $('riIndustry').textContent = state.industry;
  $('riBreachCost').textContent = data.breachCost;
  $('riCostPerRecord').textContent = data.costPerRecord;
  setGauge(data.riskMultiplier);
  riskInsight.classList.add('visible');

  // Disclaimer
  if (risk === 'high') {
    industryDisclaimer.innerHTML = '<strong>Note:</strong> High-risk industries may have an industry risk modifier included in the final underwritten quote.';
    industryDisclaimer.classList.add('visible');
  } else if (risk === 'critical') {
    industryDisclaimer.innerHTML = '<strong>Note:</strong> This industry requires manual underwriting. Submit your details and we will prepare a custom quote.';
    industryDisclaimer.classList.add('visible');
  } else {
    industryDisclaimer.classList.remove('visible');
  }

  nextBtn1.disabled = false;
});

nextBtn1.addEventListener('click', () => {
  if (!state.industry) return;
  updatePricing();
  goToStep(2);
});

/* ===== STEP 2: Coverage Selection ===== */
function setupCardSelector(containerId, stateKey) {
  const cards = $$(` #${containerId} .sel-card`);
  cards.forEach(card => {
    card.addEventListener('click', () => {
      cards.forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      state[stateKey] = parseInt(card.dataset.index, 10);

      // Show/hide custom inputs
      if (stateKey === 'revenueIndex') {
        $('customTurnoverGroup').style.display = state.revenueIndex === 7 ? 'block' : 'none';
      }
      if (stateKey === 'coverIndex') {
        $('customCoverGroup').style.display = state.coverIndex === 6 ? 'block' : 'none';
      }

      updatePricing();
    });
  });
}

setupCardSelector('revenueCards', 'revenueIndex');
setupCardSelector('coverCards', 'coverIndex');

$('nextBtn2').addEventListener('click', () => {
  updateSavingsViz();
  goToStep(3);
});
$('backBtn2').addEventListener('click', () => goToStep(1));

/* ===== STEP 3: MDR / Security Posture ===== */
const mdrYesBtn = $('mdrYes');
const mdrNoBtn = $('mdrNo');
const mdrProducts = $('mdrProducts');
const mdrCards = $$('.mdr-card');

mdrYesBtn.addEventListener('click', () => {
  mdrYesBtn.classList.add('active');
  mdrNoBtn.classList.remove('active');
  state.hasMDR = true;
  mdrProducts.classList.add('visible');

  // Select default if none selected
  const active = document.querySelector('.mdr-card.active');
  if (active) {
    state.mdrDiscount = parseFloat(active.dataset.discount);
    state.mdrType = active.dataset.type;
  }
  updatePricing();
  updateSavingsViz();
});

mdrNoBtn.addEventListener('click', () => {
  mdrNoBtn.classList.add('active');
  mdrYesBtn.classList.remove('active');
  state.hasMDR = false;
  state.mdrDiscount = 0;
  state.mdrType = '';
  mdrProducts.classList.remove('visible');
  $('savingsViz').classList.remove('visible');
  updatePricing();
});

mdrCards.forEach(card => {
  card.addEventListener('click', () => {
    mdrCards.forEach(c => c.classList.remove('active'));
    card.classList.add('active');
    state.mdrDiscount = parseFloat(card.dataset.discount);
    state.mdrType = card.dataset.type;
    updatePricing();
    updateSavingsViz();
  });
});

$('nextBtn3').addEventListener('click', () => {
  populateSummary();
  goToStep(4);
});
$('backBtn3').addEventListener('click', () => goToStep(2));

/* ===== STEP 4: Contact Details ===== */
$('backBtn4').addEventListener('click', () => goToStep(3));

function validateStep4() {
  const form = $('step4');
  const required = form.querySelectorAll('[required]');
  let valid = true;

  required.forEach(el => {
    el.classList.remove('invalid');
    if (!el.value.trim()) {
      el.classList.add('invalid');
      valid = false;
    }
  });

  const email = $('emailField');
  if (email.value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) {
    email.classList.add('invalid');
    valid = false;
  }

  if (!valid) {
    const first = form.querySelector('.invalid');
    if (first) first.focus();
  }

  return valid;
}

$('leadForm').addEventListener('submit', (e) => {
  e.preventDefault();
  if (!validateStep4()) return;

  const p = getPremium();
  const annualStr = p.contact ? 'Contact for Quote' : formatR(p.annual);
  const monthlyStr = p.contact ? 'Contact for Quote' : formatR(p.monthly);

  // Populate hidden fields
  $('h_revenueBand').value = state.revenueIndex === 7 ? 'Over R200M' : REVENUE_BANDS[state.revenueIndex];
  $('h_coverLimit').value = state.coverIndex === 6 ? 'Over R15M' : COVER_LIMITS[state.coverIndex];
  $('h_annualPremium').value = annualStr;
  $('h_monthlyPremium').value = monthlyStr;
  $('h_mdrQualified').value = state.hasMDR ? state.mdrType : 'No';
  $('h_industry').value = state.industry || '';
  $('h_customTurnover').value = $('customTurnover').value || 'N/A';
  $('h_customCover').value = $('customCover').value || 'N/A';
  $('fs_subject').value = `Lead Submission: ${$('companyName').value.trim()} - Phishield Cyber Cover`;

  const btn = $('submitBtn');
  btn.disabled = true;
  btn.innerHTML = '<span>Sending...</span>';
  $('leadForm').submit();
});

/* ===== Progress Step Clicks (navigation to completed steps) ===== */
$$('.progress-step').forEach(step => {
  step.addEventListener('click', () => {
    const targetStep = parseInt(step.dataset.step, 10);
    if (targetStep < state.currentStep) {
      if (targetStep === 2) updatePricing();
      if (targetStep === 3) { updatePricing(); updateSavingsViz(); }
      if (targetStep === 4) populateSummary();
      goToStep(targetStep);
    }
  });
});

/* ===== Handle FormSubmit redirect ===== */
if (new URLSearchParams(window.location.search).get('submitted') === 'true') {
  $$('.step-panel').forEach(p => p.classList.remove('active'));
  $('successPanel').classList.add('active');
  $('progressFill').style.width = '100%';
  for (let i = 1; i <= 4; i++) {
    $('pStep' + i).classList.remove('active');
    $('pStep' + i).classList.add('completed');
  }
  window.history.replaceState({}, '', window.location.pathname);
}

/* ===== Init ===== */
updatePricing();
