import { COVER_LIMITS, COVER_AVAILABILITY, BASE_FP_BY_COVER, getAvailableFPOptions } from '../rating-data.js';
import { formatR, getItooBenchmark } from '../rating-engine.js';
import { optionLabel, coverInstanceCount } from '../lib/options.js';
import { parseCurrency } from '../lib/format.js';
import Toggle from '../components/Toggle.jsx';
import CurrencyInput from '../components/CurrencyInput.jsx';

export default function Step4Adjust({ state, patch, dispatch, derived, goToStep }) {
  const options = state.quoteOptions;
  const band = derived.revenueBandIndex;
  const uw = derived.uw;
  const activeId = state.activeOptionTab && options.some((o) => o.id === state.activeOptionTab)
    ? state.activeOptionTab : (options[0]?.id ?? null);
  const activeOpt = options.find((o) => o.id === activeId) || options[0];

  const pFrac = (o) => (parseFloat(o?.posturePct) || 0) / 100;
  const dFrac = (o) => (parseFloat(o?.discretionaryPct) || 0) / 100;

  const setDiscount = (field, val) => {
    if (state.applyDiscountsToAll) {
      dispatch({ type: 'setOptions', options: options.map((o) => ({ ...o, [field]: val })) });
    } else if (activeOpt) {
      dispatch({ type: 'patchOption', id: activeOpt.id, patch: { [field]: val } });
    }
  };
  const setOverride = (v) => {
    if (state.applyDiscountsToAll) {
      dispatch({ type: 'setOptions', options: options.map((o) => ({ ...o, manualOverride: v })) });
    } else if (activeOpt) {
      dispatch({ type: 'patchOption', id: activeOpt.id, patch: { manualOverride: v } });
    }
  };

  // getBenchmark(): existing policy premium for renewals, else IToo industry benchmark.
  const getBenchmark = (ci) => {
    if (state.quoteType === 'renewal' && derived.renewalPremiumNum > 0) {
      return { premium: derived.renewalPremiumNum, label: 'Existing Policy' };
    }
    const itoo = getItooBenchmark(derived.actualTurnover, ci);
    return itoo ? { premium: itoo.premium, label: 'Industry Benchmark' } : null;
  };

  // Active-option discount rand impacts (verbatim legacy formula).
  let postureValueStr = 'R 0';
  let discValueStr = 'R 0';
  const activeCalc = activeOpt ? derived.optionCalcs[activeOpt.id] : null;
  if (activeOpt && activeCalc) {
    const pd = pFrac(activeOpt);
    const dd = dFrac(activeOpt);
    const baseBeforeDisc = activeCalc.annual / ((1 - pd) * (1 - dd)) || activeCalc.annual;
    const postureAmt = baseBeforeDisc * pd;
    const discAmt = (baseBeforeDisc - postureAmt) * dd;
    const posturePrefix = pd < 0 ? '+' : pd > 0 ? '-' : '';
    const discPrefix = dd < 0 ? '+' : dd > 0 ? '-' : '';
    postureValueStr = posturePrefix + formatR(Math.abs(postureAmt));
    discValueStr = discPrefix + formatR(Math.abs(discAmt));
  }
  const pdA = pFrac(activeOpt);
  const ddA = dFrac(activeOpt);
  const combined = 1 - (1 - pdA) * (1 - ddA);
  const showWarning = combined > 0.35 && pdA >= 0 && ddA >= 0;

  // ── Underwriting Conditions panel (renderUWConditionsPanel) ──
  const outcomeLabel = uw.outcome === 'caution' ? 'Proceed with Caution'
    : uw.outcome === 'loading' ? `${Math.round(uw.loadingPct * 100)}% Loading Applied`
    : uw.outcome === 'refer' ? 'Referral Required'
    : uw.outcome;

  let effectiveFPOver250k = state.fpOver250k;
  for (const opt of options) {
    const coverKey = COVER_LIMITS[opt.coverIndex].key;
    if (BASE_FP_BY_COVER[coverKey] > 250_000) effectiveFPOver250k = true;
    if (opt.fpIndex !== undefined && opt.fpIndex !== null) {
      const availFP = getAvailableFPOptions(coverKey);
      if (opt.fpIndex >= 0 && opt.fpIndex < availFP.length && availFP[opt.fpIndex].limit > 250_000) effectiveFPOver250k = true;
    }
  }

  const renewal = derived.reco?.renewal || {};
  const highestAvailIdx = () => {
    for (let i = COVER_LIMITS.length - 1; i >= 0; i--) {
      if (band >= 0 && COVER_AVAILABILITY[band][i]) return i;
    }
    return -1;
  };

  const condSections = [];
  if (uw.outcome && uw.outcome !== 'standard') {
    condSections.push(
      <div className="uw-cond-section" key="outcome">
        <div className="uw-cond-label">Underwriting Outcome</div>
        <div className="uw-cond-value">{outcomeLabel} ({uw.noCount || 0} concern{uw.noCount !== 1 ? 's' : ''} noted)</div>
      </div>,
    );
  }
  if (effectiveFPOver250k && uw.fpConditions && uw.fpConditions.length > 0) {
    condSections.push(
      <div className="uw-cond-section" key="fp">
        <div className="uw-cond-label">Conditions of Cover (FP &gt; R250,000)</div>
        <div className="uw-cond-value">The following requirements are conditions of cover:</div>
        <ul>{uw.fpConditions.map((c, i) => <li key={i}>{c}</li>)}</ul>
      </div>,
    );
  } else if (effectiveFPOver250k) {
    const q6Answered = state.uwAnswers['q6-1'] !== undefined;
    const q7Answered = state.uwAnswers['q7'] !== undefined;
    if (!q6Answered || !q7Answered) {
      condSections.push(
        <div className="uw-cond-section" key="fpwarn">
          <div className="uw-cond-label">FP Cover &gt; R250,000</div>
          <div className="uw-cond-value" style={{ color: 'var(--warning)' }}>Q6 and Q7 require answers — FP cover exceeds R250,000 threshold. Please complete underwriting questions on Step 1.</div>
        </div>,
      );
    }
  }
  if (uw.q1Conditions && uw.q1Conditions.length > 0) {
    condSections.push(
      <div className="uw-cond-section" key="q1">
        <div className="uw-cond-label">Conditions of Cover (Q1 baseline controls)</div>
        <div className="uw-cond-value">The following baseline security controls must be implemented as conditions of cover:</div>
        <ul>{uw.q1Conditions.map((c, i) => <li key={i}>{c}</li>)}</ul>
      </div>,
    );
  }
  if (state.priorClaim) {
    condSections.push(
      <div className="uw-cond-section" key="claim">
        <div className="uw-cond-label">Prior Claim</div>
        <div className="uw-cond-value">Additional underwriting required based on prior claims history.</div>
      </div>,
    );
  }
  if (state.quoteType === 'renewal' && renewal.dropTriggered) {
    const dropPct = Math.round(renewal.dropPct * 100);
    if (renewal.corporateEscalation) {
      const maxIdx = highestAvailIdx();
      const maxLabel = maxIdx >= 0 ? COVER_LIMITS[maxIdx].label : '--';
      condSections.push(
        <div className="uw-cond-section" key="corp">
          <div className="uw-cond-label">Premium Loss Risk — Corporate Referral</div>
          <div className="uw-cond-value" style={{ color: 'var(--warning)' }}>Premium at existing cover is {dropPct}% below the existing policy, and the highest SME cover ({maxLabel}) still falls below 90% retention. Consider converting to a Corporate product — refer to underwriter.</div>
        </div>,
      );
    } else {
      const tgtLabel = renewal.recommendedCoverIndex >= 0 ? COVER_LIMITS[renewal.recommendedCoverIndex].label : '--';
      condSections.push(
        <div className="uw-cond-section" key="drop">
          <div className="uw-cond-label">Premium Loss Risk on Renewal</div>
          <div className="uw-cond-value">Premium at existing cover is {dropPct}% below the existing policy. Recommended cover adjusted to {tgtLabel} to retain ≥ 90% of existing premium.</div>
        </div>,
      );
    }
  }
  if (state.quoteType === 'renewal' && renewal.bandChanged && !renewal.dropTriggered) {
    condSections.push(
      <div className="uw-cond-section" key="band">
        <div className="uw-cond-label">Revenue Band Shift</div>
        <div className="uw-cond-value">Existing cover limit is outside the recommended set for the current turnover band. Verify cover adequacy.</div>
      </div>,
    );
  }
  if (state.quoteType === 'renewal' && uw.loadingPct > 0) {
    const pct = Math.round(uw.loadingPct * 100);
    condSections.push(
      <div className="uw-cond-section" key="caveat">
        <div className="uw-cond-label">Comparison Caveat — UW Loading</div>
        <div className="uw-cond-value">Current quote includes a {pct}% underwriting loading based on Q2.1–Q5 answers. Prior term's posture is not on record; year-on-year comparison is not strictly like-for-like.</div>
      </div>,
    );
  }

  return (
    <section className="step-panel active" id="step-4">
      <div className="glass-card">
        <div className="step-header">
          <h2>Adjustments &amp; Comparison</h2>
          <p>Apply discounts or overrides and compare against benchmarks.</p>
        </div>

        {options.length >= 2 && (
          <label className="apply-all-toggle" id="apply-all-toggle" style={{ display: 'flex' }}>
            <input type="checkbox" id="apply-all-check" checked={state.applyDiscountsToAll}
              onChange={(e) => patch({ applyDiscountsToAll: e.target.checked })} />
            <span>Apply discounts to all quote options</span>
          </label>
        )}

        {options.length >= 2 && (
          <div className="option-tabs" id="step4-option-tabs" aria-label="Adjustment tabs">
            {options.map((o, idx) => {
              const inst = coverInstanceCount(options, o.coverIndex) > 1
                ? ' (' + (options.filter((x, i) => x.coverIndex === o.coverIndex && i <= idx).length) + ')' : '';
              return (
                <button key={o.id} type="button" className={'option-tab' + (o.id === activeId ? ' active' : '')}
                  onClick={() => patch({ activeOptionTab: o.id })}>{COVER_LIMITS[o.coverIndex].label}{inst}</button>
              );
            })}
          </div>
        )}

        <div className="discount-section" id="step4-discount-section">
          <div className="discount-group" data-discount="posture">
            <label className="field-label" htmlFor="posture-discount">Posture Adjustment (%)</label>
            <div className="discount-input-row">
              <input className="form-input" id="posture-discount" type="text" inputMode="numeric" placeholder="e.g. 15 or -10"
                aria-label="Posture adjustment percentage"
                value={activeOpt?.posturePct ?? ''} onChange={(e) => setDiscount('posturePct', e.target.value)} />
              <span className="discount-computed" id="posture-discount-value">{postureValueStr}</span>
            </div>
          </div>
          <div className="discount-group" data-discount="discretionary">
            <label className="field-label" htmlFor="discretionary-discount">Discretionary Adjustment (%)</label>
            <div className="discount-input-row">
              <input className="form-input" id="discretionary-discount" type="text" inputMode="numeric" placeholder="e.g. 5 or -10"
                aria-label="Discretionary adjustment percentage"
                value={activeOpt?.discretionaryPct ?? ''} onChange={(e) => setDiscount('discretionaryPct', e.target.value)} />
              <span className="discount-computed" id="discretionary-discount-value">{discValueStr}</span>
            </div>
          </div>
          {showWarning && (
            <div className="discount-warning" id="discount-warning" style={{ display: 'flex' }} aria-live="polite">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
              <span>Combined discount exceeds 35%. Senior underwriter approval required.</span>
            </div>
          )}
        </div>

        <div className="form-group">
          <label className="field-label" htmlFor="manual-override">Manual Premium Override (R) <span className="field-hint-inline">Optional</span></label>
          <CurrencyInput className="form-input" id="manual-override" type="text" inputMode="numeric" placeholder="Leave blank to use calculated premium"
            aria-label="Manual premium override"
            value={activeOpt?.manualOverride ?? ''} onChange={setOverride} />
        </div>

        {condSections.length > 0 && (
          <div className="uw-conditions-panel" id="uw-conditions-panel" style={{ display: 'block' }}>
            <label className="field-label">Underwriting Conditions</label>
            <div className="uw-conditions-content" id="uw-conditions-content">{condSections}</div>
          </div>
        )}

        <div className="form-group" style={{ marginTop: 24 }}>
          <label className="field-label">Endorsements / Underwriter Notes</label>
          <textarea className="form-input endorsements-textarea" id="endorsements" rows={4}
            placeholder="Enter any endorsements, special conditions, or notes to be included on the quote output..."
            value={state.endorsements} onChange={(e) => patch({ endorsements: e.target.value })} />
        </div>

        <div className="comparison-panel" id="comparison-panel">
          <div className="comparison-panel-header">
            <label className="field-label">Compare Against</label>
            <Toggle value={state.compareTarget}
              onChange={(v) => patch({ compareTarget: v })}
              options={[{ value: 'itoo', label: 'Industry' }, { value: 'competitor', label: 'Competitor Quote(s)' }]} />
          </div>

          <div className="comparison-bars" id="comparison-bars" aria-label="Premium comparison visualization">
            {options.map((o) => {
              const calc = derived.optionCalcs[o.id];
              if (!calc) return null;
              let phishieldPremium = state.competitorHasFP ? calc.annual : calc.annualExFP;
              const mo = parseCurrency(o.manualOverride);
              if (mo && mo > 0) phishieldPremium = mo;

              let targetPremium = 0;
              let targetLabel = '';
              if (state.compareTarget === 'itoo') {
                const benchmark = getBenchmark(o.coverIndex);
                if (benchmark) { targetPremium = benchmark.premium; targetLabel = benchmark.label; }
              } else {
                const compRow = state.competitorRows.find((r) => r && r.requestedCoverIndex === o.coverIndex);
                const compPrem = compRow ? parseCurrency(compRow.competitorPremium) : 0;
                if (compPrem > 0) { targetPremium = compPrem; targetLabel = 'Competitor'; }
              }
              if (targetPremium <= 0) return null;

              const maxVal = Math.max(phishieldPremium, targetPremium);
              const phishieldPct = (phishieldPremium / maxVal) * 100;
              const targetPct = (targetPremium / maxVal) * 100;
              const delta = phishieldPremium - targetPremium;
              const deltaPct = Math.round((delta / targetPremium) * 100);
              let barColor = 'var(--success, #2ec4b6)';
              if (delta > 0) barColor = Math.abs(deltaPct) <= 5 ? 'var(--warning, #ffb703)' : 'var(--danger, #e63946)';
              const statusText = delta <= 0
                ? 'Competitive — Phishield is lower'
                : (Math.abs(deltaPct) <= 5 ? 'Close — within 5% of benchmark' : 'Over benchmark');
              const statusClass = delta <= 0 ? 'delta-green' : (Math.abs(deltaPct) <= 5 ? 'delta-amber' : 'delta-red');
              const fpLabel = state.competitorHasFP ? '(with FP)' : '(ex-FP)';
              const diffText = `Difference: ${delta <= 0 ? '' : '+'}${formatR(Math.abs(delta))} (${delta <= 0 ? '' : '+'}${deltaPct}%)`
                + (state.competitorHasFP ? '' : `  |  FP benefit included: ${formatR(calc.fpCost)}`);

              return (
                <div className="comparison-bar" key={o.id}>
                  <div className="comparison-bar-header">
                    <span className="comparison-bar-label">{optionLabel(o.coverIndex, o.fpIndex)} Cover</span>
                    <span className={'bar-status ' + statusClass}>{statusText}</span>
                  </div>
                  <div className="comparison-bar-values">
                    <span className="bar-value-phishield">Phishield {fpLabel}: <strong>{formatR(phishieldPremium)}</strong></span>
                    <span className="bar-value-target">{targetLabel}: <strong>{formatR(targetPremium)}</strong></span>
                  </div>
                  <div className="comparison-bar-track">
                    <div className="bar-target-line" style={{ left: `${targetPct}%` }} title={`${targetLabel}: ${formatR(targetPremium)}`} />
                    <div className="bar-fill" style={{ width: `${phishieldPct}%`, background: barColor }} title={`Phishield ${fpLabel}: ${formatR(phishieldPremium)}`} />
                  </div>
                  <div className={'bar-delta ' + statusClass}>{diffText}</div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="btn-row">
          <button type="button" className="btn btn-ghost" id="backBtn4" aria-label="Back to Compare" onClick={() => goToStep(3)}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-arrow flip"><polyline points="9 18 15 12 9 6" /></svg>
            Back
          </button>
          <button type="button" className="btn btn-primary" id="nextBtn4" aria-label="Continue to Summary" onClick={() => goToStep(5)}>
            Continue to Summary
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-arrow"><polyline points="9 18 15 12 9 6" /></svg>
          </button>
        </div>
      </div>
    </section>
  );
}
