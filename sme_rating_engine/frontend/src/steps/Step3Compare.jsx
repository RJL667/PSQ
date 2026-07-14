import { COVER_LIMITS, COVER_AVAILABILITY } from '../rating-data.js';
import { formatR, getItooBenchmark } from '../rating-engine.js';
import { optionLabel } from '../lib/options.js';
import Toggle from '../components/Toggle.jsx';
import CurrencyInput from '../components/CurrencyInput.jsx';

// Requested-cover-limit dropdown options (verbatim from the legacy markup).
const COVER_SELECT_OPTIONS = [
  { value: 1000000, label: 'R1,000,000' },
  { value: 2500000, label: 'R2,500,000' },
  { value: 5000000, label: 'R5,000,000' },
  { value: 7500000, label: 'R7,500,000' },
  { value: 10000000, label: 'R10,000,000' },
  { value: 15000000, label: 'R15,000,000' },
];

export default function Step3Compare({ state, patch, derived, goToStep }) {
  const options = state.quoteOptions;
  const isMulti = options.length >= 2;
  const band = derived.revenueBandIndex;

  // Comparison-table column labels (renewal vs new business).
  const benchmarkLabel = state.quoteType === 'renewal' ? 'Existing Policy' : 'Industry Benchmark';
  const deltaLabel = state.quoteType === 'renewal' ? 'Delta vs Existing' : 'Delta vs Industry';
  const compLabel = state.competitorHasFP ? 'Phishield (with FP)' : 'Phishield (ex-FP)';

  // getBenchmark(): existing policy premium for renewals, else IToo industry benchmark.
  const getBenchmark = (ci) => {
    if (state.quoteType === 'renewal' && derived.renewalPremiumNum > 0) {
      return { premium: derived.renewalPremiumNum };
    }
    const itoo = getItooBenchmark(derived.actualTurnover, ci);
    return itoo ? { premium: itoo.premium } : null;
  };

  // Each competitor row's selected cover defaults to its quote option's cover.
  const rowCoverIdx = (idx) => {
    const r = state.competitorRows[idx];
    const stored = r && Number.isInteger(r.requestedCoverIndex) ? r.requestedCoverIndex : null;
    return stored != null ? stored : options[idx].coverIndex;
  };
  const setRowCover = (idx, coverIdx) => {
    const rows = state.competitorRows.slice();
    rows[idx] = { ...(rows[idx] || {}), requestedCoverIndex: coverIdx };
    patch({ competitorRows: rows });
  };
  const setRowField = (idx, field, val) => {
    const rows = state.competitorRows.slice();
    rows[idx] = { ...(rows[idx] || {}), [field]: val };
    patch({ competitorRows: rows });
  };

  // Row match status: Matched if available for the band, else nearest suggestions.
  const rowStatus = (coverIdx) => {
    if (band < 0 || !Number.isInteger(coverIdx)) return null;
    if (COVER_AVAILABILITY[band][coverIdx]) return <span className="status-matched">Matched</span>;
    const closest = [];
    for (let i = coverIdx - 1; i >= 0 && closest.length < 1; i--) if (COVER_AVAILABILITY[band][i]) closest.unshift(i);
    for (let i = coverIdx + 1; i < COVER_LIMITS.length && closest.length < 2; i++) if (COVER_AVAILABILITY[band][i]) closest.push(i);
    const suggestions = closest.map((ci) => COVER_LIMITS[ci].label).join(', ');
    return (
      <>
        <span className="status-na">Not Available</span> <span className="status-suggest">Suggested: {suggestions}</span>
      </>
    );
  };

  return (
    <section className="step-panel active" id="step-3">
      <div className="glass-card">
        <div className="step-header">
          <h2>Competitor Quotes &amp; Benchmarking</h2>
          <p>Compare Phishield pricing against competitor quotes and Industry benchmarks.</p>
        </div>

        {isMulti && (
          <div className="options-summary-bar" id="step3-option-tabs" aria-label="Quote option tabs">
            <span className="options-summary-label">Quoting:</span>{' '}
            {options.map((o) => (
              <span className="options-summary-item" key={o.id}>{optionLabel(o.coverIndex, o.fpIndex)}</span>
            ))}
          </div>
        )}

        <div id="step3-tab-panels">
          <div className="step3-section">
            <label className="field-label section-label">Competitor Comparison</label>
            <div className="form-grid" style={{ marginBottom: 16 }}>
              <div className="form-group">
                <label className="field-label" htmlFor="competitor-name-step3">Competitor / Provider Name</label>
                <input className="form-input" id="competitor-name-step3" type="text" placeholder="e.g. Guardrisk / Chubb"
                  aria-label="Competitor name" value={state.competitorName}
                  onChange={(e) => patch({ competitorName: e.target.value })} />
              </div>
              <div className="form-group" style={{ display: isMulti ? 'none' : undefined }}>
                <label className="field-label" htmlFor="num-cover-limits">Number of cover limits to compare</label>
                <select className="form-select" id="num-cover-limits" aria-label="Number of cover limits"
                  value={String(options.length || 1)} onChange={() => {}}>
                  <option value="1">1</option>
                  <option value="2">2</option>
                  <option value="3">3</option>
                  <option value="4">4</option>
                </select>
              </div>
            </div>

            <div className="form-grid" style={{ marginBottom: 16 }}>
              <div className="form-group">
                <label className="field-label">Does the client have existing quote(s) for comparison?</label>
                <Toggle value={state.hasExistingQuotes ? 'yes' : 'no'}
                  onChange={(v) => patch({ hasExistingQuotes: v === 'yes' })}
                  options={[{ value: 'no', label: 'No' }, { value: 'yes', label: 'Yes' }]} />
              </div>
              <div className="form-group">
                <label className="field-label">Does the competitor quote include a FP equivalent?</label>
                <Toggle value={state.competitorHasFP ? 'yes' : 'no'}
                  onChange={(v) => patch({ competitorHasFP: v === 'yes' })}
                  options={[{ value: 'no', label: 'No' }, { value: 'yes', label: 'Yes' }]} />
              </div>
            </div>

            <div className="competitor-rows" id="competitor-rows">
              {options.map((o, idx) => {
                const selCover = rowCoverIdx(idx);
                const row = state.competitorRows[idx] || {};
                return (
                  <div className="competitor-row" data-row-index={idx} key={o.id}>
                    <div className="competitor-row-header">QUOTE OPTION {idx + 1}: {optionLabel(o.coverIndex, o.fpIndex)}</div>
                    <div className="form-grid">
                      <div className="form-group">
                        <label className="field-label">Requested Cover Limit</label>
                        <select className="form-select competitor-cover-select" aria-label="Requested cover limit"
                          value={String(COVER_LIMITS[selCover].value)}
                          onChange={(e) => setRowCover(idx, COVER_LIMITS.findIndex((cl) => cl.value === parseInt(e.target.value, 10)))}>
                          <option value="" disabled>Select cover limit</option>
                          {COVER_SELECT_OPTIONS.map((c) => (
                            <option value={String(c.value)} key={c.value}>{c.label}</option>
                          ))}
                        </select>
                      </div>
                      <div className="form-group" style={{ display: state.hasExistingQuotes ? 'block' : 'none' }}>
                        <label className="field-label">Competitor Overall Limit (R)</label>
                        <CurrencyInput className="form-input competitor-limit-input" type="text" inputMode="numeric"
                          placeholder="e.g. 5,000,000" aria-label="Competitor overall limit"
                          value={row.competitorLimit || ''} onChange={(v) => setRowField(idx, 'competitorLimit', v)} />
                      </div>
                      <div className="form-group" style={{ display: state.hasExistingQuotes ? 'block' : 'none' }}>
                        <label className="field-label">Competitor Premium (R)</label>
                        <CurrencyInput className="form-input competitor-premium-input" type="text" inputMode="numeric"
                          placeholder="e.g. 22,000" aria-label="Competitor premium"
                          value={row.competitorPremium || ''} onChange={(v) => setRowField(idx, 'competitorPremium', v)} />
                      </div>
                    </div>
                    <div className="competitor-status" aria-live="polite">{rowStatus(selCover)}</div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <div className="step3-section" id="step3-all-options-summary" style={{ marginTop: 28 }}>
          <label className="field-label section-label">Industry Benchmark Comparison</label>
        </div>
        <div className="comparison-table" id="comparison-table">
          <table>
            <thead>
              <tr>
                <th>Cover Limit</th>
                <th>Phishield (with FP)</th>
                <th>{compLabel}</th>
                <th>{benchmarkLabel}</th>
                <th>{deltaLabel}</th>
              </tr>
            </thead>
            <tbody id="comparison-tbody">
              {options.map((o) => {
                const calc = derived.optionCalcs[o.id];
                if (!calc) return null;
                const phishieldCompare = state.competitorHasFP ? calc.annual : calc.annualExFP;
                const benchmark = getBenchmark(o.coverIndex);
                const benchStr = benchmark ? formatR(benchmark.premium) : '--';
                const delta = benchmark ? phishieldCompare - benchmark.premium : null;
                const deltaStr = delta !== null
                  ? `${delta >= 0 ? '+' : ''}${formatR(Math.abs(delta))} (${delta >= 0 ? '+' : '-'}${Math.abs(Math.round(delta / benchmark.premium * 100))}%)`
                  : '--';
                const deltaClass = delta !== null
                  ? (delta <= 0 ? 'delta-green' : (Math.abs(delta / benchmark.premium) <= 0.05 ? 'delta-amber' : 'delta-red'))
                  : '';
                return (
                  <tr key={o.id}>
                    <td>{optionLabel(o.coverIndex, o.fpIndex)}</td>
                    <td>{formatR(calc.annual)}</td>
                    <td>{formatR(phishieldCompare)}</td>
                    <td>{benchStr}</td>
                    <td className={deltaClass}>{deltaStr}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <div className="btn-row">
          <button type="button" className="btn btn-ghost" id="backBtn3" aria-label="Back to Coverage" onClick={() => goToStep(2)}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-arrow flip"><polyline points="9 18 15 12 9 6" /></svg>
            Back
          </button>
          <button type="button" className="btn btn-primary" id="nextBtn3" aria-label="Continue to Adjustments" onClick={() => goToStep(4)}>
            Continue to Adjust
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-arrow"><polyline points="9 18 15 12 9 6" /></svg>
          </button>
        </div>
      </div>
    </section>
  );
}
