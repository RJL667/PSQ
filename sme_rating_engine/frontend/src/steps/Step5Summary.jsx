import { useMemo, useState } from 'react';
import { INDUSTRIES, COVER_LIMITS, getAvailableFPOptions } from '../rating-data.js';
import { formatR, getItooBenchmark } from '../rating-engine.js';
import { parseCurrency } from '../lib/format.js';
import { optionLabel } from '../lib/options.js';
import { buildQuotePdf, pdfBase64 } from '../lib/pdf.js';
import { saveQuote } from '../lib/api.js';

const QUOTE_TYPE_LABELS = { new: 'New Business', renewal: 'Renewal', competing: 'Competing Quote' };
const RM_FEE_TITLE = "Our administration platform adds a 6% fee on the captured (input) premium. Capture THIS figure on the platform so the client's final premium equals the engine's calculated premium. Formula: Annual (with FP) ÷ 1.06.";

function genQuoteRef() {
  const d = new Date();
  const ymd = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
  const seq = String(Math.floor(1000 + (d.getHours() * 3600 + d.getMinutes() * 60 + d.getSeconds()) % 9000)).padStart(4, '0');
  return `CPB-${ymd}-${seq}`;
}

// A quote option -> the shape lib/pdf.js expects (fraction discounts).
function pdfOption(o) {
  return {
    coverIndex: o.coverIndex, fpIndex: o.fpIndex,
    postureDiscount: (parseFloat(o.posturePct) || 0) / 100,
    discretionaryDiscount: (parseFloat(o.discretionaryPct) || 0) / 100,
  };
}

// Per-option quote ref (legacy getOptionQuoteRef): baseRef-{Cover}-FP{fp}.
function optionRef(baseRef, o) {
  const cl = COVER_LIMITS[o.coverIndex].label.replace(/[\s,]/g, '');
  const afp = getAvailableFPOptions(COVER_LIMITS[o.coverIndex].key);
  const fpL = (o.fpIndex >= 0 && o.fpIndex < afp.length) ? afp[o.fpIndex].label.replace(/[\s,]/g, '') : 'BaseFP';
  return `${baseRef}-${cl}-FP${fpL}`;
}

export default function Step5Summary({ state, patch, derived, goToStep }) {
  const quoteRef = useMemo(() => state.quoteRef || genQuoteRef(), [state.quoteRef]);
  const [saveStatus, setSaveStatus] = useState(null);
  const options = state.quoteOptions;
  const industry = state.industryIndex >= 0 ? INDUSTRIES[state.industryIndex] : null;
  const uw = derived.uw;

  const outcomeLabels = {
    standard: 'Standard Rates',
    caution: 'Proceed with Caution',
    loading: `${Math.round(uw.loadingPct * 100)}% Loading`,
    decline: 'Declined',
    refer: 'Refer to Senior UW',
  };
  const getBenchmark = (ci) => {
    if (state.quoteType === 'renewal' && derived.renewalPremiumNum > 0) {
      return { premium: derived.renewalPremiumNum, label: 'Existing Policy' };
    }
    const itoo = getItooBenchmark(derived.actualTurnover, ci);
    return itoo ? { premium: itoo.premium, label: 'Industry Benchmark' } : null;
  };
  const deltaLabel = state.quoteType === 'renewal' ? 'Delta vs Existing' : 'Delta vs Industry';

  // Conditions of cover: Q1 baseline controls, then FP conditions, then prior claim.
  let allConditions = [...(uw.q1Conditions || []), ...(uw.fpConditions || [])];
  if (state.priorClaim) allConditions.push('Prior claim: additional underwriting required');

  function downloadPdf(o) {
    const { doc, filename } = buildQuotePdf({ state, derived, quoteRef: optionRef(quoteRef, o), option: pdfOption(o) });
    doc.save(filename);
  }
  function downloadAll() {
    // Browsers collapse/block multiple downloads fired together. Trigger the
    // first inside the click gesture (always allowed), then stagger the rest ~1s
    // apart (matches the legacy generateAllPDFs) so each is processed separately.
    options.forEach((o, i) => {
      if (i === 0) downloadPdf(o);
      else setTimeout(() => downloadPdf(o), i * 1000);
    });
  }
  function buildPayload() {
    const first = options[0];
    let pdfB64 = null;
    if (first) {
      const { doc } = buildQuotePdf({ state, derived, quoteRef: optionRef(quoteRef, first), option: pdfOption(first) });
      pdfB64 = pdfBase64(doc);
    }
    return {
      quoteRef, baseRef: quoteRef, companyName: state.companyName,
      industryMain: industry ? industry.main : '', industrySub: industry ? industry.sub : '',
      turnoverPrev: derived.prev, turnoverCurrent: derived.current, actualTurnover: derived.actualTurnover,
      revenueBand: derived.bandLabel, employeeCount: parseInt(state.employeeCount, 10) || 0,
      quoteType: state.quoteType, marketCondition: 'Softening market for 2026',
      priorClaim: state.priorClaim, uwAnswers: state.uwAnswers, uwOutcome: uw.outcome,
      uwLoadingPct: uw.loadingPct, uwConditions: allConditions, endorsements: state.endorsements,
      coverSelections: options.map((o) => {
        const calc = derived.optionCalcs[o.id] || {};
        const fp = getAvailableFPOptions(COVER_LIMITS[o.coverIndex].key)[o.fpIndex];
        return { coverIndex: o.coverIndex, coverLabel: COVER_LIMITS[o.coverIndex].label, fpLabel: fp ? fp.label : '', ...calc };
      }),
      postureDiscount: options[0] ? (parseFloat(options[0].posturePct) || 0) / 100 : 0,
      discretionaryDiscount: options[0] ? (parseFloat(options[0].discretionaryPct) || 0) / 100 : 0,
      competitorName: state.competitorName, competitorData: state.competitorRows,
      renewalCoverLimit: state.renewalCoverIndex >= 0 ? COVER_LIMITS[state.renewalCoverIndex].label : '',
      renewalPremium: derived.renewalPremiumNum, coverLabel: first ? COVER_LIMITS[first.coverIndex].label : 'quote',
      createdBy: state.createdBy || '', pdfBase64: pdfB64,
    };
  }
  async function saveNow() {
    setSaveStatus('saving');
    try { await saveQuote(buildPayload()); if (!state.quoteRef) patch({ quoteRef }); setSaveStatus('saved'); }
    catch { setSaveStatus('error'); }
  }
  function copyClipboard() {
    const lines = [`Phishield SME Cyber Quote — ${quoteRef}`, `Company: ${state.companyName}`,
      `Industry: ${industry ? industry.sub : '—'}`, `Turnover: ${formatR(derived.actualTurnover)} (${derived.bandLabel})`, `UW: ${uw.outcome}`, ''];
    options.forEach((o) => {
      const c = derived.optionCalcs[o.id]; if (!c) return;
      lines.push(`${optionLabel(o.coverIndex, o.fpIndex)}: R${c.annual.toLocaleString('en-ZA')}/yr · R${c.monthly.toLocaleString('en-ZA')}/mo`);
    });
    navigator.clipboard?.writeText(lines.join('\n'));
  }

  const isMulti = options.length >= 2;

  return (
    <section className="step-panel active" id="step-5">
      <div className="glass-card">
        <div className="step-header">
          <h2>Quote Summary</h2>
          <p>Review the full quote breakdown before exporting.</p>
        </div>

        <div className="quote-ref" id="quote-ref" aria-label="Quote reference number">{quoteRef}</div>

        {state.quoteType === 'renewal' && (
          <div className="market-badge summary-market-badge" id="summary-market-badge" style={{ display: 'flex' }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M23 6l-9.5 9.5-5-5L1 18" /><polyline points="17 6 23 6 23 12" /></svg>
            <span>Softening market for 2026</span>
          </div>
        )}

        <div className="summary-section" id="client-summary">
          <h3>Client Details</h3>
          <div className="summary-grid">
            <SItem label="Company" value={state.companyName || '--'} />
            <SItem label="Industry" value={industry ? `${industry.main} — ${industry.sub}` : '--'} />
            <SItem label="Turnover" value={derived.actualTurnover > 0 ? formatR(derived.actualTurnover) : '--'} />
            <SItem label="Revenue Bracket" value={derived.bandLabel || '--'} />
            <SItem label="Website" value={state.websiteAddress || '--'} />
            <SItem label="Quote Type" value={QUOTE_TYPE_LABELS[state.quoteType] || '--'} />
          </div>
        </div>

        <div className="summary-section" id="uw-summary">
          <h3>Underwriting</h3>
          <div className="summary-grid">
            <SItem label="UW Outcome" value={outcomeLabels[uw.outcome] || '--'} />
            <SItem label="Loadings" value={uw.loadingPct > 0 ? `${Math.round(uw.loadingPct * 100)}%` : 'None'} />
            <div className="summary-item">
              <div className="summary-label">Conditions of Cover</div>
              <div className="summary-value" id="sum-uw-conditions">
                {allConditions.length > 0
                  ? <ol className="sum-conditions-list">{allConditions.map((c, i) => <li key={i}>{c}</li>)}</ol>
                  : 'None'}
              </div>
            </div>
          </div>
        </div>

        {state.priorClaim && (
          <div className="prior-claim-note" id="sum-prior-claim" style={{ display: 'flex' }} aria-live="polite">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
            <span>Prior claim flagged. Additional underwriting review applied.</span>
          </div>
        )}

        {state.endorsements.trim() && (
          <div className="summary-section" id="sum-endorsements-section" style={{ display: 'block' }}>
            <h3>Endorsements / Notes</h3>
            <div className="summary-endorsements" id="sum-endorsements">{state.endorsements.trim()}</div>
          </div>
        )}

        <div className="quote-breakdowns" id="quote-breakdowns">
          {options.map((o) => {
            const calc = derived.optionCalcs[o.id];
            if (!calc) return null;
            const benchmark = getBenchmark(o.coverIndex);
            const compRow = state.competitorRows.find((r) => r && r.requestedCoverIndex === o.coverIndex);
            const optRef = optionRef(quoteRef, o);
            const benchLabel = benchmark ? benchmark.label : (state.quoteType === 'renewal' ? 'Existing Policy' : 'Industry Benchmark');
            const benchStr = benchmark ? formatR(benchmark.premium) : '--';
            const compPrem = compRow ? parseCurrency(compRow.competitorPremium) : 0;
            const compStr = compPrem > 0 ? formatR(compPrem) : '--';
            const compareAmount = state.competitorHasFP ? calc.annual : calc.annualExFP;
            const compareLabel = state.competitorHasFP ? 'with FP' : 'excl FP';
            let deltaStr = '--';
            let deltaClass = '';
            if (benchmark) {
              const d = compareAmount - benchmark.premium;
              deltaStr = `${d <= 0 ? '' : '+'}${formatR(Math.abs(d))} (${d <= 0 ? '' : '+'}${Math.round(d / benchmark.premium * 100)}%)`;
              deltaClass = compareAmount <= benchmark.premium ? 'text-success' : 'text-danger';
            }
            return (
              <div className="quote-breakdown-card" key={o.id}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 8 }}>Ref: {optRef}</div>
                <div className="breakdown-header">
                  <h4>{optionLabel(o.coverIndex, o.fpIndex)}</h4>
                  {calc.isMicro && <span className="micro-label">Micro SME</span>}
                </div>
                <table className="audit-trail">
                  <thead><tr><th>Step</th><th>Description</th><th className="text-right">Value</th></tr></thead>
                  <tbody>{calc.breakdown.map((b, i) => (
                    <tr key={i}><td>{b.step}</td><td>{b.desc}</td><td>{formatR(b.value)}</td></tr>
                  ))}</tbody>
                </table>
                <div className="breakdown-finals">
                  <div className="breakdown-final-item">
                    <span className="bf-label">Annual (with FP)</span>
                    <strong className="bf-value accent">{formatR(calc.annual)}</strong>
                  </div>
                  <div className="breakdown-final-item">
                    <span className="bf-label">Annual (excl FP)</span>
                    <strong className="bf-value">{formatR(calc.annualExFP)}</strong>
                  </div>
                  <div className="breakdown-final-item">
                    <span className="bf-label">Monthly</span>
                    <strong className="bf-value accent">{formatR(calc.monthly)}</strong>
                  </div>
                </div>
                <div className="breakdown-rm-fee" title={RM_FEE_TITLE}>
                  <span className="rm-fee-label">Total Premium without RM Fee</span>
                  <div className="rm-fee-figures">
                    <strong className="rm-fee-value">{formatR(calc.annual / 1.06)}<span className="rm-fee-unit">/yr</span></strong>
                    <strong className="rm-fee-value">{formatR(Math.ceil((calc.annual / 1.06) / 12))}<span className="rm-fee-unit">/mo</span></strong>
                  </div>
                </div>
                <div className="breakdown-comparison">
                  <div className="bc-item"><span className="bc-label">{benchLabel}</span><strong>{benchStr}</strong></div>
                  <div className="bc-item"><span className="bc-label">Competitor</span><strong>{compStr}</strong></div>
                  <div className="bc-item"><span className="bc-label">{deltaLabel} ({compareLabel})</span><strong className={deltaClass}>{deltaStr}</strong></div>
                </div>
                {isMulti && (
                  <div className="btn-row" style={{ marginTop: 8 }}>
                    <button type="button" className="btn btn-ghost" onClick={() => downloadPdf(o)}>Download this PDF</button>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div className="btn-row">
          <button type="button" className="btn btn-ghost" id="backBtn5" aria-label="Back to Adjustments" onClick={() => goToStep(4)}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-arrow flip"><polyline points="9 18 15 12 9 6" /></svg>
            Back
          </button>
        </div>

        <div className="btn-row">
          <button type="button" className="btn btn-primary btn-print" id="btn-print" aria-label="Print quote" onClick={() => window.print()}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 6 2 18 2 18 9" /><path d="M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2" /><rect x="6" y="14" width="12" height="8" /></svg>
            Print Quote
          </button>
          <button type="button" className="btn btn-ghost btn-clipboard" id="btn-clipboard" aria-label="Copy to clipboard" onClick={copyClipboard}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" /></svg>
            Copy to Clipboard
          </button>
          {!isMulti && (
            <button type="button" className="btn btn-primary btn-download-pdf" id="btn-download-pdf" aria-label="Download PDF" disabled={!options[0]} onClick={() => downloadPdf(options[0])}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
              Download PDF
            </button>
          )}
          {isMulti && (
            <button type="button" className="btn btn-download-all" id="btn-download-all-pdfs" aria-label="Download All PDFs" onClick={downloadAll}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
              Download All PDFs
            </button>
          )}
          <button type="button" className="btn btn-primary btn-save-quote" aria-label="Save quote" disabled={!options[0] || saveStatus === 'saving'} onClick={saveNow}>
            {saveStatus === 'saved' ? 'Saved ✓' : saveStatus === 'saving' ? 'Saving…' : saveStatus === 'error' ? 'Save failed — retry' : 'Save Quote'}
          </button>
        </div>

        <p className="footer-note-internal">Internal use only. Premiums are indicative and subject to final underwriting approval.</p>
      </div>
    </section>
  );
}

function SItem({ label, value }) {
  return (
    <div className="summary-item">
      <div className="summary-label">{label}</div>
      <div className="summary-value">{value}</div>
    </div>
  );
}
