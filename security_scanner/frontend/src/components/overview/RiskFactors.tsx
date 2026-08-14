import { useState } from 'react'
import Panel from '../primitives/Panel'
import { getRiskFactors } from '../../data/selectors'
import { SEVERITY_COLOR } from '../../data/checkerState'
import type { Results } from '../../types/results'
import styles from './RiskFactors.module.css'

type View = 'impact' | 'underwriting' | 'technical'
const VIEWS: Array<{ key: View; label: string }> = [
  { key: 'impact', label: 'Impact View' },
  { key: 'underwriting', label: 'Underwriting View' },
  { key: 'technical', label: 'Technical View' },
]

export default function RiskFactors({ r }: { r: Results }) {
  const [view, setView] = useState<View>('impact')
  const factors = getRiskFactors(r)

  return (
    <Panel
      title="Risk Factors"
      fill
      action={
        <div className={styles.tabs} role="tablist">
          {VIEWS.map((v) => (
            <button key={v.key} role="tab" aria-selected={view === v.key}
              className={`${styles.tab} ${view === v.key ? styles.tabActive : ''}`}
              onClick={() => setView(v.key)}>{v.label.replace(' View', '')}</button>
          ))}
        </div>
      }
    >
      <div className={styles.list}>
        {factors.map((f) => (
          <div className={styles.row} key={f.key}>
            {/* Show the denominator. A dimension is defined over up to four
                categories but only conclusive ones are averaged, so
                "Network Exposure — Low" can rest on a single checker while
                reading as a verdict on all four. Green on thin coverage is the
                dangerous direction: nobody challenges green. */}
            <div className={styles.label}>
              {f.label}
              {f.assessed < f.total && (
                <span className={styles.coverage} title={`${f.assessed} of ${f.total} categories in this dimension produced a verdict`}>
                  {' '}{f.assessed}/{f.total} assessed
                </span>
              )}
            </div>
            <div className={styles.barWrap}>
              <div className={styles.barTrack}>
                <div className={styles.barFill} style={{
                  width: `${f.score ?? 0}%`,
                  background: SEVERITY_COLOR[f.severity],
                }} />
              </div>
            </div>
            {view === 'impact' && (
              <>
                <span className={styles.riskLabel} style={{ color: SEVERITY_COLOR[f.severity] }}>{f.riskLabel}</span>
                {/* The category whose own PDF card set this verdict. More use
                    than the number that used to sit here, which was only the
                    bar inverted and read as an additive contribution it never
                    was: on one scan the five values summed to 326 against an
                    overall score of 251. */}
                <span className={styles.impact} title={`This verdict comes from ${f.topContributor}, matching that category's card in the PDF report`}>
                  {f.topContributor}
                </span>
              </>
            )}
            {view === 'underwriting' && (
              <>
                <span className={styles.riskLabel} style={{ color: SEVERITY_COLOR[f.severity] }}>{f.riskLabel}</span>
                <span className={styles.score}>{f.score != null ? `${f.score}/100` : 'n/a'}</span>
              </>
            )}
            {view === 'technical' && (
              <span className={styles.contributor} title={f.topContributor}>{f.topContributor}</span>
            )}
          </div>
        ))}
      </div>
      <div className={styles.footnote}>
        {view === 'technical'
          ? 'Top contributor per dimension, from completed checkers.'
          : 'Each dimension takes the verdict of its weakest category, matching that category’s card in the PDF report — a confirmed exposure is not averaged away by clean siblings. The name on the right is the category that set the verdict. Where fewer categories produced a verdict than the dimension covers, the count is shown.'}
      </div>
    </Panel>
  )
}
