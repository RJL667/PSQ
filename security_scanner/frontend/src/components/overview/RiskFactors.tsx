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
            <div className={styles.label}>{f.label}</div>
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
                <span className={styles.impact}>{f.impact != null ? `+${f.impact}` : '—'}</span>
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
          : 'Dimension scores are a deterministic roll-up of category scores (higher = safer); impact = remaining risk.'}
      </div>
    </Panel>
  )
}
