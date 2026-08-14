import { useState } from 'react'
import Panel from '../primitives/Panel'
import { getRiskFactors } from '../../data/selectors'
import { SEVERITY_COLOR } from '../../data/checkerState'
import type { Results } from '../../types/results'
import styles from './RiskFactors.module.css'

/** Name of the posture axis. "Resilience" because the number RISES as the
 *  estate gets safer: calling a higher-is-better figure a "risk score" is the
 *  same inversion trap as `dehashed 0` meaning worst, or `+70` reading as
 *  additive -- both of which were misread this week by the people who built
 *  them. Reads naturally per area too: "network resilience score". */
const SCORE_NAME = 'Resilience score'

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
                {/* TWO AXES, side by side, because neither works alone.
                    Across all 36 scans, worst-member-only puts 79.6% of
                    dimensions on High/Critical while a weighted average puts
                    85.2% on Low/Medium and finds 2 criticals in 142. One cries
                    wolf, the other never alarms. The score prices the estate;
                    the blocker gates it. */}
                <span className={styles.riskLabel} style={{ color: SEVERITY_COLOR[f.severity] }}>{f.riskLabel}</span>
                <span className={styles.impact}>
                  {f.score != null && (
                    <span className={styles.scoreNum} title={`${f.label} resilience score: the weighted average across the ${f.assessed} categories that produced a verdict, where higher is safer. Separate from the risk label beside it, which is set by the single worst finding.`}>
                      {f.score}
                    </span>
                  )}
                  {f.blockers.length > 0 && (
                    <span className={styles.blocker} style={{ color: SEVERITY_COLOR[f.severity] }}
                      title={`${f.blockers.length} finding(s) at high or critical severity set the label regardless of the score: ${f.blockers.join(', ')}`}>
                      {f.blockers.length}&nbsp;blocker{f.blockers.length > 1 ? 's' : ''}
                    </span>
                  )}
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
          : `Two separate measures. The number is the ${SCORE_NAME.toLowerCase()} for that area — a weighted average across every category assessed, where higher is safer. The label beside it is set by the single worst finding, matching that category’s card in the PDF report, so one confirmed exposure is never averaged away by clean siblings. A well-run area can therefore score highly and still carry a blocker; hover a blocker to see which finding set it.`}
      </div>
    </Panel>
  )
}
