import { Wrench, ScanSearch } from 'lucide-react'
import Panel from '../primitives/Panel'
import { SeverityDot } from '../primitives/Status'
import { fmtZar, fmtRatioPct } from '../../data/results'
import { getRemediationActions } from '../../data/selectors'
import { SEVERITY_LABEL } from '../../data/checkerState'
import type { Results } from '../../types/results'
import styles from './RemediationQueue.module.css'

export default function RemediationQueue({ r }: { r: Results }) {
  const { actions, projection } = getRemediationActions(r)
  const showProjection = projection.simulatedRsi != null || projection.totalSavings != null

  return (
    <Panel
      title="Remediation Priority Queue"
      action={<span className={styles.count}>{actions.length} actions</span>}
      flush
    >
      <div className={styles.scroll}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={styles.rank}>#</th>
              <th>Priority</th>
              <th>Action</th>
              <th className={styles.num}>RSI ↓</th>
              <th>Effort</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {actions.map((a) => (
              <tr key={a.rank} className={a.kind === 'scan_quality' ? styles.quality : ''}>
                <td className={styles.rank}>{a.rank}</td>
                <td>
                  <span className={styles.prio}>
                    <SeverityDot severity={a.severity} />
                    {a.kind === 'scan_quality' ? 'Scan quality' : SEVERITY_LABEL[a.severity]}
                  </span>
                </td>
                <td className={styles.action}>
                  <span className={styles.actIcon}>{a.kind === 'scan_quality' ? <ScanSearch size={13} /> : <Wrench size={13} />}</span>
                  {a.title}
                </td>
                <td className={styles.num}>{a.rsiReduction != null ? `−${fmtRatioPct(a.rsiReduction, 1)}` : '—'}</td>
                <td><span className={styles.effort}>{a.effort}</span></td>
                <td><span className={styles.status}>{a.status}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {showProjection && (
        <div className={styles.projection}>
          <div><span>Projected RSI</span><strong>{projection.simulatedRsi != null ? projection.simulatedRsi.toFixed(3) : '—'}</strong></div>
          <div><span>Projected annual loss</span><strong>{fmtZar(projection.projectedLoss)}</strong></div>
          <div><span>Total reduction</span><strong style={{ color: 'var(--positive)' }}>{fmtZar(projection.totalSavings)}</strong></div>
        </div>
      )}
    </Panel>
  )
}
