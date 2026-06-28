import Panel from '../primitives/Panel'
import EmptyState from '../primitives/EmptyState'
import { getComplianceSummary } from '../../data/selectors'
import type { Results } from '../../types/results'
import styles from './ComplianceMatrix.module.css'

function alignColor(pct: number | null): string {
  if (pct == null) return 'var(--unknown)'
  if (pct >= 75) return 'var(--positive)'
  if (pct >= 50) return 'var(--warning)'
  return 'var(--high)'
}

export default function ComplianceMatrix({ r }: { r: Results }) {
  const rows = getComplianceSummary(r)
  return (
    <Panel title="Compliance Framework Mapping" flush>
      {rows.length === 0 ? (
        <div className={styles.pad}><EmptyState title="Compliance mapping unavailable">Framework alignment was not computed for this scan.</EmptyState></div>
      ) : (
        <div className={styles.scroll}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Framework</th>
                <th className={styles.alignCol}>Alignment</th>
                <th className={styles.num}>Passed</th>
                <th className={styles.num}>Partial</th>
                <th className={styles.num}>Failed</th>
                <th className={styles.num}>Not assessed</th>
                <th className={styles.num}>Evidence</th>
                <th>Highest-priority gap</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.name}>
                  <td className={styles.fw}>{f.name}</td>
                  <td>
                    <div className={styles.align}>
                      <span className={styles.alignTrack}><span style={{ width: `${f.alignmentPct ?? 0}%`, background: alignColor(f.alignmentPct) }} /></span>
                      <span className={styles.alignPct} style={{ color: alignColor(f.alignmentPct) }}>{f.alignmentPct != null ? `${f.alignmentPct}%` : '—'}</span>
                    </div>
                  </td>
                  <td className={`${styles.num} ${styles.pass}`}>{f.passed}</td>
                  <td className={`${styles.num} ${styles.partial}`}>{f.partial}</td>
                  <td className={`${styles.num} ${styles.fail}`}>{f.failed}</td>
                  <td className={`${styles.num} ${styles.na}`}>{f.notAssessed}</td>
                  <td className={styles.num}>{f.evidenceCoverage}%</td>
                  <td className={styles.gap}>{f.topGap ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}
