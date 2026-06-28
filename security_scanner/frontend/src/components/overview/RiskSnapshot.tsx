import { ChevronRight } from 'lucide-react'
import Panel from '../primitives/Panel'
import { SeverityDot } from '../primitives/Status'
import { getRiskSnapshot } from '../../data/selectors'
import { SEVERITY_COLOR } from '../../data/checkerState'
import type { Results } from '../../types/results'
import styles from './RiskSnapshot.module.css'

export default function RiskSnapshot({ r, onDrill }: { r: Results; onDrill: (cat: string) => void }) {
  const rows = getRiskSnapshot(r)
  return (
    <Panel title="Risk Snapshot" fill flush>
      <ul className={styles.list}>
        {rows.map((row) => (
          <li key={row.id}>
            <button className={styles.row} type="button" onClick={() => onDrill(row.drill)}>
              <SeverityDot severity={row.severity} />
              <span className={styles.label}>{row.label}</span>
              <span className={styles.value} style={{ color: SEVERITY_COLOR[row.severity] }}>{row.value}</span>
              <ChevronRight size={14} className={styles.chev} />
            </button>
          </li>
        ))}
      </ul>
    </Panel>
  )
}
