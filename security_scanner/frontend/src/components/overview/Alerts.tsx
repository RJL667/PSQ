import { ShieldAlert, AlertTriangle, Database, Network } from 'lucide-react'
import Panel from '../primitives/Panel'
import { getCriticalAlerts, type Alert } from '../../data/selectors'
import { fmtRelative } from '../../data/results'
import { SEVERITY_COLOR, SEVERITY_SOFT } from '../../data/checkerState'
import EmptyState from '../primitives/EmptyState'
import type { Results, Severity } from '../../types/results'
import styles from './Alerts.module.css'

const ALERT_ICON: Record<string, typeof ShieldAlert> = {
  db_port: Database, waf: ShieldAlert, services: Network,
}
const STATE_STYLE: Record<Alert['state'], string> = {
  new: styles.stNew, open: styles.stOpen, acknowledged: styles.stAck, resolved: styles.stResolved, suppressed: styles.stSup,
}

export default function Alerts({ r, onDrill }: { r: Results; onDrill: (cat: string) => void }) {
  const alerts = getCriticalAlerts(r)
  return (
    <Panel title="Critical Alerts" action={<span className={styles.count}>{alerts.length}</span>} fill flush>
      {alerts.length === 0 ? (
        <div className={styles.pad}><EmptyState compact title="No critical alerts">No active critical alerts from this scan.</EmptyState></div>
      ) : (
        <ul className={styles.list}>
          {alerts.map((a) => {
            const Icon = ALERT_ICON[a.id] ?? AlertTriangle
            const sev: Severity = a.severity
            return (
              <li key={a.id}>
                <button className={styles.row} type="button" onClick={() => onDrill(a.drill === 'coverage' ? 'coverage' : a.drill)}>
                  <span className={styles.icon} style={{ color: SEVERITY_COLOR[sev], background: SEVERITY_SOFT[sev] }}><Icon size={15} /></span>
                  <span className={styles.body}>
                    <span className={styles.titleRow}>
                      <span className={styles.title}>{a.title}</span>
                      <span className={`${styles.state} ${STATE_STYLE[a.state]}`}>{a.state}</span>
                    </span>
                    <span className={styles.detail}>{a.detail}</span>
                    <span className={styles.time}>{fmtRelative(a.timestamp)}</span>
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </Panel>
  )
}
