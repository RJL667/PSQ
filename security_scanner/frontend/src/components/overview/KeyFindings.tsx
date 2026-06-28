import { ChevronRight, ShieldAlert, AlertTriangle, CheckCircle2, ShieldQuestion } from 'lucide-react'
import Panel from '../primitives/Panel'
import { SeverityBadge } from '../primitives/Status'
import { getKeyFindings } from '../../data/selectors'
import { SEVERITY_COLOR, SEVERITY_SOFT } from '../../data/checkerState'
import type { Severity, Results } from '../../types/results'
import styles from './KeyFindings.module.css'

const ICON: Partial<Record<Severity, typeof ShieldAlert>> = {
  critical: ShieldAlert, high: AlertTriangle, medium: AlertTriangle, positive: CheckCircle2,
}

export default function KeyFindings({ r, onDrill }: { r: Results; onDrill: (key: string) => void }) {
  const findings = getKeyFindings(r)
  return (
    <Panel title="Key Findings" action={<span className={styles.count}>{findings.length}</span>} fill flush>
      <ul className={styles.list}>
        {findings.map((f) => {
          const Icon = f.isCoverage ? ShieldQuestion : (ICON[f.severity] ?? AlertTriangle)
          return (
            <li key={f.id}>
              <button className={styles.row} type="button" onClick={() => onDrill(f.drill)}>
                <span className={styles.rank}>{f.rank}</span>
                <span className={styles.iconBox} style={{ color: SEVERITY_COLOR[f.severity], background: SEVERITY_SOFT[f.severity] }}>
                  <Icon size={15} />
                </span>
                <span className={styles.main}>
                  <span className={styles.title}>{f.title}</span>
                  <span className={styles.evidence}>{f.evidence}</span>
                </span>
                <span className={styles.right}>
                  <SeverityBadge severity={f.severity} label={f.isCoverage ? 'Coverage' : undefined} />
                  <span className={styles.countLabel}>{f.countLabel}</span>
                </span>
                <ChevronRight size={15} className={styles.chev} />
              </button>
            </li>
          )
        })}
      </ul>
    </Panel>
  )
}
