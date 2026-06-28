import { Search, KeyRound, Crosshair, Database, Info } from 'lucide-react'
import Panel from '../primitives/Panel'
import { SeverityBadge } from '../primitives/Status'
import { getAttackPath } from '../../data/selectors'
import { SEVERITY_COLOR, SEVERITY_SOFT } from '../../data/checkerState'
import type { Results } from '../../types/results'
import styles from './AttackPath.module.css'

const STAGE_ICON = [Search, KeyRound, Crosshair, Database]

export default function AttackPath({ r, onDrill }: { r: Results; onDrill: (cat: string) => void }) {
  const stages = getAttackPath(r)
  return (
    <Panel title="Attacker's Path" fill>
      <ol className={styles.path}>
        {stages.map((s, i) => {
          const Icon = STAGE_ICON[i] ?? Search
          const color = SEVERITY_COLOR[s.risk]
          return (
            <li className={styles.stage} key={s.key}>
              <div className={styles.rail}>
                <span className={styles.node} style={{ color, background: SEVERITY_SOFT[s.risk], borderColor: color }}>
                  <Icon size={15} />
                </span>
                {i < stages.length - 1 && <span className={styles.line} />}
              </div>
              <button className={styles.content} type="button" onClick={() => s.drill && onDrill(s.drill)}>
                <div className={styles.stageHead}>
                  <span className={styles.stageTitle}>{s.index}. {s.title}</span>
                  <SeverityBadge severity={s.risk} label={`${s.risk[0].toUpperCase()}${s.risk.slice(1)} risk`} />
                </div>
                <ul className={styles.items}>
                  {s.items.map((it, j) => <li key={j}>{it}</li>)}
                </ul>
                {s.unverified && (
                  <div className={styles.unverified}><Info size={11} /> Not externally verified — absence of a confirmed vector is not proof of safety.</div>
                )}
              </button>
            </li>
          )
        })}
      </ol>
    </Panel>
  )
}
