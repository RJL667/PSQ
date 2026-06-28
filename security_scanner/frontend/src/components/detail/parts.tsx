import type { ReactNode } from 'react'
import type { CategoryBase, Severity } from '../../types/results'
import { StatusBadge } from '../primitives/Status'
import { normalizeState, isConclusive, inconclusiveLabel, SEVERITY_COLOR } from '../../data/checkerState'
import styles from './parts.module.css'

/** Page heading with optional one-line subtitle. */
export function PageTitle({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className={styles.pageTitle}>
      <h2>{title}</h2>
      {subtitle && <p>{subtitle}</p>}
    </div>
  )
}

/** Status header for a checker that NEVER presents a stale score as a pass when
 *  the checker did not actually complete (spec §18/§33). */
export function CheckerHeader({ category }: { category: CategoryBase | undefined }) {
  if (!category) return <StatusBadge state="not_assessed" label="Not in scan" />
  const state = normalizeState(category.status)
  const label = isConclusive(category) ? undefined : inconclusiveLabel(category.status as string)
  return <StatusBadge state={state} label={label} />
}

/** Render a checker's numeric score ONLY when the checker is conclusive. */
export function ScoreLine({ category, max = 100 }: { category: CategoryBase | undefined; max?: number }) {
  if (!category || typeof category.score !== 'number') return null
  if (!isConclusive(category)) {
    return <div className={styles.scoreMuted}>Score not applicable — checker did not complete</div>
  }
  const s = category.score
  const color = s >= 80 ? 'var(--positive)' : s >= 50 ? 'var(--warning)' : 'var(--high)'
  return (
    <div className={styles.scoreLine}>
      <span className={styles.scoreVal} style={{ color }}>{s}</span>
      <span className={styles.scoreMax}>/ {max}</span>
    </div>
  )
}

export interface KVRow { label: string; value: ReactNode; severity?: Severity }
export function KV({ rows }: { rows: KVRow[] }) {
  return (
    <dl className={styles.kv}>
      {rows.map((r, i) => (
        <div key={i}>
          <dt>{r.label}</dt>
          <dd style={r.severity ? { color: SEVERITY_COLOR[r.severity] } : undefined}>{r.value ?? '—'}</dd>
        </div>
      ))}
    </dl>
  )
}

/** A pass/warn/fail check line (SPF present, HSTS, etc.). */
export function CheckLine({ label, state, value }: { label: string; state: 'pass' | 'warn' | 'fail' | 'neutral'; value?: ReactNode }) {
  const color = state === 'pass' ? 'var(--positive)' : state === 'warn' ? 'var(--warning)' : state === 'fail' ? 'var(--high)' : 'var(--unknown)'
  return (
    <div className={styles.checkLine}>
      <span className={styles.checkDot} style={{ background: color }} aria-hidden />
      <span className={styles.checkLabel}>{label}</span>
      <span className={styles.checkVal} style={{ color }}>{value}</span>
    </div>
  )
}

export function IssueList({ issues }: { issues?: Array<string | { message?: string }> }) {
  if (!issues || issues.length === 0) return null
  return (
    <ul className={styles.issues}>
      {issues.map((it, i) => <li key={i}>{typeof it === 'string' ? it : it.message ?? JSON.stringify(it)}</li>)}
    </ul>
  )
}

export function StatGrid({ stats }: { stats: Array<{ label: string; value: ReactNode; severity?: Severity }> }) {
  return (
    <div className={styles.statGrid}>
      {stats.map((s, i) => (
        <div className={styles.stat} key={i}>
          <span className={styles.statVal} style={s.severity ? { color: SEVERITY_COLOR[s.severity] } : undefined}>{s.value}</span>
          <span className={styles.statLabel}>{s.label}</span>
        </div>
      ))}
    </div>
  )
}

/** Two/three-column responsive grid for detail panels. */
export function DetailGrid({ children, cols = 2 }: { children: ReactNode; cols?: 2 | 3 }) {
  return <div className={cols === 3 ? styles.grid3 : styles.grid2}>{children}</div>
}
