import Panel from '../primitives/Panel'
import { CheckerHeader, KV } from './parts'
import { isConclusive } from '../../data/checkerState'
import type { CategoryBase } from '../../types/results'

/** Researched breach history (SCN-041).
 *
 *  Deliberately leads with WHEN rather than how many: recency is what drives the
 *  score here, and it is the first thing an underwriter asks. Also renders the
 *  unassessed state loudly — if the web-search key was down, "no breach found"
 *  would be a false clean, so the panel says so instead of showing green. */

interface Incident {
  title?: string
  incident_date?: string
  disclosure_date?: string
  records_affected?: string
  breach_type?: string
  root_cause?: string
  confidence?: string
}

const VERDICT_STYLE: Record<string, { label: string; color: string; bg: string }> = {
  confirmed: { label: 'Confirmed breach', color: 'var(--critical)', bg: 'var(--critical-soft)' },
  reported: { label: 'Reported breach', color: 'var(--high)', bg: 'var(--high-soft)' },
  possible: { label: 'Possible — unconfirmed', color: 'var(--warning)', bg: 'var(--warning-soft)' },
  none: { label: 'No breach found', color: 'var(--positive)', bg: 'var(--positive-soft)' },
  unknown: { label: 'Not assessed', color: 'var(--text-muted)', bg: 'var(--panel-bg-elevated)' },
}

export default function BreachIntelPanel({ bi }: { bi: CategoryBase | undefined }) {
  if (!bi) return null
  const verdict = String(bi.verdict ?? 'unknown')
  const conclusive = isConclusive(bi)
  const style = VERDICT_STYLE[conclusive ? verdict : 'unknown'] ?? VERDICT_STYLE.unknown
  const incidents = (bi.incidents as Incident[] | undefined) ?? []
  const sources = (bi.sources as Array<{ title?: string; url?: string }> | undefined) ?? []
  const months = bi.months_since_most_recent as number | null | undefined
  const recent = Boolean(bi.recent_material_breach)

  return (
    <Panel title="Breach History (Researched)" action={<CheckerHeader category={bi} />}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 12 }}>
        <span style={{ fontSize: 12.5, fontWeight: 700, color: style.color, background: style.bg,
          padding: '4px 11px', borderRadius: 999 }}>{style.label}</span>
        {conclusive && recent && (
          <span style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--critical)' }}>
            RECENT — materially affects posture
          </span>
        )}
        {!conclusive && (
          <span style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
            Research did not run — this is <b>not</b> evidence of a clean history.
          </span>
        )}
      </div>

      <KV rows={[
        { label: 'Most recent incident',
          value: (bi.most_recent_breach as string) ?? '—',
          severity: recent ? 'critical' : undefined },
        { label: 'Time since incident',
          value: months != null ? `${months} months` : '—' },
        { label: 'Distinct incidents', value: String(bi.incident_count ?? 0) },
        { label: 'Researched as', value: (bi.company_name as string) || '—' },
      ]} />

      {incidents.length > 0 && (
        <>
          <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '.06em', textTransform: 'uppercase',
            color: 'var(--text-muted)', margin: '14px 0 8px' }}>Incidents</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {incidents.map((inc, i) => (
              <div key={i} style={{ border: '1px solid var(--border-emphasis)', borderRadius: 10,
                padding: '10px 12px', background: 'var(--panel-bg-elevated)' }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 12.5, fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>
                    {inc.incident_date || inc.disclosure_date || 'date unestablished'}
                  </span>
                  {inc.incident_date ? null : inc.disclosure_date && (
                    <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>(disclosed)</span>
                  )}
                  {inc.confidence && (
                    <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                      color: 'var(--text-muted)' }}>{inc.confidence} confidence</span>
                  )}
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-primary)', marginTop: 3 }}>{inc.title}</div>
                <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', marginTop: 3 }}>
                  {[inc.breach_type?.replace(/_/g, ' '),
                    inc.records_affected ? `${inc.records_affected} records` : null,
                    inc.root_cause].filter(Boolean).join(' · ')}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {sources.length > 0 && (
        <>
          <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '.06em', textTransform: 'uppercase',
            color: 'var(--text-muted)', margin: '14px 0 6px' }}>Cited sources</div>
          <ul style={{ margin: 0, paddingLeft: 16, display: 'flex', flexDirection: 'column', gap: 4 }}>
            {sources.slice(0, 6).map((s, i) => (
              <li key={i} style={{ fontSize: 11.5, color: 'var(--text-secondary)', lineHeight: 1.45 }}>
                <a href={s.url} target="_blank" rel="noreferrer"
                  style={{ color: 'var(--accent-bright)', wordBreak: 'break-all' }}>
                  {s.title || s.url}
                </a>
              </li>
            ))}
          </ul>
        </>
      )}

      {Array.isArray(bi.issues) && (bi.issues as string[]).length > 0 && (
        <div style={{ marginTop: 12, fontSize: 11.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          {(bi.issues as string[]).slice(0, 3).map((it, i) => <div key={i}>· {it}</div>)}
        </div>
      )}
    </Panel>
  )
}
