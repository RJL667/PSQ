import Panel from '../../components/primitives/Panel'
import EmptyState from '../../components/primitives/EmptyState'
import FinancialExposure from '../../components/overview/FinancialExposure'
import PeerBenchmark from '../../components/overview/PeerBenchmark'
import { PageTitle, KV, DetailGrid } from '../../components/detail/parts'
import { getResults } from '../../data/results'
import { getRsiSummary, getDbiSummary } from '../../data/selectors'
import { SEVERITY_COLOR } from '../../data/checkerState'
import type { Results } from '../../types/results'
import styles from './detail.module.css'

export default function InsurancePage({ r = getResults()! }: { r?: Results }) {
  const rsi = getRsiSummary(r)
  const dbi = getDbiSummary(r)

  return (
    <div className={styles.page}>
      <PageTitle title="Insurance Analytics" subtitle="Ransomware susceptibility, data-breach resilience, modelled financial exposure and peer positioning." />

      <DetailGrid cols={2}>
        <Panel title="Ransomware Susceptibility Index">
          {rsi.available ? (
            <>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 10 }}>
                <span style={{ fontSize: 28, fontWeight: 700, color: SEVERITY_COLOR[rsi.severity] }}>{rsi.score!.toFixed(3)}</span>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>/ 1.000 · {rsi.label}</span>
              </div>
              <KV rows={[
                { label: 'Base score', value: rsi.baseScore?.toFixed(3) ?? '—' },
                { label: 'Contributing factors', value: String(rsi.factors.length) },
              ]} />
              {rsi.factors.length > 0 && (
                <ul style={{ margin: '10px 0 0', padding: 0, listStyle: 'none' }}>
                  {rsi.factors.map((f, i) => (
                    <li key={i} style={{ display: 'flex', justifyContent: 'space-between', gap: 10, padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                      <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{f.factor}</span>
                      <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--high)' }}>+{f.impact.toFixed(2)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </>
          ) : <EmptyState title="RSI not produced for this scan" />}
        </Panel>

        <Panel title="Data Breach Resilience Index">
          {dbi.available ? (
            <>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 10 }}>
                <span style={{ fontSize: 28, fontWeight: 700, color: SEVERITY_COLOR[dbi.severity] }}>{dbi.score}</span>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>/ {dbi.max} · {dbi.label}</span>
              </div>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                <tbody>
                  {dbi.components.map((c) => (
                    <tr key={c.key} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '6px 0', color: 'var(--text-secondary)' }}>{c.label}</td>
                      <td style={{ padding: '6px 0', color: 'var(--text-muted)', textAlign: 'right' }}>{c.value}</td>
                      <td style={{ padding: '6px 0 6px 12px', textAlign: 'right', fontWeight: 700, color: c.points >= c.max ? 'var(--positive)' : 'var(--warning)', fontVariantNumeric: 'tabular-nums' }}>{c.points}/{c.max}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : <EmptyState title="DBI not produced for this scan" />}
        </Panel>
      </DetailGrid>

      <FinancialExposure r={r} />
      <PeerBenchmark r={r} />
    </div>
  )
}
