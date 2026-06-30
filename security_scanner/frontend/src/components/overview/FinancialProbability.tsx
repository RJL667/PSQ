import Panel from '../primitives/Panel'
import { DetailGrid } from '../detail/parts'
import { fmtZar } from '../../data/results'
import { getRiskProbability, getLossExposure } from '../../data/selectors'
import type { Results } from '../../types/results'

// FAIR annual-likelihood + catastrophe-severity views (risk_probability,
// loss_exposure, cover_ladder) — mirrors the PDF / on-Render report. Hidden
// when the scan predates these blocks (older cached scans).

const GRADE_COLOR: Record<string, string> = {
  Strong: 'var(--positive)', Good: 'var(--positive)', Low: 'var(--positive)',
  Typical: 'var(--info)', Good_: 'var(--positive)',
  Elevated: 'var(--warning)', High: 'var(--high)', Critical: 'var(--critical)',
}
const gradeColor = (g: string | null): string => (g ? GRADE_COLOR[g] : undefined) ?? 'var(--text-muted)'

function LossTable({ rows }: { rows: { key: string; label: string; loss: number | null }[] }) {
  return (
    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
      <tbody>
        {rows.map((s) => (
          <tr key={s.key} style={{ borderBottom: '1px solid var(--border)' }}>
            <td style={{ padding: '6px 0', color: 'var(--text-secondary)' }}>{s.label}</td>
            <td style={{ padding: '6px 0', textAlign: 'right', fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>{fmtZar(s.loss)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export default function FinancialProbability({ r }: { r: Results }) {
  const rp = getRiskProbability(r)
  const le = getLossExposure(r)
  if (!rp.available && !le.available) return null

  return (
    <DetailGrid cols={2}>
      {rp.available && (
        <Panel title="Risk Probability (annual likelihood)">
          {rp.rows.map((row) => (
            <div key={row.key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 10, padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{row.label}</span>
              <span style={{ display: 'flex', alignItems: 'baseline', gap: 8, whiteSpace: 'nowrap' }}>
                <span style={{ fontSize: 20, fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>{row.pct != null ? `${row.pct}%` : '—'}</span>
                {row.grade && <span style={{ fontSize: 11, fontWeight: 700, color: gradeColor(row.grade) }}>{row.grade}</span>}
                {row.indicative && !row.grade && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>indicative</span>}
              </span>
            </div>
          ))}
          {rp.channels && (
            <p style={{ margin: '10px 0 0', fontSize: 11, color: 'var(--text-muted)' }}>
              Cyber-incident channels — breach {rp.channels.dataBreach != null ? (rp.channels.dataBreach * 100).toFixed(1) : '—'}% · ransomware {rp.channels.ransomware != null ? (rp.channels.ransomware * 100).toFixed(1) : '—'}%
            </p>
          )}
        </Panel>
      )}

      {le.available && (
        <Panel title="Loss Exposure & Cover Sizing" action={<span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{le.currency}</span>}>
          {le.scenarios.length > 0 && <LossTable rows={le.scenarios} />}
          {le.coverLadder.length > 0 && (
            <>
              <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.4, color: 'var(--text-muted)', margin: '12px 0 2px' }}>Cover ladder (severity PML, posture-independent)</div>
              <LossTable rows={le.coverLadder} />
            </>
          )}
          {le.disclaimer && <p style={{ margin: '10px 0 0', fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>{le.disclaimer}</p>}
        </Panel>
      )}
    </DetailGrid>
  )
}
