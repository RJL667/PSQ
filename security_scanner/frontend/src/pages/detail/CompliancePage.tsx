import Panel from '../../components/primitives/Panel'
import EmptyState from '../../components/primitives/EmptyState'
import ComplianceMatrix from '../../components/overview/ComplianceMatrix'
import { PageTitle, DetailGrid } from '../../components/detail/parts'
import { getResults } from '../../data/results'
import type { Results, ComplianceControl } from '../../types/results'
import styles from './detail.module.css'

const CTRL_COLOR: Record<string, string> = {
  pass: 'var(--positive)', partial: 'var(--warning)', fail: 'var(--high)', no_data: 'var(--unknown)',
}

export default function CompliancePage({ r = getResults()! }: { r?: Results }) {
  const comp = r.compliance ?? {}
  const frameworks = Object.entries(comp)

  return (
    <div className={styles.page}>
      <PageTitle title="Compliance Framework Mapping" subtitle="Externally observable alignment to POPIA, PCI DSS, ISO 27001 and NIST CSF. External scans cover only a subset of each framework's controls." />

      <ComplianceMatrix r={r} />

      {frameworks.length === 0 ? (
        <Panel title="Control detail"><EmptyState title="No framework controls computed" /></Panel>
      ) : (
        <DetailGrid cols={2}>
          {frameworks.map(([name, fw]) => (
            <Panel key={name} title={name} action={<span style={{ fontSize: 12, fontWeight: 700 }}>{fw.overall_pct ?? '—'}%</span>}>
              <div className={styles.page} style={{ gap: 0 }}>
                {Object.entries(fw.controls ?? {}).map(([cname, c]: [string, ComplianceControl]) => (
                  <div key={cname} style={{ padding: '9px 0', borderBottom: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'center' }}>
                      <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>{cname}</span>
                      <span style={{ fontSize: 10.5, fontWeight: 700, textTransform: 'uppercase', color: CTRL_COLOR[c.status ?? 'no_data'] }}>
                        {(c.status ?? 'no data').replace('_', ' ')}
                      </span>
                    </div>
                    {c.description && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{c.description}</div>}
                    {(c.findings ?? []).length > 0 && (
                      <ul style={{ margin: '5px 0 0', paddingLeft: 15 }}>
                        {(c.findings ?? []).map((f, i) => <li key={i} style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{f}</li>)}
                      </ul>
                    )}
                  </div>
                ))}
              </div>
            </Panel>
          ))}
        </DetailGrid>
      )}
    </div>
  )
}
