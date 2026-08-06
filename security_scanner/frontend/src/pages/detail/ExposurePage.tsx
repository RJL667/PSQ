import Panel from '../../components/primitives/Panel'
import { PageTitle, CheckerHeader, KV, IssueList, DetailGrid, NotAssessedNote } from '../../components/detail/parts'
import { getResults } from '../../data/results'
import { cat, CATEGORY_LABELS } from '../../data/selectors'
import { isConclusive } from '../../data/checkerState'
import CredentialExportPortal from '../../components/overview/CredentialExportPortal'
import BreachIntelPanel from '../../components/detail/BreachIntelPanel'
import type { Results, CategoryBase } from '../../types/results'
import type { KVRow } from '../../components/detail/parts'
import styles from './detail.module.css'

/** A registered domain that impersonates the client's. `technique` is how the
 *  string was derived (char-swap, char-omission, homoglyph…), `similarity` how
 *  close it is — both matter when deciding which ones to act on first. */
export interface Lookalike {
  domain: string
  technique?: string
  similarity?: number
}

function LookalikeList({ domains }: { domains?: Lookalike[] }) {
  if (!domains || domains.length === 0) return null
  return (
    <ul style={{ listStyle: 'none', margin: '10px 0 0', padding: 0,
      display: 'flex', flexDirection: 'column', gap: 6 }}>
      {domains.map((d) => (
        <li key={d.domain} style={{ display: 'flex', alignItems: 'baseline', gap: 8,
          flexWrap: 'wrap', fontSize: 12 }}>
          <span style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
            color: 'var(--text-primary)', fontWeight: 600 }}>{d.domain}</span>
          {d.technique && (
            <span style={{ fontSize: 10.5, color: 'var(--text-muted)', border: '1px solid var(--border)',
              borderRadius: 999, padding: '1px 7px' }}>{d.technique}</span>
          )}
          {typeof d.similarity === 'number' && (
            <span style={{ fontSize: 11, color: 'var(--warning)' }}>{d.similarity}% similar</span>
          )}
        </li>
      ))}
    </ul>
  )
}

export default function ExposurePage({ r = getResults()! }: { r?: Results }) {
  const get = (id: string) => cat(r, id)
  const breaches = get('breaches')
  const dehashed = get('dehashed')
  const vt = get('virustotal')
  const admin = get('exposed_admin')
  const subs = get('subdomains')
  const fraud = get('fraudulent_domains')

  const adminReachable = ((admin?.exposed as Array<{ status: number }> | undefined) ?? []).filter((e) => e.status === 200)

  return (
    <div className={styles.page}>
      <PageTitle title="Exposure & Reputation" subtitle="Breach history, credential exposure, reputation intelligence and exposed assets. States distinguish clean results from unavailable data sources." />

      {/* Researched breach history leads the page: a dated, confirmed prior breach
          is the single most consequential thing on it, and (unlike HIBP) it is
          usually the only place a real incident shows up at all. */}
      <BreachIntelPanel bi={get('breach_intel')} />

      <DetailGrid cols={3}>
        <Panel title="Known Breaches (HIBP)" action={<CheckerHeader category={breaches} />}>
          <KV rows={[
            { label: 'Breach count', value: String((breaches?.breach_count as number) ?? 0), severity: (breaches?.breach_count as number) > 0 ? 'high' : 'positive' },
            { label: 'Most recent', value: (breaches?.most_recent_breach as string) ?? 'None' },
            { label: 'Data classes', value: ((breaches?.data_classes as string[]) ?? []).length || 'None' },
          ]} />
          <IssueList issues={breaches?.issues as string[]} />
        </Panel>

        <Panel title="Credential Leaks" action={<CheckerHeader category={dehashed} />}>
          {isConclusive(dehashed) ? (
            <>
              <KV rows={[
                { label: 'Leaked records', value: String((dehashed?.total_entries as number) ?? '—') },
                { label: 'Unique emails', value: String((dehashed?.unique_emails as number) ?? '—') },
                { label: 'Passwords present', value: (dehashed?.has_passwords as boolean) ? 'Yes' : 'No' },
              ]} />
              <IssueList issues={dehashed?.issues as string[]} />
              {((dehashed?.total_entries as number) ?? 0) > 0 && <CredentialExportPortal />}
            </>
          ) : (
            // Suppress the counts entirely: a failed lookup returns 0 records, and
            // "0 leaked records" is indistinguishable from a clean estate.
            <NotAssessedNote category={dehashed} what="The breached-credential database" />
          )}
        </Panel>

        <Panel title="VirusTotal Reputation" action={<CheckerHeader category={vt} />}>
          <KV rows={[
            { label: 'Malicious', value: String((vt?.malicious_count as number) ?? 0), severity: (vt?.malicious_count as number) > 0 ? 'high' : 'positive' },
            { label: 'Suspicious', value: String((vt?.suspicious_count as number) ?? 0) },
            { label: 'Harmless', value: String((vt?.harmless_count as number) ?? 0) },
            { label: 'Reputation', value: String((vt?.reputation as number) ?? '—') },
          ]} />
          <IssueList issues={vt?.issues as string[]} />
        </Panel>

        <Panel title="Exposed Admin Panels" action={<CheckerHeader category={admin} />}>
          <KV rows={[
            { label: 'Reachable (HTTP 200)', value: String(adminReachable.length), severity: adminReachable.length > 0 ? 'critical' : 'positive' },
            { label: 'Critical paths', value: String((admin?.critical_count as number) ?? 0) },
            { label: 'High-risk paths', value: String((admin?.high_count as number) ?? 0) },
          ]} />
          <IssueList issues={admin?.issues as string[]} />
        </Panel>

        <Panel title="Subdomains" action={<CheckerHeader category={subs} />}>
          <KV rows={[
            { label: 'Discovered', value: String((subs?.total_count as number) ?? ((subs?.subdomains as unknown[]) ?? []).length) },
            { label: 'Risky', value: String(((subs?.risky_subdomains as unknown[]) ?? []).length), severity: ((subs?.risky_subdomains as unknown[]) ?? []).length > 0 ? 'high' : undefined },
          ]} />
          <IssueList issues={subs?.issues as string[]} />
        </Panel>

        <Panel title="Lookalike Domains" action={<CheckerHeader category={fraud} />}>
          <KV rows={[
            { label: 'Permutations tested', value: String((fraud?.total_permutations as number) ?? '—') },
            { label: 'Resolved (live)', value: String((fraud?.resolved_count as number) ?? 0), severity: (fraud?.resolved_count as number) > 0 ? 'medium' : 'positive' },
          ]} />
          {/* Name the domains. A count alone is not actionable: brand-abuse
              follow-up (registrar complaint, defensive registration, monitoring)
              starts from the actual strings, and every other panel that finds
              specific assets lists them. */}
          <LookalikeList domains={fraud?.fraudulent_domains as Lookalike[] | undefined} />
          <IssueList issues={fraud?.issues as string[]} />
        </Panel>
      </DetailGrid>

      <MoreCheckers r={r} ids={['credential_risk', 'credential_correlation', 'vendor_breach', 'hudson_rock', 'intelx', 'related_domains', 'info_disclosure']} />
    </div>
  )
}

/** Compact auto-rendered panels for the long tail — shows state correctly
 *  (no-API-key / subscription / no-data are neutral, not green). */
export function MoreCheckers({ r, ids }: { r: Results; ids: string[] }) {
  const present = ids.map((id) => [id, cat(r, id)] as const).filter(([, c]) => !!c)
  if (!present.length) return null
  return (
    <Panel title="Additional Intelligence Sources">
      <DetailGrid cols={3}>
        {present.map(([id, c]) => {
          const fields = Object.entries(c as CategoryBase)
            .filter(([k, v]) => !['status', 'issues', 'per_ip', 'score'].includes(k) && (typeof v !== 'object' || v === null))
            .slice(0, 4)
          const rows: KVRow[] = fields.map(([k, v]) => ({ label: k.replace(/_/g, ' '), value: String(v) }))
          return (
            <div key={id} style={{ border: '1px solid var(--border)', borderRadius: 10, padding: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 600 }}>{CATEGORY_LABELS[id] ?? id.replace(/_/g, ' ')}</span>
                <CheckerHeader category={c} />
              </div>
              {rows.length > 0 && <KV rows={rows} />}
            </div>
          )
        })}
      </DetailGrid>
    </Panel>
  )
}
