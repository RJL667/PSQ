import Panel from '../../components/primitives/Panel'
import { PageTitle, CheckerHeader, ScoreLine, KV, IssueList, DetailGrid } from '../../components/detail/parts'
import { getResults, fmtDate } from '../../data/results'
import { cat } from '../../data/selectors'
import type { Results } from '../../types/results'
import styles from './detail.module.css'

export default function CoreSecurityPage({ r = getResults()! }: { r?: Results }) {
  const ssl = cat(r, 'ssl')
  const headers = cat(r, 'http_headers')
  const waf = cat(r, 'waf')
  const tpjs = cat(r, 'third_party_js')
  const ws = cat(r, 'website_security')

  const certificate = (ssl?.certificate as Record<string, unknown>) ?? {}
  const tls = (ssl?.tls_versions as Record<string, boolean>) ?? {}
  const cipher = (ssl?.cipher_suite as Record<string, unknown>) ?? {}
  const enabledTls = Object.entries(tls).filter(([, on]) => on).map(([v]) => v)
  const weakTls = enabledTls.some((v) => /1\.0|1\.1/.test(v))

  const headerReason = (headers?.unreachable_reason as string) ?? null
  const headerStatus = headers?.http_status as number | undefined
  const headerMap = (headers?.headers as Record<string, unknown>) ?? {}

  return (
    <div className={styles.page}>
      <PageTitle title="Core Security" subtitle="TLS, HTTP security headers, WAF posture, HTTPS enforcement and third-party script integrity." />

      <DetailGrid cols={2}>
        {/* SSL / TLS */}
        <Panel title="SSL / TLS Certificate" action={<CheckerHeader category={ssl} />}>
          {!!ssl?.grade && (
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 10 }}>
              <span style={{ fontSize: 30, fontWeight: 700, color: gradeColor(ssl.grade as string) }}>{ssl.grade as string}</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>overall grade</span>
            </div>
          )}
          <KV rows={[
            { label: 'Subject', value: (certificate.subject as string) ?? '—' },
            { label: 'Issuer', value: (certificate.issuer_cn as string) ?? (certificate.issuer as string) ?? '—' },
            { label: 'Expires', value: certificate.expiry_date ? fmtDate(certificate.expiry_date as string) : '—' },
            { label: 'Days remaining', value: certificate.days_until_expiry != null ? String(certificate.days_until_expiry) : '—', severity: (certificate.days_until_expiry as number) < 30 ? 'high' : undefined },
            { label: 'TLS versions', value: enabledTls.length ? enabledTls.join(', ') : '—', severity: weakTls ? 'high' : undefined },
            { label: 'Cipher', value: (cipher.name as string) ?? '—' },
            { label: 'HSTS', value: ssl?.hsts ? 'Enabled' : 'Not configured', severity: ssl?.hsts ? 'positive' : 'medium' },
            { label: 'OCSP stapling', value: ssl?.ocsp_stapling == null ? 'Not assessed' : (ssl.ocsp_stapling ? 'Yes' : 'No') },
          ]} />
          <IssueList issues={ssl?.issues as string[]} />
        </Panel>

        {/* HTTP security headers — explicit "Not assessed" when blocked */}
        <Panel title="HTTP Security Headers" action={<CheckerHeader category={headers} />}>
          {headerReason || headerStatus === 403 ? (
            <div className={styles.note} style={{ marginTop: 0 }}>
              <strong style={{ color: 'var(--text-secondary)' }}>Not assessed.</strong> {headerReason ?? `The site returned HTTP ${headerStatus}.`} No verdict is implied — a blocked probe is neither a pass nor a fail.
            </div>
          ) : Object.keys(headerMap).length ? (
            <KV rows={Object.entries(headerMap).map(([k, v]) => ({
              label: k, value: v ? 'Present' : 'Missing', severity: v ? 'positive' as const : 'medium' as const,
            }))} />
          ) : (
            <div className={styles.note} style={{ marginTop: 0 }}>No header data returned.</div>
          )}
          <IssueList issues={headers?.issues as string[]} />
        </Panel>

        {/* WAF */}
        <Panel title="WAF / DDoS Protection" action={<CheckerHeader category={waf} />}>
          <KV rows={[
            { label: 'WAF detected', value: waf?.detected ? 'Yes' : 'No', severity: waf?.detected ? 'positive' : 'medium' },
            { label: 'Provider', value: (waf?.waf_name as string) ?? '—' },
            { label: 'All detected', value: ((waf?.all_detected as string[]) ?? []).join(', ') || '—' },
          ]} />
          <IssueList issues={waf?.issues as string[]} />
        </Panel>

        {/* Third-party JS — never present a stale score as a pass */}
        <Panel title="Third-Party JavaScript" action={<CheckerHeader category={tpjs} />}>
          <ScoreLine category={tpjs} />
          {(tpjs?.error as string) && (
            <div className={styles.note} style={{ marginTop: 0 }}>
              <strong style={{ color: 'var(--high)' }}>Checker could not complete</strong> — error: {String(tpjs?.error)}. Script integrity (SRI, third-party hosts) could not be verified; this is not a pass.
            </div>
          )}
          {!tpjs?.error && (
            <KV rows={[
              { label: 'Total scripts', value: String((tpjs?.total_scripts as number) ?? '—') },
              { label: 'Third-party hosts', value: String((tpjs?.third_party_count as number) ?? '—') },
              { label: 'Missing SRI', value: String((tpjs?.missing_sri_count as number) ?? '—'), severity: (tpjs?.missing_sri_count as number) > 0 ? 'medium' : undefined },
            ]} />
          )}
          <IssueList issues={tpjs?.issues as string[]} />
        </Panel>
      </DetailGrid>

      {/* Website security / HTTPS enforcement */}
      <Panel title="Website Security & HTTPS Enforcement" action={<CheckerHeader category={ws} />}>
        <KV rows={[
          { label: 'HTTPS enforced', value: ws?.https_enforced ? 'Yes' : 'No (HTTP does not redirect)', severity: ws?.https_enforced ? 'positive' : 'high' },
          { label: 'Mixed content', value: ws?.mixed_content ? 'Detected' : 'None', severity: ws?.mixed_content ? 'medium' : 'positive' },
          { label: 'Cookie flags', value: cookieSummary(ws?.cookies as Record<string, unknown>) },
        ]} />
        <IssueList issues={ws?.issues as string[]} />
      </Panel>
    </div>
  )
}

function gradeColor(g: string): string {
  const u = g.toUpperCase()
  if (u.startsWith('A')) return 'var(--positive)'
  if (u === 'B') return 'var(--info)'
  if (u === 'C') return 'var(--warning)'
  if (u === 'D' || u === 'E') return 'var(--high)'
  return 'var(--critical)'
}
function cookieSummary(c: Record<string, unknown> | undefined): string {
  if (!c) return '—'
  const flags = ['secure', 'httponly', 'samesite'].filter((f) => c[f])
  return flags.length ? flags.join(', ') : 'none set'
}
