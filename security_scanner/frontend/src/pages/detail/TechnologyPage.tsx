import Panel from '../../components/primitives/Panel'
import { PageTitle, CheckerHeader, KV, IssueList, DetailGrid } from '../../components/detail/parts'
import { MoreCheckers } from './ExposurePage'
import { getResults, fmtDate } from '../../data/results'
import { cat } from '../../data/selectors'
import type { Results } from '../../types/results'
import styles from './detail.module.css'

export default function TechnologyPage({ r = getResults()! }: { r?: Results }) {
  const tech = cat(r, 'tech_stack')
  const intel = cat(r, 'domain_intel')
  const policy = cat(r, 'security_policy')
  const privacy = cat(r, 'privacy_compliance')
  const payment = cat(r, 'payment_security')
  const vpn = cat(r, 'vpn_remote')

  const secTxt = (policy?.security_txt as { present?: boolean }) ?? {}
  const robots = (policy?.robots_txt as { present?: boolean }) ?? {}

  return (
    <div className={styles.page}>
      <PageTitle title="Technology & Governance" subtitle="Detected stack, domain intelligence, published policies, payment & remote-access posture. Neutral findings are not deficiencies." />

      <DetailGrid cols={3}>
        <Panel title="Technology Stack" action={<CheckerHeader category={tech} />}>
          <KV rows={[
            { label: 'Server software', value: ((tech?.server_software as string[]) ?? []).join(', ') || '—' },
            { label: 'CMS', value: (tech?.cms as { detected?: string })?.detected ?? 'None detected' },
            { label: 'End-of-life software', value: ((tech?.eol_detected as unknown[]) ?? []).length || 'None', severity: ((tech?.eol_detected as unknown[]) ?? []).length > 0 ? 'high' : 'positive' },
          ]} />
          <IssueList issues={tech?.issues as string[]} />
        </Panel>

        <Panel title="Domain Intelligence" action={<CheckerHeader category={intel} />}>
          <KV rows={[
            { label: 'Registrar', value: (intel?.registrar as string) ?? '—' },
            { label: 'Created', value: intel?.creation_date ? fmtDate(intel.creation_date as string) : '—' },
            { label: 'Expires', value: intel?.expiry_date ? fmtDate(intel.expiry_date as string) : '—' },
            { label: 'Privacy protected', value: (intel?.privacy_protected as boolean) ? 'Yes' : 'No' },
          ]} />
          <IssueList issues={intel?.issues as string[]} />
        </Panel>

        <Panel title="Security Policy & VDP" action={<CheckerHeader category={policy} />}>
          <KV rows={[
            { label: 'security.txt', value: secTxt.present ? 'Published' : 'Not found', severity: secTxt.present ? 'positive' : 'medium' },
            { label: 'robots.txt', value: robots.present ? 'Present' : 'Not found' },
          ]} />
          <IssueList issues={policy?.issues as string[]} />
        </Panel>

        <Panel title="Privacy Compliance" action={<CheckerHeader category={privacy} />}>
          <KV rows={[
            { label: 'Policy found', value: (privacy?.policy_found as boolean) ? 'Yes' : 'No', severity: (privacy?.policy_found as boolean) ? 'positive' : 'high' },
            { label: 'Coverage', value: privacy?.compliance_pct != null ? `${privacy.compliance_pct}%` : '—' },
            { label: 'Sections missing', value: ((privacy?.sections_missing as string[]) ?? []).length || 'None' },
          ]} />
          <IssueList issues={privacy?.issues as string[]} />
        </Panel>

        <Panel title="Payment Security" action={<CheckerHeader category={payment} />}>
          <KV rows={[
            { label: 'Payment page', value: (payment?.has_payment_page as boolean) ? 'Detected' : 'None detected' },
            { label: 'Provider', value: (payment?.payment_provider as string) ?? '—' },
            { label: 'Self-hosted form', value: (payment?.self_hosted_payment_form as boolean) ? 'Yes' : 'No', severity: (payment?.self_hosted_payment_form as boolean) ? 'medium' : undefined },
          ]} />
          <IssueList issues={payment?.issues as string[]} />
        </Panel>

        <Panel title="VPN / Remote Access" action={<CheckerHeader category={vpn} />}>
          <KV rows={[
            { label: 'VPN detected', value: (vpn?.vpn_detected as boolean) ? (vpn?.vpn_name as string) ?? 'Yes' : 'No' },
            { label: 'RDP exposed', value: (vpn?.rdp_exposed as boolean) ? 'Yes' : 'No', severity: (vpn?.rdp_exposed as boolean) ? 'critical' : 'positive' },
          ]} />
          <IssueList issues={vpn?.issues as string[]} />
        </Panel>
      </DetailGrid>

      <MoreCheckers r={r} ids={['dependency_manifests', 'cms_plugin_sbom', 'glasswing', 'third_party_correlation', 'cloud_cdn']} />
    </div>
  )
}
