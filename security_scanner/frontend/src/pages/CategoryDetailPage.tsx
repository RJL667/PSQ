import type { ComponentType } from 'react'
import { useParams } from 'react-router-dom'
import Panel from '../components/primitives/Panel'
import EmptyState from '../components/primitives/EmptyState'
import CategoryTabs from '../components/shell/CategoryTabs'
import Footer from '../components/shell/Footer'
import { StatusBadge } from '../components/primitives/Status'
import { getResults } from '../data/results'
import { cat, CATEGORY_LABELS } from '../data/selectors'
import { normalizeState } from '../data/checkerState'
import CoreSecurityPage from './detail/CoreSecurityPage'
import EmailPage from './detail/EmailPage'
import NetworkPage from './detail/NetworkPage'
import VulnerabilitiesPage from './detail/VulnerabilitiesPage'
import ExposurePage from './detail/ExposurePage'
import TechnologyPage from './detail/TechnologyPage'
import CompliancePage from './detail/CompliancePage'
import InsurancePage from './detail/InsurancePage'
import RemediationPage from './detail/RemediationPage'
import DiscoveryPage from './detail/DiscoveryPage'
import styles from './CategoryDetailPage.module.css'

// Bespoke detail pages (spec §18–25). Routes not listed fall back to the
// generic category-card scaffold below so every checker stays reachable.
const BESPOKE: Record<string, ComponentType> = {
  'core-security': CoreSecurityPage,
  email: EmailPage,
  network: NetworkPage,
  vulnerabilities: VulnerabilitiesPage,
  exposure: ExposurePage,
  technology: TechnologyPage,
  compliance: CompliancePage,
  insurance: InsurancePage,
  remediation: RemediationPage,
  discovery: DiscoveryPage,
}

// Which categories belong to each detail route (spec §17–23). Bespoke
// asset-first / table-first layouts are layered on later; this scaffold makes
// every category's evidence reachable now.
const SECTIONS: Record<string, { title: string; categories: string[] }> = {
  'core-security': { title: 'Core Security', categories: ['ssl', 'http_headers', 'waf', 'website_security', 'third_party_js', 'info_disclosure'] },
  email: { title: 'Email Security', categories: ['email_security', 'email_hardening', 'email_vendor_surface'] },
  network: { title: 'Network & Infrastructure', categories: ['dns_infrastructure', 'high_risk_protocols', 'shodan_vulns', 'cloud_cdn', 'vpn_remote', 'dnsbl', 'securitytrails'] },
  exposure: { title: 'Exposure & Reputation', categories: ['breaches', 'dehashed', 'credential_risk', 'virustotal', 'exposed_admin', 'subdomains', 'fraudulent_domains', 'related_domains', 'vendor_breach'] },
  technology: { title: 'Technology & Governance', categories: ['tech_stack', 'domain_intel', 'security_policy', 'payment_security', 'privacy_compliance', 'dependency_manifests', 'cms_plugin_sbom', 'glasswing'] },
  discovery: { title: 'Discovery & Information Security', categories: ['ip_discovery', 'web_ranking', 'info_disclosure', 'subdomains'] },
  vulnerabilities: { title: 'Vulnerabilities', categories: ['shodan_vulns', 'high_risk_protocols'] },
  insurance: { title: 'Insurance Analytics', categories: [] },
  remediation: { title: 'Remediation', categories: [] },
  compliance: { title: 'Compliance Framework Mapping', categories: [] },
  'risk-engine': { title: 'Risk Engine', categories: [] },
  financial: { title: 'Financial Exposure', categories: [] },
  regulatory: { title: 'Regulatory Flags', categories: [] },
  'scan-history': { title: 'Scan History', categories: [] },
}

function CategoryCard({ id }: { id: string }) {
  const r = getResults()
  const c = cat(r, id)
  const label = CATEGORY_LABELS[id] ?? id.replace(/_/g, ' ')
  if (!c) {
    return <Panel title={label}><EmptyState compact title="Not in this assessment">This checker did not run for this scan.</EmptyState></Panel>
  }
  const state = normalizeState(c.status)
  const issues = (c.issues ?? []) as Array<string | { message?: string }>
  const fields = Object.entries(c).filter(([k, v]) =>
    !['status', 'issues', 'per_ip', 'score'].includes(k) && (typeof v !== 'object' || v === null))
  return (
    <Panel title={label} action={<StatusBadge state={state} />}>
      {typeof c.score === 'number' && <div className={styles.score}>Score <strong>{c.score}</strong></div>}
      {fields.length > 0 && (
        <dl className={styles.fields}>
          {fields.slice(0, 10).map(([k, v]) => (
            <div className={styles.field} key={k}>
              <dt>{k.replace(/_/g, ' ')}</dt>
              <dd>{String(v)}</dd>
            </div>
          ))}
        </dl>
      )}
      {issues.length > 0 && (
        <ul className={styles.issues}>
          {issues.map((it, i) => (
            <li key={i}>{typeof it === 'string' ? it : it.message ?? JSON.stringify(it)}</li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

export function CategoryDetailPage() {
  const { section = '' } = useParams()
  const Bespoke = BESPOKE[section]
  const def = SECTIONS[section]

  if (Bespoke) {
    return (
      <>
        <CategoryTabs />
        <Bespoke />
        <Footer />
      </>
    )
  }

  return (
    <>
      <CategoryTabs />
      {!def ? (
        <Panel title="Section"><EmptyState title="Section in progress">This area is part of the
          assessment but its dedicated view is still being built.</EmptyState></Panel>
      ) : def.categories.length === 0 ? (
        <Panel title={def.title}><EmptyState title={`${def.title} — dedicated view in progress`}>
          The underlying data is available on the Risk Overview and via Export Report.</EmptyState></Panel>
      ) : (
        <>
          <h2 className={styles.h}>{def.title}</h2>
          <div className={styles.grid}>
            {def.categories.map((id) => <CategoryCard key={id} id={id} />)}
          </div>
        </>
      )}
      <Footer />
    </>
  )
}
