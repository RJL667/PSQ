import RemediationQueue from '../../components/overview/RemediationQueue'
import { PageTitle } from '../../components/detail/parts'
import { getResults } from '../../data/results'
import type { Results } from '../../types/results'
import styles from './detail.module.css'

export default function RemediationPage({ r = getResults()! }: { r?: Results }) {
  return (
    <div className={styles.page}>
      <PageTitle title="Remediation" subtitle="Prioritised actions ordered by risk reduction and underwriting impact. The critically exposed service is addressed first; scan-quality actions are distinguished from vulnerabilities." />
      <RemediationQueue r={r} />
    </div>
  )
}
