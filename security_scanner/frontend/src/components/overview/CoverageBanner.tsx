import { useState } from 'react'
import { ShieldAlert, ChevronDown, X } from 'lucide-react'
import { getCoverageSummary, CATEGORY_LABELS } from '../../data/selectors'
import type { Results } from '../../types/results'
import styles from './CoverageBanner.module.css'

export default function CoverageBanner({ r, onReview }: { r: Results; onReview?: (cat: string) => void }) {
  const cov = getCoverageSummary(r)
  const [expanded, setExpanded] = useState(false)
  const [dismissed, setDismissed] = useState(false)

  if (!cov.blocked || dismissed) return null

  const facts = [
    cov.coveragePct != null ? `${cov.coveragePct}% assessable coverage` : null,
    `${cov.affectedCount} affected checker${cov.affectedCount === 1 ? '' : 's'}`,
    'Active blocking detected',
    cov.probeSummary,
  ].filter(Boolean) as string[]

  return (
    <div className={styles.banner}>
      <div className={styles.head}>
        <span className={styles.icon}><ShieldAlert size={16} /></span>
        <div className={styles.headText}>
          <div className={styles.title}>Partial Scan Coverage — WAF / Bot-Manager Intervention Detected</div>
          <div className={styles.facts}>
            {facts.map((f, i) => <span key={i} className={styles.fact}>{f}</span>)}
          </div>
        </div>
        <div className={styles.actions}>
          <button className={styles.review} type="button" onClick={() => setExpanded((e) => !e)} aria-expanded={expanded}>
            Review affected checks <ChevronDown size={13} className={expanded ? styles.chevUp : ''} />
          </button>
          <button className={styles.dismiss} type="button" onClick={() => setDismissed(true)} aria-label="Dismiss coverage notice">
            <X size={15} />
          </button>
        </div>
      </div>

      {expanded && (
        <div className={styles.detail}>
          <p>
            Protective infrastructure on this target actively intervened during the scan.
            The <strong>absence of findings does not confirm the absence of risk</strong> — the
            scanner could not verify the affected checks. A scan from a different source IP, or
            coordination with the target's security team, may be required to complete coverage.
          </p>
          {cov.affectedCheckers.length > 0 && (
            <div className={styles.affected}>
              <span className={styles.affectedLabel}>Affected checks (not assessed):</span>
              <div className={styles.chips}>
                {cov.affectedCheckers.map((c) => (
                  <button key={c} type="button" className={styles.chip} onClick={() => onReview?.(c)}>
                    {CATEGORY_LABELS[c] ?? c.replace(/_/g, ' ')}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
