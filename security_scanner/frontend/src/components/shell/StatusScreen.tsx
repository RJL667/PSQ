import { ShieldHalf, Loader2, AlertTriangle } from 'lucide-react'
import styles from './StatusScreen.module.css'

/**
 * Placeholder full-screen state for non-completed scans. The full redesigned
 * scan-in-progress experience (spec §29) is built on top of this shell; this
 * keeps pending/failed coherent with the dark application language meanwhile.
 */
export default function StatusScreen({
  kind, domain, message,
}: { kind: 'pending' | 'failed'; domain: string; message?: string }) {
  return (
    <div className={styles.wrap}>
      <div className={styles.card}>
        <span className={styles.logo}><ShieldHalf size={26} /></span>
        {kind === 'pending' ? (
          <>
            <Loader2 className={styles.spin} size={22} />
            <h1 className={styles.title}>Assessment in progress</h1>
            <p className={styles.sub}>Scanning <strong>{domain}</strong> — this page will populate as
              checkers complete.</p>
          </>
        ) : (
          <>
            <AlertTriangle className={styles.warn} size={22} />
            <h1 className={styles.title}>Assessment unavailable</h1>
            <p className={styles.sub}>{message || `No completed results for ${domain}.`}</p>
          </>
        )}
      </div>
    </div>
  )
}
