import { Users, BarChart3 } from 'lucide-react'
import Panel from '../primitives/Panel'
import { getPeerSummary } from '../../data/selectors'
import type { Results } from '../../types/results'
import styles from './PeerBenchmark.module.css'

export default function PeerBenchmark({ r }: { r: Results }) {
  const peer = getPeerSummary(r)

  return (
    <Panel title="Peer Benchmarking" icon={<BarChart3 size={14} />} fill>
      {peer.insufficient ? (
        <div className={styles.pending}>
          <span className={styles.icon}><Users size={20} /></span>
          <div className={styles.pendingMain}>
            <div className={styles.pendingTitle}>Benchmark pending</div>
            <p className={styles.pendingBody}>
              Fewer than {peer.minN} comparable scans are currently available
              {peer.nPeers != null ? ` (${peer.nPeers} so far)` : ''}. Peer rating activates once the
              benchmark pool for this segment grows.
            </p>
            <dl className={styles.segment}>
              <div><dt>Industry</dt><dd>{peer.industry}</dd></div>
              <div><dt>Sub-industry</dt><dd>{peer.subIndustry}</dd></div>
              <div><dt>Size</dt><dd>{peer.revenueBand}</dd></div>
            </dl>
          </div>
        </div>
      ) : (
        <div className={styles.rated}>
          <div className={styles.ratingBig}>{peer.rating?.toFixed(1) ?? '—'}<span>/ 10</span></div>
          {peer.percentile != null && <div className={styles.pct}>{peer.percentile}th percentile in {peer.industry} · {peer.revenueBand}</div>}
        </div>
      )}
    </Panel>
  )
}
