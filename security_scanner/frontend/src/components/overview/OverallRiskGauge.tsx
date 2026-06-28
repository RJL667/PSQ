import styles from './OverallRiskGauge.module.css'

interface Props {
  score: number
  max: number
  color: string
  level: string
}

/** Compact 270° arc gauge (spec §6 — compact, not oversized). */
export default function OverallRiskGauge({ score, max, color, level }: Props) {
  const size = 138
  const stroke = 11
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  const sweep = 0.75 // 270 degrees
  const track = c * sweep
  const f = Math.max(0, Math.min(1, score / max))
  const val = track * f
  const cx = size / 2

  return (
    <div className={styles.wrap}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img"
        aria-label={`Overall risk score ${score} of ${max}, ${level} risk`}>
        <g transform={`rotate(135 ${cx} ${cx})`}>
          <circle cx={cx} cy={cx} r={r} fill="none" stroke="var(--border)" strokeWidth={stroke}
            strokeDasharray={`${track} ${c}`} strokeLinecap="round" />
          <circle cx={cx} cy={cx} r={r} fill="none" stroke={color} strokeWidth={stroke}
            strokeDasharray={`${val} ${c}`} strokeLinecap="round"
            style={{ transition: 'stroke-dasharray .6s ease' }} />
        </g>
        <text x="50%" y="46%" className={styles.value} textAnchor="middle">{score}</text>
        <text x="50%" y="60%" className={styles.max} textAnchor="middle">/ {max}</text>
      </svg>
      <span className={styles.level} style={{ color, background: `${color}1f` }}>{level}</span>
    </div>
  )
}
