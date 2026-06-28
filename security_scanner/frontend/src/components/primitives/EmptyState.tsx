import type { ReactNode } from 'react'
import { Inbox } from 'lucide-react'
import styles from './EmptyState.module.css'

export default function EmptyState({
  icon, title, children, compact,
}: { icon?: ReactNode; title: string; children?: ReactNode; compact?: boolean }) {
  return (
    <div className={compact ? styles.compact : styles.wrap}>
      <span className={styles.icon}>{icon ?? <Inbox size={compact ? 16 : 20} />}</span>
      <div className={styles.text}>
        <div className={styles.title}>{title}</div>
        {children && <div className={styles.body}>{children}</div>}
      </div>
    </div>
  )
}
