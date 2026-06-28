import type { ReactNode } from 'react'
import styles from './Panel.module.css'

interface PanelProps {
  title?: ReactNode
  /** small right-aligned header slot (counts, tabs, actions) */
  action?: ReactNode
  /** optional icon before the title */
  icon?: ReactNode
  children?: ReactNode
  /** subtle elevated surface variant */
  elevated?: boolean
  /** remove inner body padding (tables, custom layouts) */
  flush?: boolean
  className?: string
  /** make the whole panel a single column that stretches in a grid */
  fill?: boolean
}

/**
 * The one shared surface primitive (spec §27): thin border, subtle navy
 * gradient, restrained. Every analytical panel composes this; semantic
 * content components live on top of it, not as Card variants.
 */
export default function Panel({
  title, action, icon, children, elevated, flush, className, fill,
}: PanelProps) {
  const cls = [
    styles.panel,
    elevated ? styles.elevated : '',
    fill ? styles.fill : '',
    className ?? '',
  ].filter(Boolean).join(' ')
  return (
    <section className={cls}>
      {(title || action) && (
        <header className={styles.head}>
          <div className={styles.titleWrap}>
            {icon && <span className={styles.icon}>{icon}</span>}
            {title && <h2 className={styles.title}>{title}</h2>}
          </div>
          {action && <div className={styles.action}>{action}</div>}
        </header>
      )}
      <div className={flush ? styles.bodyFlush : styles.body}>{children}</div>
    </section>
  )
}
