import { NavLink } from 'react-router-dom'
import { CATEGORY_TABS } from './nav'
import styles from './CategoryTabs.module.css'

/** Secondary page-level category navigation (spec §17 preferred pattern). */
export default function CategoryTabs() {
  return (
    <nav className={styles.tabs} aria-label="Assessment sections">
      {CATEGORY_TABS.map((t) => {
        const Icon = t.icon
        return (
          <NavLink
            key={t.to}
            to={t.to}
            end={t.to === '/'}
            className={({ isActive }) => `${styles.tab} ${isActive ? styles.active : ''}`}
          >
            <Icon size={14} />
            {t.label}
          </NavLink>
        )
      })}
    </nav>
  )
}
