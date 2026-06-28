import type { ReactNode } from 'react'
import Sidebar from './Sidebar'
import CommandBar from './CommandBar'
import styles from './AppShell.module.css'

export default function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className={styles.shell}>
      <Sidebar />
      <CommandBar />
      <main className={styles.main}>{children}</main>
    </div>
  )
}
