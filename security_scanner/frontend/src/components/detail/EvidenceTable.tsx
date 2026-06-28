import type { ReactNode } from 'react'
import styles from './EvidenceTable.module.css'

export interface Column<T> {
  key: string
  header: ReactNode
  render: (row: T) => ReactNode
  align?: 'left' | 'right' | 'center'
  width?: string
}

export default function EvidenceTable<T>({
  columns, rows, getKey, empty,
}: {
  columns: Array<Column<T>>
  rows: T[]
  getKey: (row: T, i: number) => string
  empty?: ReactNode
}) {
  if (rows.length === 0) {
    return <div className={styles.empty}>{empty ?? 'No records.'}</div>
  }
  return (
    <div className={styles.scroll}>
      <table className={styles.table}>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} style={{ textAlign: c.align ?? 'left', width: c.width }}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={getKey(row, i)}>
              {columns.map((c) => (
                <td key={c.key} style={{ textAlign: c.align ?? 'left' }}>{c.render(row)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
