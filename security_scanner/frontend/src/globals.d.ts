// The server-injected globals that Flask writes into results.html before
// app.js loads. (Asset module shims live in vite-env.d.ts.)
import type { Results } from './types/results'

declare global {
  interface ScanMeta {
    status: 'completed' | 'pending' | 'failed'
    domain: string
    scanId: string
    error?: string
  }
  interface Window {
    RESULTS?: Results | null
    SCAN_META?: ScanMeta
    CHECKER_MANIFEST?: Array<{ section: string; checkers: Array<{ id: string; label: string; per_ip?: boolean }> }>
  }
}

export {}
