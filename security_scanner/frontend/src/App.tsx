import { HashRouter, Routes, Route, Navigate } from 'react-router-dom'
import { getScanMeta } from './data/results'
import AppShell from './components/shell/AppShell'
import OverviewPage from './pages/OverviewPage'
import { CategoryDetailPage } from './pages/CategoryDetailPage'
import StatusScreen from './components/shell/StatusScreen'
import ScanProgress from './components/scan/ScanProgress'

export default function App() {
  const meta = getScanMeta()

  if (meta.status === 'pending') {
    return <ScanProgress scanId={meta.scanId} domain={meta.domain} />
  }
  if (meta.status === 'failed' || !window.RESULTS) {
    return <StatusScreen kind="failed" domain={meta.domain} message={meta.error} />
  }

  return (
    <HashRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <AppShell>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/:section" element={<CategoryDetailPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell>
    </HashRouter>
  )
}
