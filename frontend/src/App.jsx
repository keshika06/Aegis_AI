import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import AttackChain from './pages/AttackChain'
import Findings from './pages/Findings'
import FindingDetail from './pages/FindingDetail'
import OwaspMapping from './pages/OwaspMapping'
import Explainability from './pages/Explainability'
import Evidence from './pages/Evidence'
import SecurityControls from './pages/SecurityControls'
import Trends from './pages/Trends'
import Reports from './pages/Reports'
import ReportPreview from './pages/ReportPreview'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        {/* Overview and Dashboard rendered the same risk gauge, OWASP grid
            and attack chain. They are one page now; the old path still
            resolves so existing links and bookmarks do not 404. */}
        <Route path="/dashboard" element={<Navigate to="/" replace />} />
        <Route path="/attack-chain" element={<AttackChain />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/findings/:id" element={<FindingDetail />} />
        <Route path="/owasp-mapping" element={<OwaspMapping />} />
        {/* Risk Analysis duplicated the Dashboard's gauge, factor bars, severity
            donut and baseline comparison. Its one original panel — every finding
            plotted on the likelihood and impact axes — moved to Explainability,
            beside the model it visualises. */}
        <Route path="/risk-analysis" element={<Navigate to="/explainability" replace />} />
        <Route path="/explainability" element={<Explainability />} />
        <Route path="/evidence" element={<Evidence />} />
        <Route path="/security-controls" element={<SecurityControls />} />
        <Route path="/trends" element={<Trends />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/reports/preview" element={<ReportPreview />} />
      </Routes>
    </Layout>
  )
}
