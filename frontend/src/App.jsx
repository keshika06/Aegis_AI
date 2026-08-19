import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Overview from './pages/Overview'
import Dashboard from './pages/Dashboard'
import AttackChain from './pages/AttackChain'
import Findings from './pages/Findings'
import FindingDetail from './pages/FindingDetail'
import OwaspMapping from './pages/OwaspMapping'
import RiskAnalysis from './pages/RiskAnalysis'
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
        <Route path="/" element={<Overview />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/attack-chain" element={<AttackChain />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/findings/:id" element={<FindingDetail />} />
        <Route path="/owasp-mapping" element={<OwaspMapping />} />
        <Route path="/risk-analysis" element={<RiskAnalysis />} />
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
