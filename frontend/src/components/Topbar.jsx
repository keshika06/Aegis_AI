import { useLocation, Link } from 'react-router-dom'
import { Download, Clock, AlertTriangle, Sun, Moon } from 'lucide-react'
import { run, dataSource, targetProfile, isStale } from '../data/scanData'
import { useTheme, useTokens } from '../theme'

const titleMap = {
  '': 'Dashboard',
  'attack-chain': 'Attack Chain',
  'findings': 'Findings',
  'owasp-mapping': 'OWASP Mapping',
  'explainability': 'Risk Attribution',
  'evidence': 'Evidence',
  'security-controls': 'Security Controls',
  'trends': 'Trends',
  'reports': 'Reports'
}

export default function Topbar() {
  const t = useTokens()
  const { theme, toggle } = useTheme()
  const { pathname } = useLocation()
  const parts = pathname.split('/').filter(Boolean)
  const current = titleMap[parts[0] || ''] || 'Dashboard'

  return (
    <header className="sticky top-0 z-20 h-14 border-b border-base-border bg-base-bg/95 backdrop-blur flex items-center justify-between px-6 gap-4">
      <div className="flex items-center gap-2 text-[13px] text-content-dim">
        <Link to="/" className="hover:text-content">AegisAI</Link>
        <span>/</span>
        <span>Validation</span>
        <span>/</span>
        <span className="mono text-brand font-semibold">{run.id}</span>
        <span>/</span>
        <span className="text-content font-medium">{current}</span>
      </div>

      <div className="flex items-center gap-3">
        <div className="hidden lg:flex items-center gap-1.5 text-[12px] text-content-dim">
          <Clock size={13} />
          {run.date}, {run.time}
        </div>
        <button
          onClick={toggle}
          className="p-2 rounded-lg text-content-muted hover:text-content hover:bg-base-card2 border border-base-border transition-colors"
          title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
        >
          {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
        </button>
        {/* Provenance is visible text, not a tooltip: the first question a
            reader has is which scan this is, and a hover target cannot answer
            a question you did not know to ask. */}
        <div
          className="hidden xl:flex items-center gap-2 text-[11px] text-content-dim mono border border-base-border rounded-lg px-2 py-1"
          title={`Scan ${dataSource.scan_id ?? 'unknown'} · exported ${dataSource.generated_at ?? 'unknown'}`}
        >
          {targetProfile.url}
          <span className="text-content-dim">|</span>
          <span className="text-content-muted">{dataSource.scan_id ?? 'unknown'}</span>
        </div>
        {isStale && (
          <div
            className="hidden lg:flex items-center gap-1.5 text-[11px] mono rounded-lg px-2 py-1 border"
            style={{ color: t.high, borderColor: 'var(--sev-high-border)', background: 'var(--sev-high-bg)' }}
            title={`A newer scan exists (${dataSource.latest_scan_id}). Refresh with:  aegisai dashboard export`}
          >
            <AlertTriangle size={12} />
            stale
          </div>
        )}
        <Link
          to="/reports"
          className="flex items-center gap-1.5 bg-brand hover:bg-brand/90 text-white text-[13px] font-semibold px-3 py-1.5 rounded-lg transition-colors"
        >
          <Download size={14} /> Export Report
        </Link>
      </div>
    </header>
  )
}
