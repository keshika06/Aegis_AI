import { useLocation, Link } from 'react-router-dom'
import { Download, Clock, AlertTriangle } from 'lucide-react'
import { run, dataSource, targetProfile, isStale } from '../data/scanData'

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
  const { pathname } = useLocation()
  const parts = pathname.split('/').filter(Boolean)
  const current = titleMap[parts[0] || ''] || 'Dashboard'

  return (
    <header className="sticky top-0 z-20 h-14 border-b border-base-border bg-base-bg/95 backdrop-blur flex items-center justify-between px-6 gap-4">
      <div className="flex items-center gap-2 text-[13px] text-slate-500">
        <Link to="/" className="hover:text-slate-300">AegisAI</Link>
        <span>/</span>
        <span>Validation</span>
        <span>/</span>
        <span className="mono text-brand font-semibold">{run.id}</span>
        <span>/</span>
        <span className="text-slate-200 font-medium">{current}</span>
      </div>

      <div className="flex items-center gap-3">
        <div className="hidden lg:flex items-center gap-1.5 text-[12px] text-slate-500">
          <Clock size={13} />
          {run.date}, {run.time}
        </div>
        {/* Provenance is visible text, not a tooltip: the first question a
            reader has is which scan this is, and a hover target cannot answer
            a question you did not know to ask. */}
        <div
          className="hidden xl:flex items-center gap-2 text-[11px] text-slate-500 mono border border-base-border rounded-lg px-2 py-1"
          title={`Scan ${dataSource.scan_id ?? 'unknown'} · exported ${dataSource.generated_at ?? 'unknown'}`}
        >
          {targetProfile.url}
          <span className="text-slate-600">|</span>
          <span className="text-slate-400">{dataSource.scan_id ?? 'unknown'}</span>
        </div>
        {isStale && (
          <div
            className="hidden lg:flex items-center gap-1.5 text-[11px] mono rounded-lg px-2 py-1 border"
            style={{ color: '#f97316', borderColor: '#5c3517', background: '#3a220f' }}
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
