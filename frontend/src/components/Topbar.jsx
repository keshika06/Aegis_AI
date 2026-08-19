import { useLocation, Link } from 'react-router-dom'
import { Search, RefreshCw, Download, Clock } from 'lucide-react'
import { run, dataSource, targetProfile } from '../data/scanData'

const titleMap = {
  '': 'Overview',
  'dashboard': 'Dashboard',
  'attack-chain': 'Attack Chain',
  'findings': 'Findings',
  'owasp-mapping': 'OWASP Mapping',
  'risk-analysis': 'Risk Analysis',
  'explainability': 'Explainability',
  'evidence': 'Evidence',
  'security-controls': 'Security Controls',
  'trends': 'Trends',
  'reports': 'Reports'
}

export default function Topbar() {
  const { pathname } = useLocation()
  const parts = pathname.split('/').filter(Boolean)
  const current = titleMap[parts[0] || ''] || 'Overview'

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

      <div className="flex items-center gap-2 flex-1 max-w-md">
        <div className="relative flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            placeholder="Search findings, OWASP, evidence..."
            className="w-full bg-base-card border border-base-border rounded-lg pl-8 pr-3 py-1.5 text-[13px] text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-brand/60"
          />
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div className="hidden lg:flex items-center gap-1.5 text-[12px] text-slate-500">
          <Clock size={13} />
          {run.date}, {run.time}
        </div>
        <button className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-base-card transition-colors">
          <RefreshCw size={15} />
        </button>
        <div
          className="hidden xl:flex items-center gap-1.5 text-[11px] text-slate-500 mono border border-base-border rounded-lg px-2 py-1"
          title={`Exported ${dataSource.generated_at ?? 'unknown'} from ${dataSource.scan_id ?? 'unknown'}`}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-sev-low" />
          {targetProfile.url}
        </div>
        <Link
          to="/reports"
          className="flex items-center gap-1.5 bg-brand hover:bg-brand/90 text-white text-[13px] font-semibold px-3 py-1.5 rounded-lg transition-colors"
        >
          <Download size={14} /> Export Report
        </Link>
        <div className="w-8 h-8 rounded-full bg-base-card2 border border-base-border flex items-center justify-center text-[11px] font-bold text-slate-300">
          SE
        </div>
      </div>
    </header>
  )
}
