import { NavLink } from 'react-router-dom'
import {
  ShieldHalf, LayoutGrid, GitBranch, Crosshair, Grid3x3,
  SearchCode, FileStack, ShieldCheck, TrendingUp,
  FileText, CircleDot
} from 'lucide-react'
import { run, findings, dataSource } from '../data/scanData'

const nav = [
  { to: '/', label: 'Dashboard', icon: LayoutGrid },
  { to: '/attack-chain', label: 'Attack Chain', icon: GitBranch },
  { to: '/findings', label: 'Findings', icon: Crosshair, badge: findings.length },
  { to: '/owasp-mapping', label: 'OWASP Mapping', icon: Grid3x3 },
  { to: '/explainability', label: 'Risk Attribution', icon: SearchCode },
  { to: '/evidence', label: 'Evidence', icon: FileStack },
  { to: '/security-controls', label: 'Security Controls', icon: ShieldCheck },
  { to: '/trends', label: 'Trends', icon: TrendingUp },
  { to: '/reports', label: 'Reports', icon: FileText }
]

export default function Sidebar() {
  return (
    <aside className="w-[248px] shrink-0 h-screen sticky top-0 flex flex-col border-r border-base-border bg-base-panel">
      <div className="px-5 pt-5 pb-4 flex items-center gap-2.5 border-b border-base-border">
        <div className="w-8 h-8 rounded-lg bg-brand flex items-center justify-center shadow-glow shrink-0">
          <ShieldHalf size={18} className="text-content" />
        </div>
        <div>
          <div className="text-[15px] font-bold text-content leading-tight">AegisAI</div>
          <div className="text-[10px] text-content-dim leading-tight tracking-wide">Validation Platform</div>
        </div>
      </div>

      <div className="px-3 pt-4 pb-2">
        <div className="label-eyebrow px-2 mb-1.5">Active Validation</div>
        <NavLink to="/" className="block card !bg-base-card2 px-3 py-2.5 hover:border-brand/50 transition-colors">
          <div className="flex items-center gap-1.5 mono text-[13px] font-semibold text-content">
            <CircleDot size={10} className="text-content-dim" />
            {run.id}
          </div>
          <div className="text-[11px] text-content-dim mt-0.5 truncate">{run.target}</div>
        </NavLink>
      </div>

      <nav className="flex-1 overflow-y-auto scroll-thin px-3 py-2 space-y-0.5">
        {nav.map(({ to, label, icon: Icon, badge }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-2.5 px-3 py-2 rounded-lg text-[13px] font-medium transition-colors ${
                isActive
                  ? 'bg-brand text-white shadow-glow'
                  : 'text-content-muted hover:text-content hover:bg-base-card'
              }`
            }
          >
            <Icon size={16} />
            <span className="flex-1">{label}</span>
            {badge ? (
              <span className="text-[10px] font-bold bg-sev-critical text-content rounded-full px-1.5 py-0.5 leading-none">
                {badge}
              </span>
            ) : null}
          </NavLink>
        ))}
      </nav>

      <div className="px-3 py-3 border-t border-base-border">
        <div className="label-eyebrow px-2 mb-1.5">Data source</div>
        <div className="px-2 text-[11px] text-content-dim leading-relaxed mono break-all">
          {dataSource.scan_id ?? 'no scan exported'}
        </div>
        <div className="px-2 text-[10px] text-content-dim mt-1">
          {dataSource.generated_at ? `exported ${dataSource.generated_at.replace('T', ' ')}` : 'run: aegisai dashboard export'}
        </div>
      </div>
    </aside>
  )
}
