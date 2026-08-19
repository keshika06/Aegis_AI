import { NavLink } from 'react-router-dom'
import {
  ShieldHalf, Eye, LayoutGrid, GitBranch, Crosshair, Grid3x3,
  BarChart3, SearchCode, FileStack, ShieldCheck, TrendingUp,
  FileText, Settings, HelpCircle, CircleDot
} from 'lucide-react'
import { run } from '../data/scanData'

const nav = [
  { to: '/', label: 'Overview', icon: Eye },
  { to: '/dashboard', label: 'Dashboard', icon: LayoutGrid },
  { to: '/attack-chain', label: 'Attack Chain', icon: GitBranch },
  { to: '/findings', label: 'Findings', icon: Crosshair, badge: 18 },
  { to: '/owasp-mapping', label: 'OWASP Mapping', icon: Grid3x3 },
  { to: '/risk-analysis', label: 'Risk Analysis', icon: BarChart3 },
  { to: '/explainability', label: 'Explainability', icon: SearchCode },
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
          <ShieldHalf size={18} className="text-white" />
        </div>
        <div>
          <div className="text-[15px] font-bold text-white leading-tight">AegisAI</div>
          <div className="text-[10px] text-slate-500 leading-tight tracking-wide">Validation Platform</div>
        </div>
      </div>

      <div className="px-3 pt-4 pb-2">
        <div className="label-eyebrow px-2 mb-1.5">Active Validation</div>
        <NavLink to="/dashboard" className="block card !bg-base-card2 px-3 py-2.5 hover:border-brand/50 transition-colors">
          <div className="flex items-center gap-1.5 mono text-[13px] font-semibold text-white">
            <CircleDot size={10} className="text-sev-critical pulse-dot" />
            {run.id}
          </div>
          <div className="text-[11px] text-slate-500 mt-0.5 truncate">{run.target}</div>
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
                  : 'text-slate-400 hover:text-slate-200 hover:bg-base-card'
              }`
            }
          >
            <Icon size={16} />
            <span className="flex-1">{label}</span>
            {badge ? (
              <span className="text-[10px] font-bold bg-sev-critical text-white rounded-full px-1.5 py-0.5 leading-none">
                {badge}
              </span>
            ) : null}
          </NavLink>
        ))}
      </nav>

      <div className="px-3 py-3 border-t border-base-border space-y-0.5">
        <button className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-[13px] text-slate-400 hover:text-slate-200 hover:bg-base-card transition-colors">
          <Settings size={16} /> Settings
        </button>
        <button className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-[13px] text-slate-400 hover:text-slate-200 hover:bg-base-card transition-colors">
          <HelpCircle size={16} /> Support
        </button>
        <div className="flex items-center gap-2.5 px-3 pt-3 mt-1 border-t border-base-border">
          <div className="w-7 h-7 rounded-full bg-base-card2 border border-base-border flex items-center justify-center text-[11px] font-bold text-slate-300">
            SE
          </div>
          <div className="leading-tight">
            <div className="text-[12px] font-semibold text-slate-200">Security Engineer</div>
            <div className="text-[10px] text-slate-500">Profile</div>
          </div>
        </div>
      </div>
    </aside>
  )
}
