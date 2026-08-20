import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Search } from 'lucide-react'
import { PageHeader, Panel } from '../components/Panel'
import SeverityBadge from '../components/SeverityBadge'
import { findings } from '../data/scanData'

const sevTabs = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function Findings() {
  const [tab, setTab] = useState('ALL')
  const [query, setQuery] = useState('')

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      const sevMatch = tab === 'ALL' || f.severity === tab
      const qMatch = query === '' || f.title.toLowerCase().includes(query.toLowerCase()) || f.id.toLowerCase().includes(query.toLowerCase())
      return sevMatch && qMatch
    })
  }, [tab, query])

  const counts = {
    ALL: findings.length,
    CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
    HIGH: findings.filter((f) => f.severity === 'HIGH').length,
    MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
    LOW: findings.filter((f) => f.severity === 'LOW').length
  }

  return (
    <div>
      <PageHeader title="Security Findings" subtitle="Prioritized, evidence-backed findings from the validation run." />

      <div className="flex items-center gap-2 mb-4 flex-wrap">
        {sevTabs.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wide transition-colors ${
              tab === t ? 'bg-brand text-white' : 'bg-base-card text-slate-400 hover:text-slate-200 border border-base-border'
            }`}
          >
            {t} <span className="opacity-70 ml-1">{counts[t]}</span>
          </button>
        ))}
        <div className="flex-1" />
        <div className="relative w-64">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search findings..."
            className="w-full bg-base-card border border-base-border rounded-lg pl-8 pr-3 py-1.5 text-[13px] text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-brand/60"
          />
        </div>
      </div>

      <Panel>
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left text-[11px] uppercase text-slate-500 border-b border-base-border">
                <th className="py-2 pr-3 font-semibold">Finding ID</th>
                <th className="py-2 pr-3 font-semibold">Title</th>
                <th className="py-2 pr-3 font-semibold">OWASP</th>
                <th className="py-2 pr-3 font-semibold">Severity</th>
                <th className="py-2 pr-3 font-semibold">Risk</th>
                <th className="py-2 pr-3 font-semibold">Confidence</th>
                <th className="py-2 pr-3 font-semibold">Attack Type</th>
                <th className="py-2 pr-3 font-semibold">Evidence</th>
                <th className="py-2 pr-3 font-semibold">Verdict</th>
                <th className="py-2 pr-3 font-semibold">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr key={f.id} className="border-b border-base-border last:border-0 hover:bg-base-card2">
                  <td className="py-2.5 pr-3"><Link to={`/findings/${f.id}`} className="mono text-brand font-semibold">{f.id}</Link></td>
                  <td className="py-2.5 pr-3 text-slate-200"><Link to={`/findings/${f.id}`}>{f.title}</Link></td>
                  <td className="py-2.5 pr-3 mono text-slate-400">{f.owasp}</td>
                  <td className="py-2.5 pr-3"><SeverityBadge level={f.severity} /></td>
                  <td className="py-2.5 pr-3 font-bold text-white">{f.risk}</td>
                  <td className="py-2.5 pr-3 text-slate-400">{f.confidence}%</td>
                  <td className="py-2.5 pr-3 text-slate-400">{f.attackType}</td>
                  <td className="py-2.5 pr-3 text-slate-400">{f.evidence}</td>
                  <td className="py-2.5 pr-3"><SeverityBadge level={f.verdict} /></td>
                  <td className="py-2.5 pr-3 mono text-slate-500 text-xs">{f.lastSeen}</td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={10} className="py-8 text-center text-slate-500">No findings match this filter.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  )
}
