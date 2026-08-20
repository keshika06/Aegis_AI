import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Search } from 'lucide-react'
import { PageHeader, Panel } from '../components/Panel'
import SeverityBadge from '../components/SeverityBadge'
import { owaspCategories, findings, severityColor } from '../data/scanData'

const sevTabs = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const rows = ['Critical', 'High', 'Medium', 'Low']

function cellCount(catId, row) {
  return findings.filter((f) => f.owasp === catId && f.severity === row.toUpperCase()).length
}

export default function OwaspMapping() {
  const [tab, setTab] = useState('ALL')
  const [query, setQuery] = useState('')
  const [activeCell, setActiveCell] = useState(null)

  const filteredCats = useMemo(() => {
    return owaspCategories.filter((o) => {
      const sevMatch = tab === 'ALL' || o.severity === tab
      const qMatch = query === '' || o.name.toLowerCase().includes(query.toLowerCase()) || o.id.toLowerCase().includes(query.toLowerCase())
      return sevMatch && qMatch
    })
  }, [tab, query])

  const affected = owaspCategories.filter((o) => o.findings > 0)
  const mostAffected = [...affected].sort((a, b) => b.findings - a.findings)[0]
  const highestRisk = [...affected].sort((a, b) => b.risk - a.risk)[0]
  // null when the export had no previous scan to compare against, which is a
  // different statement from "nothing is new".
  const newlyDetected = owaspCategories.some((o) => o.isNew === null)
    ? null
    : owaspCategories.filter((o) => o.isNew)

  return (
    <div>
      <PageHeader title="OWASP AI Security Risk Mapping" subtitle="Map observed findings to OWASP LLM Top 10 categories and visualize security exposure." />

      <div className="flex items-center gap-2 mb-5 flex-wrap">
        {sevTabs.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wide transition-colors ${
              tab === t ? 'bg-brand text-white' : 'bg-base-card text-slate-400 hover:text-slate-200 border border-base-border'
            }`}
          >
            {t}
          </button>
        ))}
        <div className="flex-1" />
        <div className="relative w-64">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search OWASP category..."
            className="w-full bg-base-card border border-base-border rounded-lg pl-8 pr-3 py-1.5 text-[13px] text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-brand/60"
          />
        </div>
      </div>

      <Panel title="OWASP Severity Heatmap" className="mb-5">
        <div className="overflow-x-auto">
          <table className="w-full border-separate" style={{ borderSpacing: 6 }}>
            <thead>
              <tr>
                <th></th>
                {owaspCategories.map((o) => (
                  <th key={o.id} className="mono text-[11px] text-slate-400 font-semibold pb-1">{o.id}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row}>
                  <td className="text-[11px] text-slate-500 font-semibold pr-2 uppercase text-right w-20">{row}</td>
                  {owaspCategories.map((o) => {
                    const count = cellCount(o.id, row)
                    const sevKey = row.toUpperCase()
                    const active = activeCell?.cat === o.id && activeCell?.row === row
                    return (
                      <td key={o.id}>
                        <button
                          onClick={() => setActiveCell(count > 0 ? { cat: o.id, row } : null)}
                          className="w-16 h-14 rounded-md flex flex-col items-center justify-center transition-all"
                          style={{
                            backgroundColor: count > 0 ? severityColor[sevKey].bg : '#161d2e',
                            border: `1px solid ${count > 0 ? severityColor[sevKey].border : '#232b3d'}`,
                            outline: active ? '2px solid #7c5cff' : 'none'
                          }}
                        >
                          <span className="text-sm font-bold" style={{ color: count > 0 ? severityColor[sevKey].text : '#3a4258' }}>
                            {count || '—'}
                          </span>
                        </button>
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {activeCell && (
          <div className="mt-4 pt-3 border-t border-base-border">
            <div className="text-xs text-slate-500 mb-2">Filtered: <span className="mono text-brand">{activeCell.cat}</span> · {activeCell.row}</div>
            <div className="space-y-1.5">
              {findings.filter((f) => f.owasp === activeCell.cat && f.severity === activeCell.row.toUpperCase()).map((f) => (
                <Link key={f.id} to={`/findings/${f.id}`} className="flex items-center gap-3 text-[13px] text-slate-300 hover:text-white">
                  <span className="mono text-brand text-xs">{f.id}</span> {f.title}
                </Link>
              ))}
            </div>
          </div>
        )}
      </Panel>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-5">
        <Panel><div className="label-eyebrow mb-1">Most Affected Category</div><div className="text-lg font-bold text-white">{mostAffected?.id}</div><div className="text-xs text-slate-500">{mostAffected?.name} · {mostAffected?.findings} findings</div></Panel>
        <Panel><div className="label-eyebrow mb-1">Highest Risk Category</div><div className="text-lg font-bold text-sev-critical">{highestRisk?.id}</div><div className="text-xs text-slate-500">{highestRisk?.name} · risk {highestRisk?.risk}</div></Panel>
        <Panel>
          <div className="label-eyebrow mb-1">Newly Detected</div>
          {newlyDetected === null ? (
            <>
              <div className="text-lg font-bold text-slate-400">—</div>
              <div className="text-xs text-slate-500">No previous scan of this target to compare against</div>
            </>
          ) : newlyDetected.length === 0 ? (
            <>
              <div className="text-lg font-bold text-slate-400">None</div>
              <div className="text-xs text-slate-500">No category appeared that the previous run did not already show</div>
            </>
          ) : (
            <>
              <div className="text-lg font-bold text-sev-high">{newlyDetected.map((o) => o.id).join(', ')}</div>
              <div className="text-xs text-slate-500">{newlyDetected.map((o) => o.name).join(' · ')} — first observed this run</div>
            </>
          )}
        </Panel>
      </div>

      <Panel title="OWASP Category Details">
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filteredCats.map((o) => (
            <div key={o.id} className="p-4 rounded-lg border border-base-border bg-base-card2">
              <div className="flex items-center justify-between mb-1">
                <span className="mono font-bold text-slate-200">{o.id}</span>
                <SeverityBadge level={o.severity} />
              </div>
              <div className="text-[13px] text-slate-300 mb-3">{o.name}</div>
              <div className="grid grid-cols-2 gap-2 text-[12px] text-slate-400 mb-3">
                <div>Findings: <span className="font-bold text-slate-200">{o.findings}</span></div>
                <div>Risk: <span className="font-bold text-slate-200">{o.risk}</span></div>
                <div>Evidence: <span className="font-bold text-slate-200">{o.evidence}</span></div>
                <div>Chains: <span className="font-bold text-slate-200">{o.chains}</span></div>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className={`font-bold ${o.status === 'OPEN' ? 'text-sev-high' : 'text-sev-low'}`}>{o.status}</span>
                {o.isNew && <span className="font-bold text-sev-high">NEW THIS RUN</span>}
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}
