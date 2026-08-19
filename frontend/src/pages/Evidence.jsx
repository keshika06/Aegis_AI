import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { PageHeader, Panel } from '../components/Panel'
import { evidenceItems } from '../data/scanData'

const types = ['All', 'Prompts', 'Responses', 'Tool Calls', 'RAG', 'Agent', 'Guardrail', 'Network', 'Logs']
const typeMap = { Prompts: 'Prompt', Responses: 'Response', 'Tool Calls': 'Tool Call', RAG: 'RAG', Agent: 'Agent', Guardrail: 'Guardrail', Network: 'Network', Logs: 'Logs' }

export default function Evidence() {
  const [filter, setFilter] = useState('All')
  const [expanded, setExpanded] = useState(null)

  const filtered = useMemo(() => {
    if (filter === 'All') return evidenceItems
    return evidenceItems.filter((e) => e.type === typeMap[filter])
  }, [filter])

  return (
    <div>
      <PageHeader title="Evidence Explorer" subtitle="Trace every security decision back to observable evidence." />

      <div className="flex items-center gap-2 mb-5 flex-wrap">
        {types.map((t) => (
          <button
            key={t}
            onClick={() => setFilter(t)}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wide transition-colors ${
              filter === t ? 'bg-brand text-white' : 'bg-base-card text-slate-400 hover:text-slate-200 border border-base-border'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      <Panel title="Evidence Timeline">
        <div className="space-y-2">
          {filtered.map((e) => {
            const isOpen = expanded === e.id
            return (
              <div key={e.id} className="border border-base-border rounded-lg overflow-hidden">
                <button onClick={() => setExpanded(isOpen ? null : e.id)} className="w-full flex items-center gap-4 p-3 hover:bg-base-card2 transition-colors text-left">
                  {isOpen ? <ChevronDown size={14} className="text-slate-500 shrink-0" /> : <ChevronRight size={14} className="text-slate-500 shrink-0" />}
                  <span className="mono text-brand font-semibold text-sm w-24 shrink-0">{e.id}</span>
                  <span className="text-xs font-bold text-slate-300 border border-base-border rounded px-2 py-0.5 shrink-0">{e.type}</span>
                  <span className="mono text-xs text-slate-500 w-20 shrink-0">{e.timestamp}</span>
                  <span className="text-xs text-slate-400 flex-1">{e.source}</span>
                  <Link to={`/findings/${e.finding}`} onClick={(ev) => ev.stopPropagation()} className="mono text-xs text-slate-400 hover:text-brand">{e.finding}</Link>
                  <span className="text-xs font-bold text-sev-low w-14 text-right shrink-0">{e.confidence}%</span>
                </button>
                {isOpen && (
                  <div className="px-4 pb-4 pt-1 bg-base-card2/40 border-t border-base-border">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[12px] mb-3">
                      <div><div className="text-slate-500">Chain</div><div className="mono text-slate-200">{e.chain}</div></div>
                      <div><div className="text-slate-500">Confidence</div><div className="text-slate-200 font-bold">{e.confidence}%</div></div>
                      <div><div className="text-slate-500">Source</div><div className="text-slate-200">{e.source}</div></div>
                      <div><div className="text-slate-500">Type</div><div className="text-slate-200">{e.type}</div></div>
                    </div>
                    <div className="mono text-[11px] text-slate-500 bg-base-bg rounded-lg p-3 border border-base-border">
                      {`{ "evidence_id": "${e.id}", "type": "${e.type}", "captured_at": "${e.timestamp}", "linked_finding": "${e.finding}", "linked_chain": "${e.chain}" }`}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </Panel>
    </div>
  )
}
