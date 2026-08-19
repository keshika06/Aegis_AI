import { useState } from 'react'
import { ZoomIn, ZoomOut, Maximize2, RotateCcw, Expand, Map } from 'lucide-react'
import { PageHeader, Panel } from '../components/Panel'
import SeverityBadge from '../components/SeverityBadge'
import { attackChainNodes, attackTimeline } from '../data/scanData'

const statusColor = {
  OBSERVED: '#3b82f6',
  BLOCKED: '#22c55e',
  BYPASSED: '#ef4444',
  SUCCESS: '#f97316',
  FAILED: '#64748b'
}

function riskSeverity(risk) {
  if (risk >= 80) return 'CRITICAL'
  if (risk >= 60) return 'HIGH'
  if (risk >= 35) return 'MEDIUM'
  return 'LOW'
}

export default function AttackChain() {
  const [selected, setSelected] = useState(attackChainNodes[7])

  return (
    <div>
      <PageHeader title="Attack Chain Explorer" subtitle="Correlate security events and visualize the complete attack path." />

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-6">
        <Panel
          title="Attack Chain Graph"
          className="xl:col-span-2"
          right={
            <div className="flex items-center gap-1">
              {[ZoomIn, ZoomOut, Maximize2, RotateCcw, Expand, Map].map((Icon, i) => (
                <button key={i} className="p-1.5 rounded-md text-slate-500 hover:text-slate-200 hover:bg-base-card2 transition-colors">
                  <Icon size={14} />
                </button>
              ))}
            </div>
          }
        >
          <div className="overflow-x-auto scroll-thin pb-2">
            <div className="flex items-stretch gap-0 min-w-[900px]">
              {attackChainNodes.map((n, i) => (
                <div key={n.id} className="flex items-center">
                  <button
                    onClick={() => setSelected(n)}
                    className={`w-[104px] h-[104px] rounded-xl border-2 flex flex-col items-center justify-center gap-1 p-2 text-center transition-all ${
                      selected?.id === n.id ? 'scale-105 shadow-glow' : 'hover:scale-[1.02]'
                    }`}
                    style={{
                      borderColor: statusColor[n.status],
                      backgroundColor: selected?.id === n.id ? '#161d2e' : '#131a29'
                    }}
                  >
                    <span className="text-[11px] font-semibold text-slate-200 leading-tight">{n.name}</span>
                    <span className="text-[9px] font-bold uppercase" style={{ color: statusColor[n.status] }}>{n.status}</span>
                    {n.risk > 0 && <span className="mono text-[10px] text-slate-500">{n.risk}</span>}
                  </button>
                  {i < attackChainNodes.length - 1 && (
                    <div className="w-6 h-0.5 shrink-0" style={{ backgroundColor: '#2a3348' }} />
                  )}
                </div>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-4 mt-4 pt-3 border-t border-base-border flex-wrap">
            {Object.entries(statusColor).map(([k, v]) => (
              <div key={k} className="flex items-center gap-1.5 text-[11px] text-slate-500">
                <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: v }} /> {k}
              </div>
            ))}
          </div>
        </Panel>

        <Panel title={selected ? selected.name : 'Select a Node'} className="min-h-[300px]">
          {selected && (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <SeverityBadge level={riskSeverity(selected.risk)} size="lg" />
                <span className="text-xs font-bold" style={{ color: statusColor[selected.status] }}>{selected.status}</span>
              </div>
              <div className="grid grid-cols-2 gap-3 text-[13px]">
                <div>
                  <div className="text-[11px] text-slate-500">Risk Score</div>
                  <div className="font-bold text-white text-lg">{selected.risk}/100</div>
                </div>
                <div>
                  <div className="text-[11px] text-slate-500">Timestamp</div>
                  <div className="mono text-slate-300">{selected.timestamp}</div>
                </div>
                <div>
                  <div className="text-[11px] text-slate-500">OWASP</div>
                  <div className="mono text-slate-300">{selected.owasp}</div>
                </div>
                <div>
                  <div className="text-[11px] text-slate-500">Evidence</div>
                  <div className="mono text-brand">EV-0042</div>
                </div>
              </div>
              <div className="pt-3 border-t border-base-border">
                <div className="text-[11px] text-slate-500 mb-1">Reason</div>
                <p className="text-[13px] text-slate-300 leading-relaxed">
                  {selected.name === 'Tool Invocation'
                    ? 'The agent invoked a sensitive tool after the guardrail was bypassed, allowing untrusted retrieved content to influence a privileged action.'
                    : `Event correlated as ${selected.status.toLowerCase()} within the active attack chain investigation for RUN-042.`}
                </p>
              </div>
              <div className="flex items-center justify-between text-[12px] pt-3 border-t border-base-border">
                <div className="text-slate-500">Previous Node</div>
                <div className="text-slate-500">Next Node</div>
              </div>
              <div className="flex items-center justify-between text-[13px] font-medium text-slate-300">
                <div>{attackChainNodes[Math.max(0, attackChainNodes.findIndex((n) => n.id === selected.id) - 1)].name}</div>
                <div>{attackChainNodes[Math.min(attackChainNodes.length - 1, attackChainNodes.findIndex((n) => n.id === selected.id) + 1)].name}</div>
              </div>
            </div>
          )}
        </Panel>
      </div>

      <Panel title="Attack Timeline">
        <div className="space-y-0">
          {attackTimeline.map((t, i) => {
            const node = attackChainNodes.find((n) => n.id === t.node)
            return (
              <button
                key={i}
                onClick={() => setSelected(node)}
                className="w-full flex items-center gap-4 py-3 border-b border-base-border last:border-0 hover:bg-base-card2 px-2 -mx-2 rounded transition-colors text-left"
              >
                <span className="mono text-xs text-slate-500 w-20 shrink-0">{t.time}</span>
                <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: statusColor[node?.status] || '#64748b' }} />
                <span className="text-[13px] text-slate-200 flex-1">{t.label}</span>
                <span className="text-[11px] text-slate-500 mono">{node?.name}</span>
              </button>
            )
          })}
        </div>
      </Panel>
    </div>
  )
}
