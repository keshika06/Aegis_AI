import { useState } from 'react'
import { ChevronDown, ChevronRight, Wrench, ShieldPlus, Radar } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, PieChart, Pie, Cell } from 'recharts'
import { PageHeader, Panel } from '../components/Panel'
import SeverityBadge from '../components/SeverityBadge'
import { controlResults, outcomeDistribution, run, attackScenarios } from '../data/scanData'

// A high acceptance rate means the target let that representation through.
function rateColor(rate) {
  if (rate >= 75) return '#ef4444'
  if (rate >= 40) return '#eab308'
  return '#22c55e'
}

function Remedy({ icon: Icon, title, items, colour }) {
  if (!items || items.length === 0) return null
  return (
    <div>
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wide font-bold mb-2" style={{ color: colour }}>
        <Icon size={13} /> {title}
      </div>
      <ol className="space-y-1.5">
        {items.map((t, i) => (
          <li key={i} className="flex gap-2.5 text-[12px] text-slate-300 leading-relaxed">
            <span className="mono text-[10px] shrink-0 mt-0.5" style={{ color: colour }}>{String(i + 1).padStart(2, '0')}</span>
            <span>{t}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}

export default function SecurityControls() {
  const [expanded, setExpanded] = useState(attackScenarios[0]?.id ?? null)
  const noControlObserved = run.baseRejectedCases === 0

  return (
    <div>
      <PageHeader
        title="Target Control Evaluation"
        subtitle="How the target's own controls responded to each representation of the same objective. AegisAI records the target's decision; it never makes one."
      />

      {noControlObserved && (
        <div className="mb-5 p-4 rounded-lg border border-sev-medium/40 bg-sev-mediumBg">
          <div className="text-sev-medium font-bold text-sm mb-1">No input control observed</div>
          <p className="text-[13px] text-slate-300">
            The target rejected none of the base-case probes, so there was no input filter to evade
            and the evasion rate is reported as zero. That is a materially different result from a
            control holding firm — it means no such control was seen at all.
          </p>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mb-5">
        {controlResults.map((c) => (
          <Panel key={c.family}>
            <div className="text-[13px] font-bold text-slate-200 uppercase tracking-wide mb-3">{c.name}</div>
            <div className="grid grid-cols-3 gap-2 text-center mb-3">
              <div><div className="text-[10px] text-slate-500">Tested</div><div className="font-bold text-slate-200">{c.tested}</div></div>
              <div><div className="text-[10px] text-slate-500">Refused</div><div className="font-bold text-sev-info">{c.refused}</div></div>
              <div><div className="text-[10px] text-slate-500">Accepted</div><div className="font-bold text-sev-critical">{c.accepted}</div></div>
            </div>
            <div className="flex items-center justify-between text-[11px] text-slate-500 mb-1">
              <span>Acceptance rate</span>
              <span className="font-bold" style={{ color: rateColor(c.acceptanceRate) }}>{c.acceptanceRate}%</span>
            </div>
            <div className="h-2 rounded-full bg-base-card2 overflow-hidden">
              <div className="h-full rounded-full" style={{ width: `${c.acceptanceRate}%`, backgroundColor: rateColor(c.acceptanceRate) }} />
            </div>
            {c.evadedBaseRejection > 0 && (
              <div className="mt-2 text-[11px] text-sev-critical">
                {c.evadedBaseRejection} evaded a base-case rejection
              </div>
            )}
          </Panel>
        ))}
        {controlResults.length === 0 && (
          <Panel><div className="text-sm text-slate-500">No evasion families were generated for this scan.</div></Panel>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-5">
        <Panel title="Per-family outcomes — accepted vs refused" className="lg:col-span-2">
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={controlResults} layout="vertical" margin={{ left: 30 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#232b3d" horizontal={false} />
              <XAxis type="number" tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} />
              <YAxis type="category" dataKey="name" width={130} tick={{ fill: '#a8b3cc', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} />
              <Tooltip contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="refused" stackId="a" fill="#3b82f6" name="Refused by LLM" />
              <Bar dataKey="rejected" stackId="a" fill="#22c55e" name="Rejected by control" />
              <Bar dataKey="accepted" stackId="a" fill="#ef4444" radius={[0, 4, 4, 0]} name="Accepted" />
            </BarChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Outcome Distribution">
          <ResponsiveContainer width="100%" height={190}>
            <PieChart>
              <Pie data={outcomeDistribution} dataKey="value" innerRadius={45} outerRadius={72} paddingAngle={2}>
                {outcomeDistribution.map((d, i) => <Cell key={i} fill={d.color} />)}
              </Pie>
              <Tooltip contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="grid grid-cols-1 gap-1.5 mt-2">
            {outcomeDistribution.map((d) => (
              <div key={d.name} className="flex items-center justify-between text-xs text-slate-400">
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} /> {d.name}</span>
                <span className="font-semibold text-slate-300">{d.value}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <Panel title={`Remediation by attack scenario — ${attackScenarios.length} objective${attackScenarios.length === 1 ? '' : 's'}`} className="mb-5">
        <p className="text-[13px] text-slate-400 mb-4">
          Grouped by objective rather than by probe: several representations of one weakness are
          one thing to fix. Each scenario's guidance is derived from what that attack actually did
          — the contract rule that broke, the runtime events the target emitted, its control
          decision, and the representation that got through — so no two scenarios carry the same
          advice unless they genuinely earned it.
        </p>

        <div className="space-y-2">
          {attackScenarios.length === 0 && (
            <div className="text-sm text-slate-500 py-6 text-center">
              No confirmed attack scenarios in this scan, so there is nothing to remediate.
            </div>
          )}

          {attackScenarios.map((sc) => {
            const isOpen = expanded === sc.id
            return (
              <div key={sc.id} className="border border-base-border rounded-lg overflow-hidden">
                <button
                  onClick={() => setExpanded(isOpen ? null : sc.id)}
                  className="w-full flex items-center gap-3 p-3 hover:bg-base-card2 transition-colors text-left"
                >
                  {isOpen ? <ChevronDown size={14} className="text-slate-500 shrink-0" />
                          : <ChevronRight size={14} className="text-slate-500 shrink-0" />}
                  <SeverityBadge level={sc.severity} />
                  <span className="flex-1 min-w-0">
                    <span className="block text-[13px] text-slate-200 truncate">{sc.title}</span>
                    <span className="block text-[11px] text-slate-500 truncate">{sc.summary}</span>
                  </span>
                  <span className="hidden md:flex items-center gap-3 text-[11px] text-slate-500 shrink-0">
                    <span className="mono">{sc.owasp ?? '—'}</span>
                    <span>{sc.probes} probe{sc.probes === 1 ? '' : 's'}</span>
                  </span>
                  <span className="mono text-sm font-bold text-white w-10 text-right shrink-0">{sc.risk}</span>
                </button>

                {isOpen && (
                  <div className="px-4 pb-4 pt-3 bg-base-card2/40 border-t border-base-border space-y-4">
                    <div className="flex flex-wrap gap-1.5">
                      {sc.transformations.map((t) => (
                        <span key={t} className="mono text-[10px] px-2 py-0.5 rounded border border-base-border text-slate-400">
                          {t === 'none' ? 'sent as written' : t}
                        </span>
                      ))}
                      {sc.boundaries.map((b) => (
                        <span key={b} className="mono text-[10px] px-2 py-0.5 rounded border border-sev-critical/40 text-sev-critical">
                          {b}
                        </span>
                      ))}
                    </div>

                    <Remedy icon={Wrench} title="Mitigation — restore the broken invariant" items={sc.mitigations} colour="#ef4444" />
                    <Remedy icon={ShieldPlus} title="Preventive — stop it reaching that point" items={sc.preventive} colour="#f97316" />
                    <Remedy icon={Radar} title="Detection — catch a recurrence" items={sc.detection} colour="#3b82f6" />
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </Panel>

      <Panel title="Reading these numbers">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-lg border border-sev-low/40 bg-sev-lowBg">
            <div className="text-sev-low font-bold text-sm mb-1">Rejected by target control</div>
            <p className="text-[13px] text-slate-300">A control in the target detected and rejected the probe before it reached the model. This is the only outcome that demonstrates a control working.</p>
          </div>
          <div className="p-4 rounded-lg border border-sev-info/40 bg-sev-infoBg">
            <div className="text-sev-info font-bold text-sm mb-1">Refused by the model</div>
            <p className="text-[13px] text-slate-300">The probe reached the model, which declined on its own. The model saved you here — no deployed control did. Alignment is not a security control.</p>
          </div>
          <div className="p-4 rounded-lg border border-sev-critical/40 bg-sev-criticalBg">
            <div className="text-sev-critical font-bold text-sm mb-1">Accepted</div>
            <p className="text-[13px] text-slate-300">Nothing stopped the probe. Whether that produced impact is decided by evidence, not by how the response reads.</p>
          </div>
        </div>
        <p className="text-[12px] text-slate-500 mt-4">
          These are transformation families, not named controls. AegisAI evaluates a target as a
          black box — it never learns which controls a target implements, only how the target
          responded, so naming controls it never observed would be inventing knowledge.
        </p>
      </Panel>
    </div>
  )
}
