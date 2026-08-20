import { Link } from 'react-router-dom'
import { ShieldAlert, ListChecks, Crosshair, Grid3x3, ShieldOff, CheckCircle2, ArrowRight, GitBranch } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, PieChart, Pie, Cell } from 'recharts'
import { PageHeader, Panel, Bar } from '../components/Panel'
import KpiCard from '../components/KpiCard'
import RiskGauge from '../components/RiskGauge'
import SeverityBadge from '../components/SeverityBadge'
import { run, riskRuns, owaspCategories, findings, riskComponents, severityColor, chainSummary, attackChains } from '../data/scanData'

const donutData = [
  { name: 'Critical', value: run.critical, color: severityColor.CRITICAL.text },
  { name: 'High', value: run.high, color: severityColor.HIGH.text },
  { name: 'Medium', value: run.medium, color: severityColor.MEDIUM.text },
  { name: 'Low', value: run.low, color: severityColor.LOW.text }
]

const AXIS_TITLE = {
  likelihood: 'Likelihood — how readily this path is walked again',
  impact: 'Impact — what it costs when it is'
}

export default function Dashboard() {
  const topOwasp = [...owaspCategories].filter((o) => o.findings > 0).sort((a, b) => b.risk - a.risk).slice(0, 5)
  const topFindings = [...findings].sort((a, b) => b.risk - a.risk).slice(0, 5)
  const hasBaseline = run.previousRisk !== null && run.previousRisk !== undefined
  const delta = hasBaseline ? run.risk - run.previousRisk : null
  const worstChain = attackChains[0] ?? null

  return (
    <div>
      <PageHeader
        title="Security Command Center"
        subtitle="Evidence-driven security posture and AI application validation overview."
        right={
          <div>
            <div className="mono text-brand font-bold text-sm">{run.id}</div>
            <div className="text-xs text-slate-500">{run.status} · {run.date}</div>
          </div>
        }
      />

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4 mb-6">
        <KpiCard
          icon={ShieldAlert}
          label="Posture Score"
          value={run.risk}
          sub={hasBaseline ? `${run.severity} · vs previous run` : `${run.severity} · first run`}
          delta={delta}
        />
        <KpiCard icon={ListChecks} label="Total Findings" value={run.totalFindings} sub={`${run.critical} Critical · ${run.high} High`} />
        <KpiCard
          icon={Crosshair}
          label="Attack Success Rate"
          value={run.attackSuccessRate === null ? '—' : `${run.attackSuccessRate}%`}
          sub="objectives confirmed"
          delta={run.attackSuccessDelta}
          deltaSuffix="%"
        />
        <KpiCard icon={Grid3x3} label="OWASP Coverage" value={`${run.owaspAffected}/${run.owaspTotal}`} sub="categories affected" />
        <KpiCard icon={ShieldOff} label="Guardrail Evasion" value={`${run.guardrailEvasion}%`} valueColor="#ef4444" sub={run.baseRejectedCases === 0 ? 'no input control observed' : 'successful bypasses'} />
        <KpiCard
          icon={CheckCircle2}
          label="Evidence Confidence"
          value={run.evidenceConfidence === null ? '—' : `${run.evidenceConfidence}%`}
          sub={run.evidenceConfidence === null ? 'no deterministic evidence' : 'mean across deterministic proof'}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-6">
        <Panel title="Overall Security Posture" className="flex flex-col items-center">
          <RiskGauge score={run.risk} label={run.severity} />
          {hasBaseline ? (
            <div className="w-full grid grid-cols-3 gap-2 text-center mt-2 pt-3 border-t border-base-border">
              <div>
                <div className="text-[11px] text-slate-500">Previous Run</div>
                <div className="font-bold text-slate-300">{run.previousRisk}</div>
              </div>
              <div>
                <div className="text-[11px] text-slate-500">Current Run</div>
                <div className="font-bold text-white">{run.risk}</div>
              </div>
              <div>
                <div className="text-[11px] text-slate-500">Change</div>
                <div className={`font-bold ${delta > 0 ? 'text-sev-high' : delta < 0 ? 'text-sev-low' : 'text-slate-400'}`}>
                  {delta > 0 ? '+' : ''}{delta}
                </div>
              </div>
            </div>
          ) : (
            <div className="w-full mt-2 pt-3 border-t border-base-border text-[11px] text-slate-500 text-center">
              First recorded run for this target — no baseline to compare against.
            </div>
          )}
        </Panel>

        <Panel title="What drove the worst finding's score" className="lg:col-span-2">
          {riskComponents.length === 0 && <div className="text-sm text-slate-500">No scored findings in this scan.</div>}
          {['likelihood', 'impact'].map((axis) => {
            const rows = riskComponents.filter((c) => c.axis === axis && c.established)
            if (rows.length === 0) return null
            return (
              <div key={axis} className="mb-4 last:mb-0">
                <div className="text-[11px] uppercase tracking-wide text-slate-500 mb-2">{AXIS_TITLE[axis]}</div>
                {rows.map((c) => (
                  <Bar key={c.label} label={c.label} score={c.score} color={axis === 'impact' ? '#ef4444' : '#f97316'} sub={c.explain} />
                ))}
              </div>
            )
          })}
        </Panel>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-6">
        <Panel title="Posture Score Over Validation Runs" className="lg:col-span-2">
          {riskRuns.length > 1 ? (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={riskRuns} margin={{ left: -20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#232b3d" />
                <XAxis dataKey="run" tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} tickLine={false} />
                <YAxis tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} tickLine={false} domain={[0, 100]} />
                <Tooltip contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }} />
                <Line type="monotone" dataKey="risk" name="Posture" stroke="#7c5cff" strokeWidth={2.5} dot={{ r: 4, fill: '#7c5cff' }} activeDot={{ r: 6 }} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[220px] flex items-center justify-center text-sm text-slate-500 text-center px-6">
              Only one run is recorded for this target. A line through a single point would imply a
              history that was never measured.
            </div>
          )}
        </Panel>

        <Panel title="Finding Severity Distribution">
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={donutData} dataKey="value" innerRadius={50} outerRadius={75} paddingAngle={3}>
                {donutData.map((d, i) => <Cell key={i} fill={d.color} />)}
              </Pie>
              <Tooltip contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="grid grid-cols-2 gap-2 mt-2">
            {donutData.map((d) => (
              <div key={d.name} className="flex items-center gap-1.5 text-xs text-slate-400">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} /> {d.name} ({d.value})
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <Panel title="OWASP Risk Snapshot" icon={Grid3x3} right={<Link to="/owasp-mapping" className="text-xs text-brand font-semibold flex items-center gap-1">View Full OWASP Mapping <ArrowRight size={12} /></Link>} className="mb-6">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {topOwasp.length === 0 && <div className="text-sm text-slate-500">No OWASP category was affected in this scan.</div>}
          {topOwasp.map((o) => (
            <Link key={o.id} to="/owasp-mapping" className="p-3 rounded-lg border border-base-border bg-base-card2 hover:border-brand/50 transition-colors">
              <div className="mono text-xs font-bold text-slate-300 mb-1">{o.id}</div>
              <div className="text-[11px] text-slate-500 mb-2 truncate">{o.name}</div>
              <SeverityBadge level={o.severity} />
              <div className="text-xs text-slate-400 mt-2">{o.findings} finding{o.findings !== 1 ? 's' : ''}</div>
            </Link>
          ))}
        </div>
      </Panel>

      <Panel title="Top Security Findings" icon={Crosshair} right={<Link to="/findings" className="text-xs text-brand font-semibold flex items-center gap-1">View All Findings <ArrowRight size={12} /></Link>} className="mb-6">
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left text-[11px] uppercase text-slate-500 border-b border-base-border">
                <th className="py-2 pr-3 font-semibold">ID</th>
                <th className="py-2 pr-3 font-semibold">Finding</th>
                <th className="py-2 pr-3 font-semibold">OWASP</th>
                <th className="py-2 pr-3 font-semibold">Severity</th>
                <th className="py-2 pr-3 font-semibold">Risk</th>
                <th className="py-2 pr-3 font-semibold">Evidence</th>
                <th className="py-2 pr-3 font-semibold">Verdict</th>
              </tr>
            </thead>
            <tbody>
              {topFindings.length === 0 && (
                <tr><td colSpan={7} className="py-8 text-center text-slate-500">No findings in this scan.</td></tr>
              )}
              {topFindings.map((f) => (
                <tr key={f.id} className="border-b border-base-border last:border-0 hover:bg-base-card2">
                  <td className="py-2.5 pr-3"><Link to={`/findings/${f.id}`} className="mono text-brand font-semibold">{f.id}</Link></td>
                  <td className="py-2.5 pr-3 text-slate-200">{f.title}</td>
                  <td className="py-2.5 pr-3 mono text-slate-400">{f.owasp}</td>
                  <td className="py-2.5 pr-3"><SeverityBadge level={f.severity} /></td>
                  <td className="py-2.5 pr-3 font-bold text-white">{f.risk}</td>
                  <td className="py-2.5 pr-3 text-slate-400">{f.evidence}</td>
                  <td className="py-2.5 pr-3"><SeverityBadge level={f.verdict} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Worst Attack Chain" icon={GitBranch} right={<Link to="/attack-chain" className="text-xs text-brand font-semibold flex items-center gap-1">Open Attack Chain Explorer <ArrowRight size={12} /></Link>}>
        {worstChain ? (
          <>
            <div className="text-[13px] text-slate-300 font-semibold mb-3">{worstChain.findingTitle}</div>
            <div className="flex items-center gap-2 mono text-[12px] text-slate-300 flex-wrap">
              {worstChain.phases.map((p, i, arr) => (
                <span key={p.n} className="flex items-center gap-2">
                  <span
                    className="px-2.5 py-1 rounded border"
                    style={
                      p.status === 'failed'
                        ? { borderColor: '#5c2026', background: '#3a1518', color: '#ef4444' }
                        : p.status === 'ok'
                        ? { borderColor: '#1c4d2e', background: '#12301d', color: '#22c55e' }
                        : { borderColor: '#2a3348', background: '#1c2333', color: '#94a3b8' }
                    }
                    title={p.headline}
                  >
                    {p.name}
                  </span>
                  {i < arr.length - 1 && <span className="text-slate-600">→</span>}
                </span>
              ))}
            </div>
            <div className="flex items-center gap-8 mt-4 pt-3 border-t border-base-border flex-wrap">
              <div>
                <div className="text-[11px] text-slate-500">Attack Chain Risk</div>
                <div className="text-xl font-bold text-sev-critical">{chainSummary.risk}/100</div>
              </div>
              <div>
                <div className="text-[11px] text-slate-500">Furthest phase a defence failed at</div>
                <div className="text-sm font-semibold text-slate-200">{chainSummary.worstPhaseName ?? '—'}</div>
              </div>
              <div>
                <div className="text-[11px] text-slate-500">Defence layers breached</div>
                <div className="text-sm font-semibold text-slate-200">{chainSummary.breachedLayers}/{chainSummary.totalLayers}</div>
              </div>
            </div>
          </>
        ) : (
          <div className="text-sm text-slate-500">No attack chain was built for this scan.</div>
        )}
      </Panel>
    </div>
  )
}
