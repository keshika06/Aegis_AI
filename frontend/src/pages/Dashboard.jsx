import { Link } from 'react-router-dom'
import {
  ShieldAlert, ListChecks, Crosshair, Grid3x3, ShieldOff, CheckCircle2,
  ArrowRight, GitBranch
} from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, PieChart, Pie, Cell } from 'recharts'
import { PageHeader, Panel, Bar } from '../components/Panel'
import KpiCard from '../components/KpiCard'
import RiskGauge from '../components/RiskGauge'
import SeverityBadge from '../components/SeverityBadge'
import {
  run, riskRuns, owaspCategories, findings, riskComponents, severityColor,
  chainSummary, attackChains, recommendedActions
} from '../data/scanData'
import { useTokens } from '../theme'

const donutData = [
  { name: 'Critical', value: run.critical, color: severityColor.CRITICAL.text },
  { name: 'High', value: run.high, color: severityColor.HIGH.text },
  { name: 'Medium', value: run.medium, color: severityColor.MEDIUM.text },
  { name: 'Low', value: run.low, color: severityColor.LOW.text }
]

// Likelihood and impact multiply, so a reader comparing a factor against the
// wrong axis would draw the wrong conclusion about which one to fix.
const AXIS_TITLE = {
  likelihood: 'Likelihood — how readily this path is walked again',
  impact: 'Impact — what it costs when it is'
}

const phaseStyleFor = (t) => ({
  failed: { borderColor: 'var(--sev-critical-border)', background: 'var(--sev-critical-bg)', color: t.critical },
  ok: { borderColor: 'var(--sev-low-border)', background: 'var(--sev-low-bg)', color: t.low },
  info: { borderColor: 'var(--border2)', background: 'var(--sev-neutral-bg)', color: 'var(--text-muted)' }
})

export default function Dashboard() {
  const t = useTokens()
  const PHASE_STYLE = phaseStyleFor(t)
  const topOwasp = [...owaspCategories].filter((o) => o.findings > 0).sort((a, b) => b.risk - a.risk).slice(0, 5)
  const topFindings = [...findings].sort((a, b) => b.risk - a.risk).slice(0, 8)
  // No prior scan means no delta. Subtracting from null yields the current
  // score itself, which would read as a change that never happened.
  const hasBaseline = run.previousRisk !== null && run.previousRisk !== undefined
  const delta = hasBaseline ? run.risk - run.previousRisk : null
  const worstChain = attackChains[0] ?? null

  return (
    <div>
      <PageHeader
        title="Security Command Center"
        subtitle="Evidence-driven risk assessment for the current AI application validation run."
        right={
          <div>
            <div className="mono text-brand font-bold text-sm">{run.id}</div>
            <div className="text-xs text-content-dim">{run.status} · {run.date}</div>
          </div>
        }
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <KpiCard
          icon={ShieldAlert}
          label="Risk Score"
          value={`${run.risk}/100`}
          sub={run.severity}
          trend={hasBaseline ? `${Math.abs(delta)} from previous` : null}
          trendUp={delta > 0}
        />
        <KpiCard icon={ListChecks} label="Total Findings" value={run.totalFindings} sub={`${run.confirmed} confirmed`} />
        <KpiCard icon={Crosshair} label="Critical" value={run.critical} valueColor={t.critical} sub={`${run.high} high · ${run.medium} medium`} />
        <KpiCard
          icon={Crosshair}
          label="Attack Success Rate"
          value={run.attackSuccessRate === null ? '—' : `${run.attackSuccessRate}%`}
          sub="objectives confirmed"
          trend={run.attackSuccessDelta !== null && run.attackSuccessDelta !== undefined ? `${Math.abs(run.attackSuccessDelta)}%` : null}
          trendUp={run.attackSuccessDelta > 0}
        />
        <KpiCard icon={Grid3x3} label="OWASP Coverage" value={`${run.owaspAffected}/${run.owaspTotal}`} sub="categories affected" />
        <KpiCard icon={GitBranch} label="Attack Chains" value={run.attackChains} sub="objectives reaching a finding" />
        <KpiCard
          icon={ShieldOff}
          label="Guardrail Evasion"
          value={`${run.guardrailEvasion}%`}
          valueColor={t.critical}
          sub={run.baseRejectedCases === 0 ? 'no input control observed' : 'successful bypasses'}
        />
        <KpiCard
          icon={CheckCircle2}
          label="Evidence Confidence"
          value={run.evidenceConfidence === null ? '—' : `${run.evidenceConfidence}%`}
          sub={run.evidenceConfidence === null ? 'no deterministic evidence' : 'mean across deterministic proof'}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-6">
        <Panel title="Overall Risk Score" className="flex flex-col items-center">
          <RiskGauge score={run.risk} label={run.severity} />
          {hasBaseline ? (
            <div className="w-full grid grid-cols-3 gap-2 text-center mt-2 pt-3 border-t border-base-border">
              <div>
                <div className="text-[11px] text-content-dim">Previous Run</div>
                <div className="font-bold text-content">{run.previousRisk}</div>
              </div>
              <div>
                <div className="text-[11px] text-content-dim">Current Run</div>
                <div className="font-bold text-content">{run.risk}</div>
              </div>
              <div>
                <div className="text-[11px] text-content-dim">Change</div>
                <div className={`font-bold ${delta > 0 ? 'text-sev-high' : delta < 0 ? 'text-sev-low' : 'text-content-muted'}`}>
                  {delta > 0 ? '+' : ''}{delta}
                </div>
              </div>
            </div>
          ) : (
            <div className="w-full mt-2 pt-3 border-t border-base-border text-[11px] text-content-dim text-center">
              First recorded run for this target — no baseline to compare against.
            </div>
          )}
        </Panel>

        <Panel
          title="What drove the worst finding's score"
          className="lg:col-span-2"
          right={<Link to="/explainability" className="text-xs text-brand font-semibold flex items-center gap-1">Full attribution <ArrowRight size={12} /></Link>}
        >
          {riskComponents.length === 0 && <div className="text-sm text-content-dim">No scored findings in this scan.</div>}
          {['likelihood', 'impact'].map((axis) => {
            const rows = riskComponents.filter((c) => c.axis === axis && c.established)
            if (rows.length === 0) return null
            return (
              <div key={axis} className="mb-4 last:mb-0">
                <div className="text-[11px] uppercase tracking-wide text-content-dim mb-2">{AXIS_TITLE[axis]}</div>
                {rows.map((c) => (
                  <Bar key={c.label} label={c.label} score={c.score} color={axis === 'impact' ? '#ef4444' : t.high} sub={c.explain} />
                ))}
              </div>
            )
          })}
        </Panel>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-6">
        <Panel title="Risk Score Over Validation Runs" className="lg:col-span-2">
          {riskRuns.length > 1 ? (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={riskRuns} margin={{ left: -20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={t.grid} />
                <XAxis dataKey="run" tick={{ fill: t.axis, fontSize: 11 }} axisLine={{ stroke: t.grid }} tickLine={false} />
                <YAxis tick={{ fill: t.axis, fontSize: 11 }} axisLine={{ stroke: t.grid }} tickLine={false} domain={[0, 100]} />
                <Tooltip contentStyle={{ background: t.tooltipBg, border: `1px solid ${t.tooltipBorder}`, borderRadius: 8, fontSize: 12 }} />
                <Line type="monotone" dataKey="risk" name="Risk" stroke={t.brand} strokeWidth={2.5} dot={{ r: 4, fill: t.brand }} activeDot={{ r: 6 }} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[220px] flex items-center justify-center text-sm text-content-dim text-center px-6">
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
              <Tooltip contentStyle={{ background: t.tooltipBg, border: `1px solid ${t.tooltipBorder}`, borderRadius: 8, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="grid grid-cols-2 gap-2 mt-2">
            {donutData.map((d) => (
              <div key={d.name} className="flex items-center gap-1.5 text-xs text-content-muted">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} /> {d.name} ({d.value})
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <Panel
        title="OWASP Exposure"
        icon={Grid3x3}
        right={<Link to="/owasp-mapping" className="text-xs text-brand font-semibold flex items-center gap-1">View Full Mapping <ArrowRight size={12} /></Link>}
        className="mb-6"
      >
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {topOwasp.length === 0 && <div className="text-sm text-content-dim">No OWASP category was affected in this scan.</div>}
          {topOwasp.map((o) => (
            <Link key={o.id} to="/owasp-mapping" className="p-3 rounded-lg border border-base-border bg-base-card2 hover:border-brand/50 transition-colors">
              <div className="flex items-center justify-between mb-1">
                <span className="mono text-xs font-bold text-content">{o.id}</span>
                {o.isNew && <span className="text-[9px] font-bold text-sev-high">NEW</span>}
              </div>
              <div className="text-[11px] text-content-dim mb-2 truncate">{o.name}</div>
              <SeverityBadge level={o.severity} />
              <div className="text-xs text-content-muted mt-2">{o.findings} finding{o.findings !== 1 ? 's' : ''}</div>
            </Link>
          ))}
        </div>
      </Panel>

      <Panel
        title="Top Security Findings"
        icon={Crosshair}
        right={<Link to="/findings" className="text-xs text-brand font-semibold flex items-center gap-1">View All {run.totalFindings} Findings <ArrowRight size={12} /></Link>}
        className="mb-6"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left text-[11px] uppercase text-content-dim border-b border-base-border">
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
                <tr><td colSpan={7} className="py-8 text-center text-content-dim">No findings in this scan.</td></tr>
              )}
              {topFindings.map((f) => (
                <tr key={f.id} className="border-b border-base-border last:border-0 hover:bg-base-card2">
                  <td className="py-2.5 pr-3"><Link to={`/findings/${f.id}`} className="mono text-brand font-semibold">{f.id}</Link></td>
                  <td className="py-2.5 pr-3 text-content"><Link to={`/findings/${f.id}`}>{f.title}</Link></td>
                  <td className="py-2.5 pr-3 mono text-content-muted">{f.owasp}</td>
                  <td className="py-2.5 pr-3"><SeverityBadge level={f.severity} /></td>
                  <td className="py-2.5 pr-3 font-bold text-content">{f.risk}</td>
                  <td className="py-2.5 pr-3 text-content-muted">{f.evidence}</td>
                  <td className="py-2.5 pr-3"><SeverityBadge level={f.verdict} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Panel
          title="Worst Attack Chain"
          icon={GitBranch}
          right={<Link to="/attack-chain" className="text-xs text-brand font-semibold flex items-center gap-1">Explore <ArrowRight size={12} /></Link>}
        >
          {worstChain ? (
            <>
              <div className="text-[13px] text-content font-semibold mb-3">{worstChain.findingTitle}</div>
              <div className="flex items-center gap-1.5 mono text-[11px] text-content flex-wrap">
                {worstChain.phases.map((p, i, arr) => (
                  <span key={p.n} className="flex items-center gap-1.5">
                    <span className="px-2 py-1 rounded border" style={PHASE_STYLE[p.status] ?? PHASE_STYLE.info} title={p.headline}>
                      {p.name}
                    </span>
                    {i < arr.length - 1 && <span className="text-content-dim">→</span>}
                  </span>
                ))}
              </div>
              <div className="flex items-center gap-6 mt-4 pt-3 border-t border-base-border flex-wrap">
                <div>
                  <div className="text-[11px] text-content-dim">Chain Risk</div>
                  <div className="text-xl font-bold text-sev-critical">{chainSummary.risk}/100</div>
                </div>
                <div>
                  <div className="text-[11px] text-content-dim">Furthest failure</div>
                  <div className="text-sm font-semibold text-content">{chainSummary.worstPhaseName ?? '—'}</div>
                </div>
                <div>
                  <div className="text-[11px] text-content-dim">Layers breached</div>
                  <div className="text-sm font-semibold text-content">{chainSummary.breachedLayers}/{chainSummary.totalLayers}</div>
                </div>
              </div>
            </>
          ) : (
            <div className="text-sm text-content-dim">No attack chain was built for this scan.</div>
          )}
        </Panel>

        <Panel title="Recommended Actions" icon={ListChecks}>
          <div className="space-y-2">
            {recommendedActions.length === 0 && (
              <div className="text-sm text-content-dim">No remediation required — no finding reached CONFIRMED.</div>
            )}
            {recommendedActions.map((a, i) => (
              <div key={i} className="flex items-start gap-3 text-[13px] text-content">
                <span className="mono text-brand font-bold w-5 shrink-0">{String(i + 1).padStart(2, '0')}</span>
                {a}
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  )
}
