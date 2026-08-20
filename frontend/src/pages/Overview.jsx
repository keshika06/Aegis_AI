import { Link } from 'react-router-dom'
import { ShieldAlert, Crosshair, Grid3x3, GitBranch, ArrowRight, ListChecks, TrendingUp, TrendingDown } from 'lucide-react'
import { PageHeader, Panel } from '../components/Panel'
import KpiCard from '../components/KpiCard'
import SeverityBadge from '../components/SeverityBadge'
import RiskGauge from '../components/RiskGauge'
import { run, findings, owaspCategories, recommendedActions, chainSummary, attackChains } from '../data/scanData'

export default function Overview() {
  const topRisks = [...findings].sort((a, b) => b.risk - a.risk).slice(0, 5)
  const affected = owaspCategories.filter((o) => o.findings > 0)
  // No prior scan means no delta. Subtracting from null yields the current
  // score itself, which would read as a change that never happened.
  const hasBaseline = run.previousRisk !== null && run.previousRisk !== undefined
  const delta = hasBaseline ? run.risk - run.previousRisk : null
  // The worst chain's real phase sequence, rather than a fixed illustration of
  // what a RAG attack usually looks like.
  const worstChain = attackChains[0] ?? null

  return (
    <div>
      <PageHeader
        title="AegisAI Security Overview"
        subtitle="Landing summary of the current AI application security validation for your target."
        right={
          <div className="text-right">
            <div className="mono text-brand font-bold text-sm">{run.id}</div>
            <div className="text-xs text-slate-500">{run.status} · {run.date}</div>
          </div>
        }
      />

      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-4 mb-6">
        <KpiCard icon={ShieldAlert} label="Posture Score" value={`${run.risk}/100`} sub={`${run.severity} risk`} />
        <KpiCard icon={ListChecks} label="Total Findings" value={run.totalFindings} sub={`${run.critical} Critical · ${run.high} High`} />
        <KpiCard icon={Crosshair} label="Critical" value={run.critical} valueColor="#ef4444" sub={`${run.high} High Severity`} />
        <KpiCard icon={Grid3x3} label="OWASP Affected" value={`${run.owaspAffected}/${run.owaspTotal}`} sub="categories impacted" />
        <KpiCard icon={GitBranch} label="Attack Chains" value={run.attackChains} sub={`${run.guardrailEvasion}% guardrail bypass`} />
        <KpiCard
          icon={ShieldAlert}
          label="Evidence Confidence"
          value={run.evidenceConfidence === null ? '—' : `${run.evidenceConfidence}%`}
          sub={run.evidenceConfidence === null ? 'no deterministic evidence' : 'mean across deterministic proof'}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-6">
        <Panel title="Security Posture" className="lg:col-span-1 flex flex-col items-center justify-center">
          <RiskGauge score={run.risk} label={run.severity} />
          {hasBaseline ? (
            <>
              <div className="w-full flex items-center justify-between mt-3 pt-3 border-t border-base-border text-center">
                <div>
                  <div className="text-[11px] text-slate-500">Previous Run</div>
                  <div className="text-lg font-bold text-slate-300">{run.previousRisk}</div>
                </div>
                <div className={`flex items-center gap-1 text-sm font-bold ${delta > 0 ? 'text-sev-high' : delta < 0 ? 'text-sev-low' : 'text-slate-400'}`}>
                  {delta > 0 ? <TrendingUp size={16} /> : delta < 0 ? <TrendingDown size={16} /> : null}
                  {delta > 0 ? '+' : ''}{delta}
                </div>
                <div>
                  <div className="text-[11px] text-slate-500">Current Run</div>
                  <div className="text-lg font-bold text-white">{run.risk}</div>
                </div>
              </div>
              <div className="text-xs text-slate-500 mt-2">
                Risk {delta > 0 ? 'increased' : delta < 0 ? 'decreased' : 'is unchanged'} compared to the previous validation.
              </div>
            </>
          ) : (
            <div className="w-full mt-3 pt-3 border-t border-base-border text-xs text-slate-500 text-center">
              First recorded run for this target — no baseline to compare against.
            </div>
          )}
        </Panel>

        <Panel title="Top Security Risks" icon={Crosshair} right={<Link to="/findings" className="text-xs text-brand font-semibold flex items-center gap-1">View All <ArrowRight size={12} /></Link>} className="lg:col-span-2">
          <div className="space-y-2">
            {topRisks.length === 0 && <div className="text-sm text-slate-500">No findings in this scan.</div>}
            {topRisks.map((f) => (
              <Link key={f.id} to={`/findings/${f.id}`} className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-base-card2 transition-colors">
                <span className="mono text-[11px] text-slate-500 w-12 shrink-0">{f.id}</span>
                <SeverityBadge level={f.severity} />
                <span className="text-[13px] text-slate-200 flex-1 truncate">{f.title}</span>
                <span className="mono text-xs text-slate-400 w-16 shrink-0">{f.owasp}</span>
                <span className="mono text-sm font-bold text-white w-8 text-right shrink-0">{f.risk}</span>
              </Link>
            ))}
          </div>
        </Panel>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-6">
        <Panel title="OWASP Exposure Summary" icon={Grid3x3} right={<Link to="/owasp-mapping" className="text-xs text-brand font-semibold flex items-center gap-1">View Mapping <ArrowRight size={12} /></Link>} className="lg:col-span-2">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {affected.length === 0 && <div className="text-sm text-slate-500">No OWASP category was affected in this scan.</div>}
            {affected.map((o) => (
              <Link key={o.id} to="/owasp-mapping" className="p-3 rounded-lg border border-base-border bg-base-card2 hover:border-brand/50 transition-colors">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="mono text-xs font-bold text-slate-300">{o.id}</span>
                  <SeverityBadge level={o.severity} />
                </div>
                <div className="text-[11px] text-slate-500 truncate">{o.name}</div>
                <div className="text-xs text-slate-400 mt-1">{o.findings} finding{o.findings !== 1 ? 's' : ''}</div>
              </Link>
            ))}
          </div>
        </Panel>

        <Panel title="Worst Attack Chain" icon={GitBranch} right={<Link to="/attack-chain" className="text-xs text-brand font-semibold flex items-center gap-1">Explore <ArrowRight size={12} /></Link>}>
          {worstChain ? (
            <>
              <div className="text-[12px] text-slate-300 font-semibold mb-2 truncate">{worstChain.findingTitle}</div>
              <div className="flex flex-col items-center gap-1 text-[12px] mono text-slate-400">
                {worstChain.phases.map((p, i, arr) => (
                  <div key={p.n} className="flex flex-col items-center w-full">
                    <div
                      className="px-3 py-1.5 rounded border w-full text-center truncate"
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
                    </div>
                    {i < arr.length - 1 && <div className="text-slate-600">↓</div>}
                  </div>
                ))}
              </div>
              <div className="mt-4 pt-3 border-t border-base-border flex items-center justify-between">
                <span className="text-xs text-slate-500">Chain Risk</span>
                <span className="text-lg font-bold text-sev-critical">{chainSummary.risk}/100</span>
              </div>
            </>
          ) : (
            <div className="text-sm text-slate-500">No attack chain was built for this scan.</div>
          )}
        </Panel>
      </div>

      <Panel title="Recommended Actions" icon={ListChecks}>
        <div className="space-y-2">
          {recommendedActions.length === 0 && (
            <div className="text-sm text-slate-500">No remediation required — no finding reached CONFIRMED.</div>
          )}
          {recommendedActions.map((a, i) => (
            <div key={i} className="flex items-start gap-3 text-[13px] text-slate-300">
              <span className="mono text-brand font-bold w-5 shrink-0">{String(i + 1).padStart(2, '0')}</span>
              {a}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}
