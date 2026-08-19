import { Link } from 'react-router-dom'
import { ShieldAlert, ListChecks, Crosshair, Grid3x3, ShieldOff, CheckCircle2, ArrowRight, GitBranch } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, PieChart, Pie, Cell } from 'recharts'
import { PageHeader, Panel, Bar } from '../components/Panel'
import KpiCard from '../components/KpiCard'
import RiskGauge from '../components/RiskGauge'
import SeverityBadge from '../components/SeverityBadge'
import { run, riskRuns, owaspCategories, findings, riskComponents, severityColor, chainSummary } from '../data/scanData'

const donutData = [
  { name: 'Critical', value: run.critical, color: severityColor.CRITICAL.text },
  { name: 'High', value: run.high, color: severityColor.HIGH.text },
  { name: 'Medium', value: run.medium, color: severityColor.MEDIUM.text },
  { name: 'Low', value: run.low, color: severityColor.LOW.text }
]

export default function Dashboard() {
  const topOwasp = [...owaspCategories].filter((o) => o.findings > 0).sort((a, b) => b.risk - a.risk).slice(0, 5)
  const topFindings = [...findings].sort((a, b) => b.risk - a.risk).slice(0, 5)

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
        <KpiCard icon={ShieldAlert} label="Overall Risk" value={run.risk} valueColor="#f97316" trend={`${run.risk - run.previousRisk} from previous`} trendUp sub="HIGH" />
        <KpiCard icon={ListChecks} label="Total Findings" value={run.totalFindings} sub={`${run.critical} Critical · ${run.high} High`} />
        <KpiCard icon={Crosshair} label="Attack Success Rate" value={`${run.attackSuccessRate}%`} trend={`${run.attackSuccessDelta}%`} trendUp />
        <KpiCard icon={Grid3x3} label="OWASP Coverage" value={`${run.owaspAffected}/${run.owaspTotal}`} sub="categories affected" />
        <KpiCard icon={ShieldOff} label="Guardrail Evasion" value={`${run.guardrailEvasion}%`} valueColor="#ef4444" sub="successful bypasses" />
        <KpiCard icon={CheckCircle2} label="Evidence Confidence" value={`${run.evidenceConfidence}%`} valueColor="#22c55e" sub="high confidence" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-6">
        <Panel title="Overall Security Risk" className="flex flex-col items-center">
          <RiskGauge score={run.risk} label={run.severity} />
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
              <div className="font-bold text-sev-high">+{run.risk - run.previousRisk}</div>
            </div>
          </div>
        </Panel>

        <Panel title="Why is the Risk High?" className="lg:col-span-2">
          {riskComponents.slice(0, 5).map((c) => (
            <Bar key={c.label} label={c.label} score={c.score} color="#f97316" sub={c.explain} />
          ))}
        </Panel>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-6">
        <Panel title="Risk Score Over Validation Runs" className="lg:col-span-2">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={riskRuns} margin={{ left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#232b3d" />
              <XAxis dataKey="run" tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} tickLine={false} />
              <YAxis tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} tickLine={false} domain={[0, 100]} />
              <Tooltip contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }} />
              <Line type="monotone" dataKey="risk" stroke="#7c5cff" strokeWidth={2.5} dot={{ r: 4, fill: '#7c5cff' }} activeDot={{ r: 6 }} />
            </LineChart>
          </ResponsiveContainer>
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
                <th className="py-2 pr-3 font-semibold">Status</th>
              </tr>
            </thead>
            <tbody>
              {topFindings.map((f) => (
                <tr key={f.id} className="border-b border-base-border last:border-0 hover:bg-base-card2 cursor-pointer">
                  <td className="py-2.5 pr-3"><Link to={`/findings/${f.id}`} className="mono text-brand font-semibold">{f.id}</Link></td>
                  <td className="py-2.5 pr-3 text-slate-200">{f.title}</td>
                  <td className="py-2.5 pr-3 mono text-slate-400">{f.owasp}</td>
                  <td className="py-2.5 pr-3"><SeverityBadge level={f.severity} /></td>
                  <td className="py-2.5 pr-3 font-bold text-white">{f.risk}</td>
                  <td className="py-2.5 pr-3 text-slate-400">{f.evidence}</td>
                  <td className="py-2.5 pr-3 text-sev-high font-semibold">{f.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Attack Chain Preview" icon={GitBranch} right={<Link to="/attack-chain" className="text-xs text-brand font-semibold flex items-center gap-1">Open Attack Chain Explorer <ArrowRight size={12} /></Link>}>
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-2 mono text-[12px] text-slate-300 flex-wrap">
            {['User Input', 'Encoded Payload', 'RAG Retrieval', 'Malicious Context', 'LLM', 'Tool Call', 'Sensitive Action'].map((s, i, arr) => (
              <span key={s} className="flex items-center gap-2">
                <span className="px-2.5 py-1 rounded border border-base-border bg-base-card2">{s}</span>
                {i < arr.length - 1 && <span className="text-slate-600">→</span>}
              </span>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-8 mt-4 pt-3 border-t border-base-border">
          <div>
            <div className="text-[11px] text-slate-500">Attack Chain Risk</div>
            <div className="text-xl font-bold text-sev-critical">{chainSummary.risk}/100</div>
          </div>
          <div>
            <div className="text-[11px] text-slate-500">Highest Risk Node</div>
            <div className="text-sm font-semibold text-slate-200">{chainSummary.worstPhaseName ?? "—"}</div>
          </div>
        </div>
      </Panel>
    </div>
  )
}
