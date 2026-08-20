import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, ScatterChart, Scatter, XAxis, YAxis, ZAxis, CartesianGrid } from 'recharts'
import { PageHeader, Panel } from '../components/Panel'
import RiskGauge from '../components/RiskGauge'
import { run, riskComponents, findings, severityColor } from '../data/scanData'

const donutData = [
  { name: 'Critical', value: run.critical, color: severityColor.CRITICAL.text },
  { name: 'High', value: run.high, color: severityColor.HIGH.text },
  { name: 'Medium', value: run.medium, color: severityColor.MEDIUM.text },
  { name: 'Low', value: run.low, color: severityColor.LOW.text }
]

// Both axes come from the finding's own scored factors, so a point's position
// is the risk model's own likelihood and impact rather than a stand-in derived
// from the composite it already produced.
const matrixData = findings
  .filter((f) => typeof f.likelihood === 'number' && typeof f.impact === 'number')
  .map((f) => ({
    likelihood: Math.round(f.likelihood * 10),
    impact: Math.round(f.impact * 10),
    z: f.risk,
    id: f.id,
    title: f.title,
    color: (severityColor[f.severity] ?? severityColor.NEUTRAL).text
  }))

export default function RiskAnalysis() {
  const hasBaseline = run.previousRisk !== null && run.previousRisk !== undefined
  const delta = hasBaseline ? run.risk - run.previousRisk : null

  return (
    <div>
      <PageHeader title="Risk Analysis" subtitle="Comprehensive analysis of systemic vulnerabilities, normalized across multidimensional threat vectors." />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-5">
        <Panel title="Aggregate Risk Score" className="flex flex-col items-center">
          <RiskGauge score={run.risk} label={run.severity} />
          <div className="w-full grid grid-cols-3 text-center mt-2 pt-3 border-t border-base-border">
            <div><div className="text-[11px] text-slate-500">Prev</div><div className="font-bold text-slate-300">{hasBaseline ? run.previousRisk : '—'}</div></div>
            <div>
              <div className="text-[11px] text-slate-500">Trend</div>
              <div className={`font-bold ${delta > 0 ? 'text-sev-high' : delta < 0 ? 'text-sev-low' : 'text-slate-400'}`}>
                {hasBaseline ? `${delta > 0 ? '+' : ''}${delta}` : '—'}
              </div>
            </div>
            <div><div className="text-[11px] text-slate-500">Conf</div><div className="font-bold text-sev-low">{run.evidenceConfidence === null ? '—' : `${run.evidenceConfidence}%`}</div></div>
          </div>
        </Panel>

        <Panel title="Risk Component Contributions" className="lg:col-span-2">
          <div className="space-y-3">
            {riskComponents.length === 0 && <div className="text-sm text-slate-500">No scored findings in this scan.</div>}
            {riskComponents.map((c) => (
              <div key={c.label} className="flex items-center gap-3">
                <span className="text-[13px] text-slate-300 w-40 shrink-0">{c.label}</span>
                <div className="flex-1 h-2 rounded-full bg-base-card2 overflow-hidden">
                  {c.established && (
                    <div className="h-full rounded-full" style={{ width: `${c.score}%`, backgroundColor: c.axis === 'impact' ? '#ef4444' : '#f97316' }} />
                  )}
                </div>
                <span className="mono text-xs font-bold text-slate-200 w-8 text-right">{c.established ? c.score : '—'}</span>
                <span className="text-[11px] text-slate-500 w-24 text-right shrink-0">{c.established ? `${c.weight}% of ${c.axis}` : 'not established'}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-5">
        <Panel title="Impact vs. Likelihood" className="lg:col-span-2">
          <ResponsiveContainer width="100%" height={280}>
            <ScatterChart margin={{ top: 10, right: 20, bottom: 10, left: -10 }}>
              <CartesianGrid stroke="#232b3d" />
              <XAxis type="number" dataKey="likelihood" name="Likelihood" domain={[0, 10]} tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} label={{ value: 'Likelihood', position: 'insideBottom', offset: -5, fill: '#7c8aab', fontSize: 11 }} />
              <YAxis type="number" dataKey="impact" name="Impact" domain={[0, 10]} tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} label={{ value: 'Impact', angle: -90, position: 'insideLeft', fill: '#7c8aab', fontSize: 11 }} />
              <ZAxis type="number" dataKey="z" range={[80, 260]} />
              <Tooltip cursor={{ strokeDasharray: '3 3' }} contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }} formatter={(v, n, p) => [`${p.payload.id} — ${p.payload.title}`, 'Finding']} />
              <Scatter data={matrixData}>
                {matrixData.map((d, i) => <Cell key={i} fill={d.color} fillOpacity={0.85} />)}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Severity Distribution">
          <ResponsiveContainer width="100%" height={190}>
            <PieChart>
              <Pie data={donutData} dataKey="value" innerRadius={50} outerRadius={75} paddingAngle={3}>
                {donutData.map((d, i) => <Cell key={i} fill={d.color} />)}
              </Pie>
              <Tooltip contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="grid grid-cols-2 gap-2 mt-1">
            {donutData.map((d) => (
              <div key={d.name} className="flex items-center gap-1.5 text-xs text-slate-400">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} /> {d.name} ({d.value})
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <Panel title="Current Run vs Previous Run">
        {hasBaseline ? (
          <div className="grid grid-cols-3 gap-6 text-center">
            <div><div className="text-[11px] text-slate-500 mb-1">Previous Run</div><div className="text-2xl font-bold text-slate-400">{run.previousRisk}</div></div>
            <div><div className="text-[11px] text-slate-500 mb-1">Current Run</div><div className="text-2xl font-bold text-white">{run.risk}</div></div>
            <div>
              <div className="text-[11px] text-slate-500 mb-1">Difference</div>
              <div className={`text-2xl font-bold ${delta > 0 ? 'text-sev-high' : delta < 0 ? 'text-sev-low' : 'text-slate-400'}`}>
                {delta > 0 ? '+' : ''}{delta}
              </div>
            </div>
          </div>
        ) : (
          <div className="text-sm text-slate-500 text-center py-4">
            This is the first recorded scan of {run.target}. There is no previous run to compare against.
          </div>
        )}
      </Panel>
    </div>
  )
}
