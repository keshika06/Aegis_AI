import { AlertTriangle } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend } from 'recharts'
import { PageHeader, Panel } from '../components/Panel'
import { riskRuns, regression } from '../data/scanData'

function Delta({ from, to, invert }) {
  const improved = invert ? to > from : to < from
  const same = to === from
  const color = same ? 'text-slate-400' : improved ? 'text-sev-low' : 'text-sev-high'
  const label = same ? 'UNCHANGED' : improved ? 'IMPROVED' : 'REGRESSED'
  return (
    <div className="flex items-center justify-between p-3 rounded-lg border border-base-border bg-base-card2">
      <div className="mono text-sm text-slate-300">{from} → {to}</div>
      <span className={`text-[11px] font-bold ${color}`}>{label}</span>
    </div>
  )
}

export default function Trends() {
  return (
    <div>
      <PageHeader title="Security Trends & Regression" subtitle="Track validation runs over time and detect regressions before they reach production." />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
        <Panel title="Risk Score Over Time">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={riskRuns} margin={{ left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#232b3d" />
              <XAxis dataKey="run" tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} />
              <YAxis tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} domain={[0, 100]} />
              <Tooltip contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }} />
              <Line type="monotone" dataKey="risk" stroke="#7c5cff" strokeWidth={2.5} dot={{ r: 4 }} />
            </LineChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Critical & High Findings Over Time">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={riskRuns} margin={{ left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#232b3d" />
              <XAxis dataKey="run" tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} />
              <YAxis tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} />
              <Tooltip contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Line type="monotone" dataKey="critical" name="Critical" stroke="#ef4444" strokeWidth={2} dot={{ r: 3 }} />
              <Line type="monotone" dataKey="high" name="High" stroke="#f97316" strokeWidth={2} dot={{ r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Attack Success Rate & Guardrail Bypass">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={riskRuns} margin={{ left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#232b3d" />
              <XAxis dataKey="run" tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} />
              <YAxis tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} />
              <Tooltip contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Line type="monotone" dataKey="attackSuccess" name="Attack Success %" stroke="#eab308" strokeWidth={2} dot={{ r: 3 }} />
              <Line type="monotone" dataKey="guardrailBypass" name="Guardrail Bypass %" stroke="#ef4444" strokeWidth={2} dot={{ r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Security Control Effectiveness">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={riskRuns} margin={{ left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#232b3d" />
              <XAxis dataKey="run" tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} />
              <YAxis tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} domain={[0, 100]} />
              <Tooltip contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }} />
              <Line type="monotone" dataKey="controlEffectiveness" name="Effectiveness %" stroke="#22c55e" strokeWidth={2.5} dot={{ r: 4 }} />
            </LineChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      <Panel title={`${regression.prevRun} vs ${regression.currentRun}`} className="mb-5">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <Delta from={regression.riskPrev} to={regression.riskCurrent} />
          <Delta from="3" to="2" />
          <Delta from="8" to="6" />
          <Delta from="31%" to="27%" />
        </div>
      </Panel>

      <Panel title="Regression Detected" className="mb-5 border-l-4 border-l-sev-critical">
        <div className="flex items-start gap-3">
          <AlertTriangle size={18} className="text-sev-critical shrink-0 mt-0.5" />
          <div>
            <div className="font-bold text-slate-100">{regression.detail.category}</div>
            <div className="text-[13px] text-slate-400 mt-1">
              Risk increased: <span className="mono font-bold text-sev-critical">{regression.detail.prev} → {regression.detail.current}</span>
            </div>
          </div>
        </div>
      </Panel>

      <Panel title="Recommended Next Validation Focus">
        <div className="flex flex-wrap gap-2">
          {regression.nextFocus.map((f) => (
            <span key={f} className="px-3 py-1.5 rounded-lg bg-base-card2 border border-base-border text-[13px] text-slate-300">{f}</span>
          ))}
        </div>
      </Panel>
    </div>
  )
}
