import { AlertTriangle } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend } from 'recharts'
import { PageHeader, Panel } from '../components/Panel'
import { riskRuns, regression } from '../data/scanData'

function Delta({ label, from, to, invert }) {
  if (from === null || from === undefined || to === null || to === undefined) {
    return (
      <div className="flex items-center justify-between p-3 rounded-lg border border-base-border bg-base-card2">
        <div className="text-[13px] text-slate-400">{label}</div>
        <span className="text-[11px] font-bold text-slate-500">NO BASELINE</span>
      </div>
    )
  }
  const improved = invert ? to > from : to < from
  const same = to === from
  const color = same ? 'text-slate-400' : improved ? 'text-sev-low' : 'text-sev-high'
  const word = same ? 'UNCHANGED' : improved ? 'IMPROVED' : 'REGRESSED'
  return (
    <div className="flex items-center justify-between p-3 rounded-lg border border-base-border bg-base-card2">
      <div>
        <div className="text-[11px] text-slate-500">{label}</div>
        <div className="mono text-sm text-slate-300">{from} → {to}</div>
      </div>
      <span className={`text-[11px] font-bold ${color}`}>{word}</span>
    </div>
  )
}

export default function Trends() {
  // One scan is a point, not a trend. Drawing a line through a single value
  // implies a history that was never recorded.
  const hasHistory = riskRuns.length > 1
  const previous = riskRuns.length > 1 ? riskRuns[riskRuns.length - 2] : null
  const current = riskRuns[riskRuns.length - 1] ?? null

  return (
    <div>
      <PageHeader title="Security Trends & Regression" subtitle="Track validation runs over time and detect regressions before they reach production." />

      {!hasHistory && (
        <div className="mb-5 p-4 rounded-lg border border-sev-info/40 bg-sev-infoBg">
          <div className="text-sev-info font-bold text-sm mb-1">Only one run recorded for this target</div>
          <p className="text-[13px] text-slate-300">
            Trends need at least two scans of the same target. Run another scan to compare against
            this one; until then there is nothing to plot.
          </p>
        </div>
      )}

      {hasHistory && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
          <Panel title="Posture Score Over Time">
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={riskRuns} margin={{ left: -20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#232b3d" />
                <XAxis dataKey="run" tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} />
                <YAxis tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} domain={[0, 100]} />
                <Tooltip contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }} />
                <Line type="monotone" dataKey="risk" name="Posture" stroke="#7c5cff" strokeWidth={2.5} dot={{ r: 4 }} />
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

          <Panel title="Confirmed Findings Over Time" className="lg:col-span-2">
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={riskRuns} margin={{ left: -20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#232b3d" />
                <XAxis dataKey="run" tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} />
                <YAxis tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} />
                <Tooltip contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Line type="monotone" dataKey="confirmed" name="Confirmed" stroke="#ef4444" strokeWidth={2.5} dot={{ r: 4 }} />
                <Line type="monotone" dataKey="findings" name="Total findings" stroke="#64748b" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </Panel>
        </div>
      )}

      <Panel title={regression.prevRun ? `${regression.prevRun} vs ${regression.currentRun}` : `${regression.currentRun} — first recorded run`} className="mb-5">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <Delta label="Posture score" from={regression.riskPrev} to={regression.riskCurrent} />
          <Delta label="Critical findings" from={previous?.critical} to={current?.critical} />
          <Delta label="Confirmed findings" from={previous?.confirmed} to={current?.confirmed} />
        </div>
        <div className="mt-4 pt-3 border-t border-base-border grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
          <div><div className="text-[11px] text-slate-500">Regression tests</div><div className="font-bold text-slate-200">{regression.total}</div></div>
          <div><div className="text-[11px] text-slate-500">Active</div><div className="font-bold text-sev-high">{regression.active}</div></div>
          <div><div className="text-[11px] text-slate-500">Resolved</div><div className="font-bold text-sev-low">{regression.resolved}</div></div>
          <div><div className="text-[11px] text-slate-500">Regressed</div><div className="font-bold text-sev-critical">{regression.regressed}</div></div>
        </div>
      </Panel>

      {regression.detail && (
        <Panel title="Most Persistent Category" className="mb-5 border-l-4 border-l-sev-critical">
          <div className="flex items-start gap-3">
            <AlertTriangle size={18} className="text-sev-critical shrink-0 mt-0.5" />
            <div>
              <div className="font-bold text-slate-100">{regression.detail.category}</div>
              <div className="text-[13px] text-slate-400 mt-1">
                {regression.detail.prev === null || regression.detail.prev === undefined
                  ? <>Posture at <span className="mono font-bold text-sev-critical">{regression.detail.current}</span> — no earlier run to compare against.</>
                  : <>Posture moved <span className="mono font-bold text-sev-critical">{regression.detail.prev} → {regression.detail.current}</span></>}
              </div>
            </div>
          </div>
        </Panel>
      )}

      {(regression.nextFocus ?? []).length > 0 && (
        <Panel title="Recommended Next Validation Focus">
          <p className="text-[13px] text-slate-400 mb-3">
            The transformation families the target accepted most readily. Derived from what was
            measured, not from a curated list.
          </p>
          <div className="flex flex-wrap gap-2">
            {regression.nextFocus.map((f) => (
              <span key={f} className="px-3 py-1.5 rounded-lg bg-base-card2 border border-base-border text-[13px] text-slate-300">{f.replace(/_/g, ' ')}</span>
            ))}
          </div>
        </Panel>
      )}
    </div>
  )
}
