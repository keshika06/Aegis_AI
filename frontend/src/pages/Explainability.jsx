import { useState } from 'react'
import { BarChart, Bar as RBar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from 'recharts'
import { PageHeader, Panel } from '../components/Panel'
import SeverityBadge from '../components/SeverityBadge'
import { factorContributions, contributionFinal, unestablishedFactors, finding_detail } from '../data/scanData'

// The risk model is a weighted linear combination, so each factor's contribution
// is exactly weight x value. Summing them reproduces the composite — this is the
// real decomposition, not an approximation of a model that was never run.
function buildWaterfall() {
  let running = 0
  const segs = []
  factorContributions.forEach((f) => {
    const start = running
    running += f.contribution
    segs.push({
      name: f.feature.replace(/_/g, ' '),
      start: Math.min(start, running),
      end: Math.max(start, running),
      value: f.contribution,
      type: f.direction
    })
  })
  segs.push({ name: 'COMPOSITE', start: 0, end: contributionFinal, value: contributionFinal, type: 'final' })
  return segs
}

const colorFor = { up: '#ef4444', down: '#22c55e', final: '#7c5cff' }

export default function Explainability() {
  const [active, setActive] = useState(factorContributions[0] ?? null)
  const data = buildWaterfall()

  if (factorContributions.length === 0) {
    return (
      <div>
        <PageHeader title="Risk Attribution" subtitle="How each factor contributed to the composite risk score." />
        <Panel><div className="text-sm text-slate-500">No scored findings in this scan.</div></Panel>
      </div>
    )
  }

  return (
    <div>
      <PageHeader
        title="Risk Attribution"
        subtitle="Exactly how each factor contributed to the composite score. The model is a weighted linear combination, so these contributions sum to the result."
      />

      <Panel title={finding_detail.title ?? 'Highest-scoring finding'} className="mb-5">
        <div className="flex items-center gap-3 flex-wrap">
          <SeverityBadge level={finding_detail.severity ?? 'LOW'} size="lg" />
          <span className="text-sm text-slate-300">
            Composite: <span className="font-bold text-white">{contributionFinal}/10</span>
          </span>
          <span className="text-sm text-slate-300">
            Verdict: <span className="font-bold text-white">{finding_detail.verdict ?? '—'}</span>
          </span>
          <span className="text-[11px] text-slate-500 ml-auto border border-base-border rounded px-2 py-1 mono">
            Deterministic — same inputs always produce this score
          </span>
        </div>
      </Panel>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-5">
        <Panel title="Contribution waterfall — factors sum to the composite" className="xl:col-span-2">
          <ResponsiveContainer width="100%" height={320}>
            <BarChart data={data} margin={{ left: 10, bottom: 40 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#232b3d" vertical={false} />
              <XAxis dataKey="name" tick={{ fill: '#7c8aab', fontSize: 10 }} angle={-35} textAnchor="end" height={70} axisLine={{ stroke: '#232b3d' }} />
              <YAxis tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} />
              <Tooltip
                contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }}
                formatter={(v, n, p) => [`${p.payload.value >= 0 ? '+' : ''}${p.payload.value}`, 'contribution']}
              />
              <RBar dataKey="end" radius={[4, 4, 0, 0]}>
                {data.map((d, i) => <Cell key={i} fill={colorFor[d.type] ?? '#64748b'} />)}
              </RBar>
            </BarChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Factors by contribution">
          <div className="flex flex-col gap-2">
            {[...factorContributions].sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution)).map((f) => (
              <button
                key={f.feature}
                onClick={() => setActive(f)}
                className={`text-left p-3 rounded-lg border transition ${
                  active?.feature === f.feature ? 'border-accent/60 bg-base-card2' : 'border-base-border hover:border-slate-600'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[13px] font-semibold text-slate-200">{f.feature.replace(/_/g, ' ')}</span>
                  <span className="mono text-xs font-bold" style={{ color: colorFor[f.direction] }}>
                    {f.contribution >= 0 ? '+' : ''}{f.contribution}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 mono">{f.explain}</div>
              </button>
            ))}
          </div>
        </Panel>
      </div>

      {unestablishedFactors.length > 0 && (
        <Panel title="Factors not established">
          <p className="text-[13px] text-slate-300 mb-3">
            These could not be measured for this finding. They are excluded from the weighting and
            the remaining weights are re-normalised — an unmeasured factor counted as zero would
            quietly understate the risk.
          </p>
          <div className="flex flex-wrap gap-2">
            {unestablishedFactors.map((f) => (
              <span key={f} className="mono text-[11px] px-2 py-1 rounded border border-base-border text-slate-400">
                {f.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        </Panel>
      )}
    </div>
  )
}
