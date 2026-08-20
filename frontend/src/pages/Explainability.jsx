import { useState } from 'react'
import { BarChart, Bar as RBar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from 'recharts'
import { PageHeader, Panel } from '../components/Panel'
import SeverityBadge from '../components/SeverityBadge'
import {
  factorContributions, contributionFinal, unestablishedFactors, finding_detail,
  contributionLikelihood, contributionImpact, contributionConfidence, contributionArithmetic
} from '../data/scanData'

const AXIS = {
  likelihood: { label: 'Likelihood', color: '#f97316', blurb: 'How readily an attacker walks this path again.' },
  impact: { label: 'Impact', color: '#ef4444', blurb: 'What it costs when they do.' }
}

export default function Explainability() {
  const [active, setActive] = useState(factorContributions[0] ?? null)

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
        subtitle="How this finding's score was reached. The model multiplies likelihood by impact, so each factor is a weighted share of its own axis — not a slice of the final number."
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
        {contributionArithmetic && (
          <div className="mt-4 pt-3 border-t border-base-border">
            <div className="text-[11px] uppercase tracking-wide text-slate-500 mb-2">The arithmetic</div>
            <div className="flex items-center gap-3 flex-wrap mono text-sm">
              <Term label="likelihood" value={contributionLikelihood} color={AXIS.likelihood.color} />
              <span className="text-slate-500">×</span>
              <Term label="impact" value={contributionImpact} color={AXIS.impact.color} />
              {contributionConfidence !== null && (
                <>
                  <span className="text-slate-500">×</span>
                  <Term label="confidence" value={contributionConfidence} color="#7c5cff" />
                </>
              )}
              <span className="text-slate-500">× 10 =</span>
              <span className="text-xl font-bold text-white">{contributionFinal}</span>
            </div>
            <p className="text-[12px] text-slate-500 mt-3 max-w-[80ch]">
              Confidence scales the result rather than averaging into it. A weakness has to be both
              reachable and consequential to score highly — that is why a single high factor cannot
              carry the composite on its own.
            </p>
          </div>
        )}
      </Panel>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 mb-5">
        {['likelihood', 'impact'].map((axis) => {
          const rows = factorContributions.filter((f) => f.axis === axis)
          if (rows.length === 0) return null
          const axisValue = axis === 'likelihood' ? contributionLikelihood : contributionImpact
          return (
            <Panel key={axis} title={`${AXIS[axis].label} — ${axisValue?.toFixed(2) ?? '—'}`}>
              <p className="text-[12px] text-slate-500 mb-3">{AXIS[axis].blurb} Bars are each factor's weighted share of this axis; they sum to the axis value.</p>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={rows} margin={{ left: 10, bottom: 30 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#232b3d" vertical={false} />
                  <XAxis dataKey="feature" tickFormatter={(v) => v.replace(/_/g, ' ')} tick={{ fill: '#7c8aab', fontSize: 10 }} angle={-25} textAnchor="end" height={60} axisLine={{ stroke: '#232b3d' }} />
                  <YAxis tick={{ fill: '#7c8aab', fontSize: 11 }} axisLine={{ stroke: '#232b3d' }} domain={[0, 1]} />
                  <Tooltip
                    contentStyle={{ background: '#131a29', border: '1px solid #232b3d', borderRadius: 8, fontSize: 12 }}
                    formatter={(v, n, p) => [`${p.payload.contribution} of ${axis}`, p.payload.feature.replace(/_/g, ' ')]}
                  />
                  <RBar dataKey="contribution" radius={[4, 4, 0, 0]}>
                    {rows.map((d, i) => <Cell key={i} fill={AXIS[axis].color} fillOpacity={d.direction === 'up' ? 1 : 0.5} />)}
                  </RBar>
                </BarChart>
              </ResponsiveContainer>
            </Panel>
          )
        })}
      </div>

      <Panel title="Every factor, with its measured value" className="mb-5">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {[...factorContributions].sort((a, b) => b.contribution - a.contribution).map((f) => (
            <button
              key={f.feature}
              onClick={() => setActive(f)}
              className={`text-left p-3 rounded-lg border transition ${
                active?.feature === f.feature ? 'border-accent/60 bg-base-card2' : 'border-base-border hover:border-slate-600'
              }`}
            >
              <div className="flex items-center justify-between mb-1 gap-2">
                <span className="text-[13px] font-semibold text-slate-200">{f.feature.replace(/_/g, ' ')}</span>
                <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded shrink-0" style={{ color: AXIS[f.axis].color, border: `1px solid ${AXIS[f.axis].color}55` }}>
                  {f.axis}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-slate-500 mono">{f.explain}</span>
                <span className="mono text-xs font-bold" style={{ color: AXIS[f.axis].color }}>{f.value.toFixed(2)}</span>
              </div>
            </button>
          ))}
        </div>
      </Panel>

      {unestablishedFactors.length > 0 && (
        <Panel title="Factors not established">
          <p className="text-[13px] text-slate-300 mb-3">
            These could not be measured for this finding. They are excluded from the weighting and
            the remaining weights on their axis are re-normalised — an unmeasured factor counted as
            zero would quietly understate the risk.
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

function Term({ label, value, color }) {
  return (
    <span className="inline-flex flex-col items-center px-3 py-1.5 rounded-lg border" style={{ borderColor: `${color}55`, background: `${color}12` }}>
      <span className="text-lg font-bold" style={{ color }}>{value?.toFixed(2) ?? '—'}</span>
      <span className="text-[10px] uppercase tracking-wide text-slate-500">{label}</span>
    </span>
  )
}
