import { useState } from 'react'
import {
  BarChart, Bar as RBar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell,
  ScatterChart, Scatter, ZAxis, ReferenceLine
} from 'recharts'
import { PageHeader, Panel } from '../components/Panel'
import SeverityBadge from '../components/SeverityBadge'
import {
  factorContributions, contributionFinal, unestablishedFactors, finding_detail,
  contributionLikelihood, contributionImpact, contributionConfidence, contributionArithmetic,
  findings, severityColor
} from '../data/scanData'
import { useTokens } from '../theme'

const axisFor = (t) => ({
  likelihood: { label: 'Likelihood', color: t.high, blurb: 'How readily an attacker walks this path again.' },
  impact: { label: 'Impact', color: t.critical, blurb: 'What it costs when they do.' }
})

// Every finding placed on the two axes the score multiplies. Both coordinates
// are the finding's own measured axis values, not a stand-in derived from the
// composite they already produced — so distance from the origin *is* the score,
// and the two ways of being dangerous separate visually.
const matrixData = findings
  .filter((f) => typeof f.likelihood === 'number' && typeof f.impact === 'number')
  .map((f) => ({
    likelihood: Number((f.likelihood * 10).toFixed(1)),
    impact: Number((f.impact * 10).toFixed(1)),
    z: f.risk,
    id: f.id,
    title: f.title,
    color: (severityColor[f.severity] ?? severityColor.NEUTRAL).text
  }))

export default function Explainability() {
  const t = useTokens()
  const AXIS = axisFor(t)
  const [active, setActive] = useState(factorContributions[0] ?? null)

  if (factorContributions.length === 0) {
    return (
      <div>
        <PageHeader title="Risk Attribution" subtitle="How each factor contributed to the composite risk score." />
        <Panel><div className="text-sm text-content-dim">No scored findings in this scan.</div></Panel>
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
          <span className="text-sm text-content">
            Composite: <span className="font-bold text-content">{contributionFinal}/10</span>
          </span>
          <span className="text-sm text-content">
            Verdict: <span className="font-bold text-content">{finding_detail.verdict ?? '—'}</span>
          </span>
          <span className="text-[11px] text-content-dim ml-auto border border-base-border rounded px-2 py-1 mono">
            Deterministic — same inputs always produce this score
          </span>
        </div>
        {contributionArithmetic && (
          <div className="mt-4 pt-3 border-t border-base-border">
            <div className="text-[11px] uppercase tracking-wide text-content-dim mb-2">The arithmetic</div>
            <div className="flex items-center gap-3 flex-wrap mono text-sm">
              <Term label="likelihood" value={contributionLikelihood} color={AXIS.likelihood.color} />
              <span className="text-content-dim">×</span>
              <Term label="impact" value={contributionImpact} color={AXIS.impact.color} />
              {contributionConfidence !== null && (
                <>
                  <span className="text-content-dim">×</span>
                  <Term label="confidence" value={contributionConfidence} color={t.brand} />
                </>
              )}
              <span className="text-content-dim">× 10 =</span>
              <span className="text-xl font-bold text-content">{contributionFinal}</span>
            </div>
            <p className="text-[12px] text-content-dim mt-3 max-w-[80ch]">
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
              <p className="text-[12px] text-content-dim mb-3">{AXIS[axis].blurb} Bars are each factor's weighted share of this axis; they sum to the axis value.</p>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={rows} margin={{ left: 10, bottom: 30 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={t.grid} vertical={false} />
                  <XAxis dataKey="feature" tickFormatter={(v) => v.replace(/_/g, ' ')} tick={{ fill: t.axis, fontSize: 10 }} angle={-25} textAnchor="end" height={60} axisLine={{ stroke: t.grid }} />
                  <YAxis tick={{ fill: t.axis, fontSize: 11 }} axisLine={{ stroke: t.grid }} domain={[0, 1]} />
                  <Tooltip
                    contentStyle={{ background: t.tooltipBg, border: `1px solid ${t.tooltipBorder}`, borderRadius: 8, fontSize: 12 }}
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
                active?.feature === f.feature ? 'border-accent/60 bg-base-card2' : 'border-base-border hover:border-base-border2'
              }`}
            >
              <div className="flex items-center justify-between mb-1 gap-2">
                <span className="text-[13px] font-semibold text-content">{f.feature.replace(/_/g, ' ')}</span>
                <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded shrink-0" style={{ color: AXIS[f.axis].color, border: `1px solid ${AXIS[f.axis].color}55` }}>
                  {f.axis}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-content-dim mono">{f.explain}</span>
                <span className="mono text-xs font-bold" style={{ color: AXIS[f.axis].color }}>{f.value.toFixed(2)}</span>
              </div>
            </button>
          ))}
        </div>
      </Panel>

      {matrixData.length > 0 && (
        <Panel title={`Every finding on the two axes — ${matrixData.length} scored`} className="mb-5">
          <p className="text-[12px] text-content-dim mb-3">
            Position is the finding's own measured likelihood and impact, so distance from the
            origin is its score. The two ways of being dangerous separate here: top-left is severe
            but hard to reach, bottom-right is trivially reachable but cheap. Only the top-right
            corner is both.
          </p>
          <ResponsiveContainer width="100%" height={300}>
            <ScatterChart margin={{ top: 10, right: 20, bottom: 20, left: -10 }}>
              <CartesianGrid stroke={t.grid} />
              <XAxis
                type="number" dataKey="likelihood" name="Likelihood" domain={[0, 10]}
                tick={{ fill: t.axis, fontSize: 11 }} axisLine={{ stroke: t.grid }}
                label={{ value: 'Likelihood →', position: 'insideBottom', offset: -10, fill: t.axis, fontSize: 11 }}
              />
              <YAxis
                type="number" dataKey="impact" name="Impact" domain={[0, 10]}
                tick={{ fill: t.axis, fontSize: 11 }} axisLine={{ stroke: t.grid }}
                label={{ value: 'Impact →', angle: -90, position: 'insideLeft', fill: t.axis, fontSize: 11 }}
              />
              <ZAxis type="number" dataKey="z" range={[60, 300]} />
              <ReferenceLine x={5} stroke={t.grid} strokeDasharray="3 3" />
              <ReferenceLine y={5} stroke={t.grid} strokeDasharray="3 3" />
              <Tooltip
                cursor={{ strokeDasharray: '3 3' }}
                contentStyle={{ background: t.tooltipBg, border: `1px solid ${t.tooltipBorder}`, borderRadius: 8, fontSize: 12 }}
                formatter={(v, n, p) => [`${p.payload.id} — ${p.payload.title}`, `L ${p.payload.likelihood} · I ${p.payload.impact} · risk ${p.payload.z}`]}
              />
              <Scatter data={matrixData}>
                {matrixData.map((d, i) => <Cell key={i} fill={d.color} fillOpacity={0.8} />)}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
        </Panel>
      )}

      {unestablishedFactors.length > 0 && (
        <Panel title="Factors not established">
          <p className="text-[13px] text-content mb-3">
            These could not be measured for this finding. They are excluded from the weighting and
            the remaining weights on their axis are re-normalised — an unmeasured factor counted as
            zero would quietly understate the risk.
          </p>
          <div className="flex flex-wrap gap-2">
            {unestablishedFactors.map((f) => (
              <span key={f} className="mono text-[11px] px-2 py-1 rounded border border-base-border text-content-muted">
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
      <span className="text-[10px] uppercase tracking-wide text-content-dim">{label}</span>
    </span>
  )
}
