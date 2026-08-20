import { useParams, Link } from 'react-router-dom'
import { PageHeader, Panel, Bar } from '../components/Panel'
import SeverityBadge from '../components/SeverityBadge'
import { findingDetails, findings } from '../data/scanData'
import { useTokens } from '../theme'

// Likelihood and impact multiply, so they are shown as two groups rather than
// one flat list — a reader comparing a factor against the wrong axis would draw
// the wrong conclusion about which one to fix.
const AXIS_LABEL = {
  likelihood: 'Likelihood — how readily this path is walked again',
  impact: 'Impact — what it costs when it is'
}

export default function FindingDetail() {
  const t = useTokens()
  const { id } = useParams()
  const d = findingDetails[id]

  if (!d) {
    return (
      <div>
        <PageHeader title="Finding not found" subtitle={`No finding ${id} in the exported scan.`} />
        <Panel>
          <Link to="/findings" className="text-sm text-brand font-semibold">Back to all findings →</Link>
        </Panel>
      </div>
    )
  }

  const axes = ['likelihood', 'impact'].filter((a) => d.components.some((c) => c.axis === a))

  return (
    <div>
      <PageHeader
        title={
          <span className="flex items-center gap-3">
            <span className="mono text-brand">{d.id}</span>
            <span>{d.title}</span>
          </span>
        }
        right={
          <div className="flex items-center gap-4">
            <div className="text-right"><div className="text-[11px] text-content-dim">Risk Score</div><div className="text-xl font-bold text-content">{d.risk}/100</div></div>
            <div className="text-right"><div className="text-[11px] text-content-dim">Confidence</div><div className="text-xl font-bold text-content">{d.confidence}%</div></div>
          </div>
        }
      />
      <div className="flex items-center gap-2 mb-6 -mt-4 flex-wrap">
        <SeverityBadge level={d.severity} size="lg" />
        <Link to="/owasp-mapping" className="mono text-xs text-content-muted border border-base-border rounded px-2 py-1">
          {d.owasp}{d.owaspName !== '—' ? ` · ${d.owaspName}` : ''}
        </Link>
        <span className="text-xs font-bold text-content border border-base-border rounded px-2 py-1">{d.verdict}</span>
        <span className="mono text-[11px] text-content-dim border border-base-border rounded px-2 py-1">
          {d.transformation === 'none' ? 'sent as written' : `via ${d.transformation}`}
        </span>
      </div>

      {d.description && (
        <Panel className="mb-5 !bg-gradient-to-br !from-base-card !to-base-card2 border-brand/30">
          <div className="label-eyebrow mb-2 text-brand">What was found</div>
          <p className="text-[14px] text-content leading-relaxed">{d.description}</p>
          {d.intent && (
            <p className="text-[12px] text-content-dim mt-2">
              Objective under test: <span className="text-content-muted">{d.intent.replace(/_/g, ' ')}</span>
            </p>
          )}
        </Panel>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
        <Panel title="Why this scored what it did">
          {axes.map((axis) => (
            <div key={axis} className="mb-4 last:mb-0">
              <div className="text-[11px] uppercase tracking-wide text-content-dim mb-2">{AXIS_LABEL[axis]}</div>
              {d.components.filter((c) => c.axis === axis).map((c) => (
                <Bar key={c.label} label={c.label} score={c.score} color={axis === 'impact' ? '#ef4444' : t.high} sub={`weight ${c.weight}% of ${axis}`} />
              ))}
            </div>
          ))}
          {d.unestablished.length > 0 && (
            <div className="mt-3 pt-3 border-t border-base-border text-[11px] text-content-dim">
              Not established for this finding, so excluded from the weighting: {d.unestablished.join(', ')}.
            </div>
          )}
          {d.explanation && <div className="mt-3 mono text-[11px] text-content-dim">{d.explanation}</div>}
        </Panel>

        <Panel title="Evidence">
          <div className="space-y-2">
            {d.evidence.length === 0 && <div className="text-sm text-content-dim">No evidence recorded for this finding.</div>}
            {d.evidence.map((e) => (
              <Link key={e.id} to="/evidence" className="flex items-center justify-between p-2.5 rounded-lg hover:bg-base-card2 transition-colors border border-base-border">
                <div className="flex items-center gap-3 min-w-0">
                  <span className="mono text-xs text-brand font-semibold shrink-0">{e.id}</span>
                  <span className="text-xs text-content shrink-0">{e.type}</span>
                  <span className="text-[11px] text-content-dim truncate">{e.summary}</span>
                </div>
                <div className="flex items-center gap-3 text-[11px] text-content-dim shrink-0">
                  <span className={e.deterministic ? 'text-sev-low font-bold' : ''}>{e.deterministic ? 'proof' : 'supporting'}</span>
                  <span className="mono">{e.timestamp}</span>
                </div>
              </Link>
            ))}
          </div>
        </Panel>
      </div>

      {d.payload && (
        <Panel title="The probe that produced this" className="mb-5">
          <pre className="mono text-[12px] text-content bg-base-bg rounded-lg p-3 border border-base-border whitespace-pre-wrap break-words max-h-60 overflow-y-auto">
{d.payload}
          </pre>
        </Panel>
      )}

      {d.violations.length > 0 && (
        <Panel title="Policy boundaries crossed" className="mb-5">
          <div className="space-y-2">
            {d.violations.map((v) => (
              <div key={v.boundary} className="text-[12px] bg-base-bg rounded-lg p-2.5 border border-base-border">
                <div className="mono text-content font-semibold mb-0.5">{v.boundary}</div>
                <div className="text-content-dim">expected: {v.expected}</div>
                <div className="text-sev-critical">observed: {v.observed}</div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {d.mitigation && (
        <Panel title="Recommendation" className="border-l-4 border-l-sev-critical">
          <p className="text-[13px] text-content leading-relaxed">{d.mitigation}</p>
        </Panel>
      )}
    </div>
  )
}
