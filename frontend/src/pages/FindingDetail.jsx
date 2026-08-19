import { useParams, Link } from 'react-router-dom'
import { PageHeader, Panel, Bar } from '../components/Panel'
import SeverityBadge from '../components/SeverityBadge'
import { finding_detail, findings, attackChainNodes } from '../data/scanData'

export default function FindingDetail() {
  const { id } = useParams()
  const summary = findings.find((f) => f.id === id) || findings[0]
  const d = { ...finding_detail, id: summary.id, title: summary.title, severity: summary.severity, risk: summary.risk, confidence: summary.confidence, owasp: summary.owasp, status: summary.status }

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
            <div className="text-right"><div className="text-[11px] text-slate-500">Risk Score</div><div className="text-xl font-bold text-white">{d.risk}/100</div></div>
            <div className="text-right"><div className="text-[11px] text-slate-500">Confidence</div><div className="text-xl font-bold text-white">{d.confidence}%</div></div>
          </div>
        }
      />
      <div className="flex items-center gap-2 mb-6 -mt-4">
        <SeverityBadge level={d.severity} size="lg" />
        <Link to="/owasp-mapping" className="mono text-xs text-slate-400 border border-base-border rounded px-2 py-1">{d.owasp}</Link>
        <span className="text-xs font-bold text-sev-high border border-base-border rounded px-2 py-1">{d.status}</span>
      </div>

      <Panel className="mb-5 !bg-gradient-to-br !from-base-card !to-base-card2 border-brand/30">
        <div className="label-eyebrow mb-2 text-brand">Executive Explanation</div>
        <p className="text-[14px] text-slate-200 leading-relaxed italic">"{d.summary}"</p>
      </Panel>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
        <Panel title="Why This Is Risky">
          {d.components.map((c) => <Bar key={c.label} label={c.label} score={c.score} color="#ef4444" />)}
        </Panel>

        <Panel title="Evidence">
          <div className="space-y-2">
            {d.evidence.map((e) => (
              <Link key={e.id} to="/evidence" className="flex items-center justify-between p-2.5 rounded-lg hover:bg-base-card2 transition-colors border border-base-border">
                <div className="flex items-center gap-3">
                  <span className="mono text-xs text-brand font-semibold">{e.id}</span>
                  <span className="text-xs text-slate-300">{e.type}</span>
                </div>
                <div className="flex items-center gap-3 text-[11px] text-slate-500">
                  <span>{e.source}</span>
                  <span className="mono">{e.timestamp}</span>
                </div>
              </Link>
            ))}
          </div>
        </Panel>
      </div>

      <Panel title="Attack Chain" className="mb-5">
        <div className="flex items-center gap-0 overflow-x-auto scroll-thin">
          {attackChainNodes.map((n, i, arr) => (
            <div key={n.id} className="flex items-center">
              <div className="px-3 py-1.5 rounded-lg border border-base-border bg-base-card2 mono text-[11px] text-slate-300 whitespace-nowrap">{n.name}</div>
              {i < arr.length - 1 && <div className="w-4 h-px bg-base-border2 mx-1" />}
            </div>
          ))}
        </div>
        <Link to="/attack-chain" className="text-xs text-brand font-semibold mt-3 inline-block">Open full Attack Chain Explorer →</Link>
      </Panel>

      <Panel title="Recommendation" className="border-l-4 border-l-sev-critical">
        <div className="flex items-start gap-3">
          <SeverityBadge level={d.recommendation.priority} size="lg" />
          <p className="text-[13px] text-slate-300 leading-relaxed flex-1">{d.recommendation.text}</p>
        </div>
      </Panel>
    </div>
  )
}
