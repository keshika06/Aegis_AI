import { useRef } from 'react'
import { Download, FileJson, Printer } from 'lucide-react'
import {
  run, findings, owaspCategories, riskComponents, factorContributions, contributionFinal,
  attackChainNodes, evidenceItems, dataSource, controlResults, regression, severityColor
} from '../data/scanData'

function sevPill(sev) {
  const c = severityColor[sev] || severityColor.NEUTRAL
  return (
    <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded" style={{ color: '#fff', backgroundColor: c.text }}>
      {sev}
    </span>
  )
}

export default function ReportPreview() {
  const printRef = useRef(null)

  // The anchor must be in the document for Firefox to honour the click, and the
  // blob URL must outlive it — revoking synchronously after click() cancels the
  // download before the browser has started reading it.
  const download = (blob, filename) => {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.style.display = 'none'
    document.body.appendChild(a)
    a.click()
    setTimeout(() => {
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    }, 1000)
  }

  const exportJSON = () => {
    const payload = {
      meta: dataSource, run, findings, owaspCategories, riskComponents,
      controlResults, regression, evidenceItems, attackChainNodes, factorContributions
    }
    download(
      new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }),
      `AegisAI_${run.id}_Report.json`
    )
  }

  const exportHTML = () => {
    if (!printRef.current) return
    const styles = [...document.querySelectorAll('style, link[rel="stylesheet"]')]
      .map((n) => n.outerHTML)
      .join('')
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>AegisAI ${run.id} Report</title>${styles}</head><body class="bg-white">${printRef.current.innerHTML}</body></html>`
    download(new Blob([html], { type: 'text/html' }), `AegisAI_${run.id}_Report.html`)
  }

  const exportPDF = () => window.print()

  return (
    <div>
      <div className="flex items-center justify-between mb-5 print:hidden">
        <div>
          <h1 className="text-2xl font-bold text-white">Report Preview</h1>
          <p className="text-sm text-slate-500 mt-1">{run.id} · {reportName()}</p>
        </div>
        <div className="flex gap-2">
          <button onClick={exportHTML} className="flex items-center gap-1.5 bg-base-card border border-base-border text-slate-200 text-[13px] font-semibold px-3 py-2 rounded-lg hover:border-brand/50 transition-colors">
            <Download size={14} /> Export HTML
          </button>
          <button onClick={exportPDF} className="flex items-center gap-1.5 bg-base-card border border-base-border text-slate-200 text-[13px] font-semibold px-3 py-2 rounded-lg hover:border-brand/50 transition-colors">
            <Printer size={14} /> Export PDF
          </button>
          <button onClick={exportJSON} className="flex items-center gap-1.5 bg-brand text-white text-[13px] font-semibold px-3 py-2 rounded-lg hover:bg-brand/90 transition-colors">
            <FileJson size={14} /> Export JSON
          </button>
        </div>
      </div>

      {/* Printable report surface — light theme per spec, optimized for PDF/print */}
      <div ref={printRef} className="bg-[#f5f6f8] text-[#1a1f2b] rounded-xl overflow-hidden shadow-2xl print:rounded-none print:shadow-none">
        {/* Cover / dark header */}
        <div className="bg-[#0a0e17] text-white px-10 py-14 text-center">
          <div className="text-3xl font-extrabold tracking-tight">AEGIS<span className="text-brand">AI</span></div>
          <div className="text-xs tracking-[0.2em] text-slate-400 mt-2">AI APPLICATION SECURITY VALIDATION REPORT</div>
          <div className="mt-8 mono text-brand font-bold text-lg">{run.id}</div>
          <div className="text-sm text-slate-400 mt-1">{run.target} · {run.date}</div>
        </div>

        <div className="px-10 py-10 space-y-10">
          {/* Executive Summary */}
          <Section title="1 · Executive Summary">
            <div className="grid grid-cols-4 gap-4">
              <Stat label="Overall Risk" value="HIGH" color="#dc2626" />
              <Stat label="Risk Score" value={`${run.risk}/100`} />
              <Stat label="Critical Findings" value={run.critical} color="#dc2626" />
              <Stat label="OWASP Categories" value={`${run.owaspAffected}/${run.owaspTotal}`} />
            </div>
            <p className="text-sm text-[#3a4152] leading-relaxed mt-4">
              The validation of {run.target} identified {run.totalFindings} findings across {run.owaspAffected} OWASP LLM Top 10
              categories, resulting in an overall risk score of {run.risk}/100 ({run.severity}), an increase of{' '}
              {run.risk - run.previousRisk} points from the previous validation run ({run.previousRisk}). The most significant
              exposure was an indirect prompt injection that bypassed the prompt guardrail and reached a privileged tool
              invocation.
            </p>
          </Section>

          {/* Scope & Target */}
          <Section title="2 · Assessment Scope & 3 · Target Profile">
            <div className="grid grid-cols-2 gap-6 text-sm">
              <div>
                <div className="font-semibold text-[#0a0e17] mb-1">Target Application</div>
                <div className="text-[#5a6478]">{run.target}</div>
              </div>
              <div>
                <div className="font-semibold text-[#0a0e17] mb-1">Validation Type</div>
                <div className="text-[#5a6478]">Closed-loop continuous red-team validation, OWASP AI Top 10 aligned</div>
              </div>
            </div>
          </Section>

          {/* Risk Score */}
          <Section title="4 · Overall Security Posture & 5 · Risk Score">
            <div className="grid grid-cols-2 gap-8 items-center">
              <div className="text-center">
                <div className="text-6xl font-extrabold" style={{ color: '#dc2626' }}>{run.risk}</div>
                <div className="text-sm text-[#5a6478]">out of 100 · HIGH RISK</div>
              </div>
              <div className="space-y-2">
                {riskComponents.map((c) => (
                  <div key={c.label}>
                    <div className="flex justify-between text-xs mb-0.5"><span>{c.label}</span><span className="font-bold">{c.score}</span></div>
                    <div className="h-1.5 bg-[#e5e7eb] rounded-full overflow-hidden"><div className="h-full bg-[#dc2626] rounded-full" style={{ width: `${c.score}%` }} /></div>
                  </div>
                ))}
              </div>
            </div>
          </Section>

          {/* Findings */}
          <Section title="6 · Findings">
            <table className="w-full text-xs border-collapse">
              <thead>
                <tr className="border-b-2 border-[#0a0e17] text-left">
                  <th className="py-2 pr-2">ID</th><th className="py-2 pr-2">Title</th><th className="py-2 pr-2">OWASP</th><th className="py-2 pr-2">Severity</th><th className="py-2 pr-2">Risk</th><th className="py-2 pr-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id} className="border-b border-[#e5e7eb]">
                    <td className="py-1.5 pr-2 font-mono">{f.id}</td>
                    <td className="py-1.5 pr-2">{f.title}</td>
                    <td className="py-1.5 pr-2 font-mono">{f.owasp}</td>
                    <td className="py-1.5 pr-2">{sevPill(f.severity)}</td>
                    <td className="py-1.5 pr-2 font-bold">{f.risk}</td>
                    <td className="py-1.5 pr-2">{f.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>

          {/* OWASP Mapping */}
          <Section title="7 · OWASP Mapping">
            <div className="grid grid-cols-5 gap-3">
              {owaspCategories.map((o) => (
                <div key={o.id} className="border border-[#e5e7eb] rounded-lg p-3">
                  <div className="font-mono text-xs font-bold">{o.id}</div>
                  <div className="text-[11px] text-[#5a6478] mb-2 truncate">{o.name}</div>
                  {o.findings > 0 ? sevPill(o.severity) : sevPill('NEUTRAL')}
                  <div className="text-[11px] mt-1">{o.findings} findings</div>
                </div>
              ))}
            </div>
          </Section>

          {/* Attack Chain */}
          <Section title="8 · Attack Chain Analysis">
            <div className="flex items-center flex-wrap gap-1 text-[11px] font-mono">
              {attackChainNodes.length === 0 && <span className="text-[#5a6478]">No attack chain was built for this scan.</span>}
              {attackChainNodes.map((n, i, arr) => (
                <span key={n.id} className="flex items-center gap-1">
                  <span className="border border-[#d1d5db] rounded px-2 py-1 bg-white">{n.name}</span>
                  {i < arr.length - 1 && <span>→</span>}
                </span>
              ))}
            </div>
            <div className="text-sm mt-3">Attack Chain Risk: <span className="font-bold" style={{ color: '#dc2626' }}>86/100</span> · Highest Risk Node: <span className="font-bold">Tool Invocation</span></div>
          </Section>

          {/* Evidence */}
          <Section title="9 · Evidence">
            <div className="grid grid-cols-3 gap-3 text-xs">
              {evidenceItems.slice(0, 6).map((e) => (
                <div key={e.id} className="border border-[#e5e7eb] rounded-lg p-2.5">
                  <div className="font-mono font-bold">{e.id}</div>
                  <div className="text-[#5a6478]">{e.type} · {e.timestamp}</div>
                  <div className="text-[#5a6478]">Confidence: {e.confidence}%</div>
                </div>
              ))}
            </div>
          </Section>

          {/* Risk attribution */}
          <Section title="10 · Risk Attribution">
            <div className="text-sm mb-2">Weighted factor contributions sum to the composite <span className="font-bold" style={{ color: '#dc2626' }}>{contributionFinal}/10</span></div>
            <table className="w-full text-xs">
              <tbody>
                {factorContributions.map((f) => (
                  <tr key={f.feature} className="border-b border-[#e5e7eb]">
                    <td className="py-1 font-mono">{f.feature}</td>
                    <td className="py-1" style={{ color: f.direction === 'up' ? '#dc2626' : '#16a34a' }}>{f.contribution > 0 ? '+' : ''}{f.contribution.toFixed(2)}</td>
                    <td className="py-1 text-[#5a6478]">{f.explain}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>

          {/* Controls */}
          <Section title="11 · Target Control Evaluation">
            <table className="w-full text-xs">
              <thead><tr className="border-b-2 border-[#0a0e17] text-left"><th className="py-2">Family</th><th>Tested</th><th>Rejected</th><th>Accepted</th><th>Accept rate</th></tr></thead>
              <tbody>
                {controlResults.map((c) => (
                  <tr key={c.name} className="border-b border-[#e5e7eb]">
                    <td className="py-1.5">{c.name}</td><td>{c.tested}</td><td>{c.rejected}</td><td>{c.accepted}</td><td className="font-bold">{c.acceptanceRate}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>

          {/* Recommendations */}
          <Section title="12 · Recommendations">
            <ol className="list-decimal list-inside text-sm space-y-1 text-[#3a4152]">
              <li>Strengthen contextual input isolation and enforce instruction hierarchy for RAG-sourced content.</li>
              <li>Reduce tool authorization scope for the agent runtime; require step-up approval for sensitive actions.</li>
              <li>Harden the prompt guardrail against Unicode / encoding-based obfuscation.</li>
              <li>Add output-side PII detection prior to summarization responses.</li>
            </ol>
          </Section>

          {/* Regression */}
          <Section title="13 · Regression Analysis">
            <div className="text-sm text-[#3a4152]">
              {regression.total === 0 ? (
                'No regression tests are stored for this target yet. They are created from confirmed findings.'
              ) : (
                <>
                  {regression.prevRun
                    ? `Compared to ${regression.prevRun}: `
                    : 'First recorded scan of this target: '}
                  {regression.fixed} resolved, {regression.new} newly stored, {regression.regressions} still failing.
                  {regression.detail && (
                    <> Most persistent: {regression.detail.category}.</>
                  )}
                  {regression.riskPrev !== null && regression.riskPrev !== undefined && (
                    <> Overall risk moved {regression.riskPrev} → {regression.riskCurrent}.</>
                  )}
                </>
              )}
            </div>
          </Section>

          {/* Conclusion */}
          <Section title="14 · Conclusion">
            <p className="text-sm text-[#3a4152] leading-relaxed">
              {run.target} presents a HIGH residual risk primarily driven by prompt injection and excessive agency exposure.
              Addressing the prioritized recommendations above and re-validating in the next scheduled run is advised before
              expanding this assistant's tool permissions further.
            </p>
          </Section>
        </div>

        <div className="bg-[#0a0e17] text-slate-500 text-center text-[11px] py-4">
          AegisAI — AI Application Security Validation Platform · {run.id} · Generated {run.date}
        </div>
      </div>
    </div>
  )
}

function reportName() {
  return 'Technical Report'
}

function Stat({ label, value, color }) {
  return (
    <div className="text-center border border-[#e5e7eb] rounded-lg py-3">
      <div className="text-[10px] uppercase tracking-wide text-[#5a6478]">{label}</div>
      <div className="text-xl font-extrabold mt-1" style={{ color: color || '#0a0e17' }}>{value}</div>
    </div>
  )
}

function Section({ title, children }) {
  return (
    <div className="break-inside-avoid">
      <div className="text-sm font-extrabold uppercase tracking-wide text-[#0a0e17] border-b-2 border-[#0a0e17] pb-2 mb-4">{title}</div>
      {children}
    </div>
  )
}
