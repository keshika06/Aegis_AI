import { useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Download, FileJson, Printer } from 'lucide-react'
// A print surface, fixed light in both themes because it is exported to PDF.
// It carries its own literal palette rather than the page's theme variables,
// which would render white-on-white when exported from dark mode.
const PRINT_SEVERITY = {
  CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#ca8a04', LOW: '#16a34a',
  INFO: '#2563eb', NEUTRAL: '#64748b', CONFIRMED: '#dc2626', LIKELY: '#ca8a04',
  SUSPECTED: '#64748b', OPEN: '#ea580c', CLEAR: '#16a34a'
}

import {
  run, findings, owaspCategories, riskComponents, factorContributions, contributionFinal,
  attackChainNodes, evidenceItems, dataSource, controlResults, regression,
  chainSummary, recommendedActions, contributionArithmetic, targetProfile
} from '../data/scanData'
import { planFromParams } from '../data/reportSections'

function sevPill(sev) {
  const c = PRINT_SEVERITY[sev] ?? PRINT_SEVERITY.NEUTRAL
  return (
    <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded" style={{ color: '#fff', backgroundColor: c }}>
      {sev}
    </span>
  )
}

export default function ReportPreview() {
  const printRef = useRef(null)
  const [params] = useSearchParams()
  const plan = planFromParams(params)

  // The severity filter selects which findings the report covers; everything
  // derived from findings follows it. Scan-level sections are left alone —
  // narrowing those would misreport what the scan actually did.
  const levels = plan.severity.levels
  const shownFindings = levels ? findings.filter((f) => levels.includes(f.severity)) : findings
  // Evidence joins on the raw finding id, not the display id.
  const shownFindingKeys = new Set(shownFindings.map((f) => f.findingId))
  const shownEvidence = levels
    ? evidenceItems.filter((e) => shownFindingKeys.has(e.findingId))
    : evidenceItems
  const shownOwasp = owaspCategories.filter((o) => {
    if (plan.owaspScope === 'affected' && o.findings === 0) return false
    if (levels && !levels.includes(o.severity)) return false
    return true
  })
  // Named from what the scan found, rather than asserting which categories
  // drove the result before looking.
  const topCategories = [...shownOwasp]
    .filter((o) => o.findings > 0)
    .sort((a, b) => b.risk - a.risk)
    .slice(0, 2)

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
      meta: dataSource,
      report: {
        type: plan.type.id,
        severityFilter: plan.severity.id,
        owaspScope: plan.owaspScope
      },
      run,
      findings: shownFindings,
      owaspCategories: shownOwasp,
      evidenceItems: shownEvidence,
      riskComponents, controlResults, regression, attackChainNodes, factorContributions
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
          <p className="text-sm text-slate-500 mt-1">{plan.type.name} · {run.id} · {run.target}</p>
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
          <div className="text-xs tracking-[0.2em] text-slate-400 mt-2">{plan.type.name.toUpperCase()}</div>
          <div className="mt-8 mono text-brand font-bold text-lg">{run.id}</div>
          <div className="text-sm text-slate-400 mt-1">{run.target} · {run.date}</div>
        </div>

        {(plan.severity.levels || plan.owaspScope === 'affected') && (
          <div className="bg-[#fef3c7] border-b border-[#fcd34d] px-10 py-3 text-[12px] text-[#78350f]">
            <span className="font-bold">Filtered report.</span>{' '}
            {plan.severity.levels && (
              <>Findings, OWASP rows and evidence are limited to{' '}
              <span className="font-bold">{plan.severity.label.toLowerCase()}</span> —{' '}
              showing {shownFindings.length} of {findings.length}. </>
            )}
            {plan.owaspScope === 'affected' && <>OWASP mapping shows affected categories only. </>}
            Scan-level figures (risk score, control evaluation, regression) describe the whole scan.
          </div>
        )}

        <div className="px-10 py-10 space-y-10">
          {/* Executive Summary */}
          {plan.shows('exec') && (
          <Section title={plan.heading('exec')}>
            <div className="grid grid-cols-4 gap-4">
              <Stat label="Overall Risk" value={run.severity} color={PRINT_SEVERITY[run.severity] ?? '#0a0e17'} />
              <Stat label="Risk Score" value={`${run.risk}/100`} />
              <Stat label="Critical Findings" value={run.critical} color="#dc2626" />
              <Stat label="OWASP Categories" value={`${run.owaspAffected}/${run.owaspTotal}`} />
            </div>
            <p className="text-sm text-[#3a4152] leading-relaxed mt-4">
              The validation of {run.target} identified {run.totalFindings} finding{run.totalFindings === 1 ? '' : 's'} across{' '}
              {run.owaspAffected} OWASP LLM Top 10 categor{run.owaspAffected === 1 ? 'y' : 'ies'}, of which{' '}
              {run.confirmed} {run.confirmed === 1 ? 'was' : 'were'} confirmed by deterministic evidence. The overall risk
              score is {run.risk}/100 ({run.severity})
              {run.previousRisk !== null && run.previousRisk !== undefined
                ? `, ${run.risk - run.previousRisk >= 0 ? 'up' : 'down'} ${Math.abs(run.risk - run.previousRisk)} points from the previous run (${run.previousRisk})`
                : ' (first recorded run for this target)'}.
              {chainSummary.title
                ? ` The most significant exposure was "${chainSummary.title}", which breached ${chainSummary.breachedLayers} of ${chainSummary.totalLayers} defence layers.`
                : ''}
            </p>
          </Section>
          )}

          {/* Scope & Target */}
          {plan.shows('scope') && (
          <Section title={plan.heading('scope')}>
            <div className="grid grid-cols-2 gap-6 text-sm">
              <div>
                <div className="font-semibold text-[#0a0e17] mb-1">Target Application</div>
                <div className="text-[#5a6478]">{run.target}</div>
              </div>
              <div>
                <div className="font-semibold text-[#0a0e17] mb-1">Application Type</div>
                <div className="text-[#5a6478]">{targetProfile.type}</div>
              </div>
            </div>
            {targetProfile.endpoints.length > 0 && (
              <div className="mt-4">
                <div className="font-semibold text-[#0a0e17] mb-1 text-sm">Attack surface discovered</div>
                <div className="flex flex-wrap gap-1.5">
                  {targetProfile.endpoints.map((e, i) => (
                    <span key={i} className="font-mono text-[11px] border border-[#d1d5db] rounded px-2 py-0.5 bg-white">
                      {typeof e === 'string' ? e : (e.path ?? e.name ?? JSON.stringify(e))}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </Section>
          )}

          {/* Risk Score */}
          {plan.shows('risk') && (
          <Section title={plan.heading('risk')}>
            <div className="grid grid-cols-2 gap-8 items-center">
              <div className="text-center">
                <div className="text-6xl font-extrabold" style={{ color: PRINT_SEVERITY[run.severity] ?? '#0a0e17' }}>{run.risk}</div>
                <div className="text-sm text-[#5a6478]">out of 100 · {run.severity} RISK</div>
              </div>
              <div className="space-y-2">
                {riskComponents.map((c) => (
                  <div key={c.label}>
                    <div className="flex justify-between text-xs mb-0.5">
                      <span>{c.label} <span className="text-[#5a6478]">({c.axis})</span></span>
                      <span className="font-bold">{c.established ? c.score : 'not established'}</span>
                    </div>
                    <div className="h-1.5 bg-[#e5e7eb] rounded-full overflow-hidden">
                      {c.established && (
                        <div className="h-full rounded-full" style={{ width: `${c.score}%`, backgroundColor: c.axis === 'impact' ? '#dc2626' : '#ea580c' }} />
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </Section>
          )}

          {/* Findings */}
          {plan.shows('findings') && (
          <Section title={plan.heading('findings')}>
            <table className="w-full text-xs border-collapse">
              <thead>
                <tr className="border-b-2 border-[#0a0e17] text-left">
                  <th className="py-2 pr-2">ID</th><th className="py-2 pr-2">Title</th><th className="py-2 pr-2">OWASP</th><th className="py-2 pr-2">Severity</th><th className="py-2 pr-2">Risk</th><th className="py-2 pr-2">Verdict</th>
                </tr>
              </thead>
              <tbody>
                {shownFindings.map((f) => (
                  <tr key={f.id} className="border-b border-[#e5e7eb]">
                    <td className="py-1.5 pr-2 font-mono">{f.id}</td>
                    <td className="py-1.5 pr-2">{f.title}</td>
                    <td className="py-1.5 pr-2 font-mono">{f.owasp}</td>
                    <td className="py-1.5 pr-2">{sevPill(f.severity)}</td>
                    <td className="py-1.5 pr-2 font-bold">{f.risk}</td>
                    <td className="py-1.5 pr-2">{f.verdict}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {shownFindings.length === 0 && (
              <p className="text-xs text-[#5a6478] mt-2">
                No finding matches the {plan.severity.label.toLowerCase()} filter. The scan
                recorded {run.totalFindings} finding{run.totalFindings === 1 ? '' : 's'} in total.
              </p>
            )}
          </Section>
          )}

          {/* OWASP Mapping */}
          {plan.shows('owasp') && (
          <Section title={plan.heading('owasp')}>
            <div className="grid grid-cols-5 gap-3">
              {shownOwasp.map((o) => (
                <div key={o.id} className="border border-[#e5e7eb] rounded-lg p-3">
                  <div className="font-mono text-xs font-bold">{o.id}</div>
                  <div className="text-[11px] text-[#5a6478] mb-2 truncate">{o.name}</div>
                  {o.findings > 0 ? sevPill(o.severity) : sevPill('NEUTRAL')}
                  <div className="text-[11px] mt-1">{o.findings} findings</div>
                </div>
              ))}
              {shownOwasp.length === 0 && (
                <p className="text-[11px] text-[#5a6478] col-span-5">
                  No OWASP category matches the selected scope.
                </p>
              )}
            </div>
          </Section>
          )}

          {/* Attack Chain */}
          {plan.shows('chain') && (
          <Section title={plan.heading('chain')}>
            <div className="flex items-center flex-wrap gap-1 text-[11px] font-mono">
              {attackChainNodes.length === 0 && <span className="text-[#5a6478]">No attack chain was built for this scan.</span>}
              {attackChainNodes.map((n, i, arr) => (
                <span key={n.id} className="flex items-center gap-1">
                  <span className="border border-[#d1d5db] rounded px-2 py-1 bg-white">{n.name}</span>
                  {i < arr.length - 1 && <span>→</span>}
                </span>
              ))}
            </div>
            <div className="text-sm mt-3">Attack Chain Risk: <span className="font-bold" style={{ color: PRINT_SEVERITY[chainSummary.riskLevel] ?? '#0a0e17' }}>{chainSummary.risk}/100</span> · Furthest phase a defence failed at: <span className="font-bold">{chainSummary.worstPhaseName ?? '—'}</span></div>
          </Section>
          )}

          {/* Evidence */}
          {plan.shows('evidence') && (
          <Section title={plan.heading('evidence')}>
            <div className="grid grid-cols-3 gap-3 text-xs">
              {shownEvidence.slice(0, 6).map((e) => (
                <div key={e.id} className="border border-[#e5e7eb] rounded-lg p-2.5">
                  <div className="font-mono font-bold">{e.id}</div>
                  <div className="text-[#5a6478]">{e.type} · {e.timestamp}</div>
                  <div className="text-[#5a6478]">Confidence: {e.confidence}%</div>
                </div>
              ))}
              {shownEvidence.length === 0 && (
                <p className="text-[#5a6478] col-span-3">
                  No evidence belongs to a finding matching the selected severity.
                </p>
              )}
            </div>
          </Section>
          )}

          {/* Risk attribution */}
          {plan.shows('attribution') && (
          <Section title={plan.heading('attribution')}>
            <div className="text-sm mb-2">
              {contributionArithmetic ?? `Composite ${contributionFinal}/10`}
            </div>
            <p className="text-xs text-[#5a6478] mb-3">
              The model multiplies likelihood by impact and scales by evidence confidence. Each row
              below is that factor's weighted share of its own axis.
            </p>
            <table className="w-full text-xs">
              <thead><tr className="border-b-2 border-[#0a0e17] text-left"><th className="py-2">Factor</th><th>Axis</th><th>Value</th><th>Share of axis</th></tr></thead>
              <tbody>
                {factorContributions.map((f) => (
                  <tr key={f.feature} className="border-b border-[#e5e7eb]">
                    <td className="py-1 font-mono">{f.feature}</td>
                    <td className="py-1">{f.axis}</td>
                    <td className="py-1 font-bold">{f.value.toFixed(2)}</td>
                    <td className="py-1 text-[#5a6478]">{f.contribution.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
          )}

          {/* Controls */}
          {plan.shows('controls') && (
          <Section title={plan.heading('controls')}>
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
          )}

          {/* Recommendations */}
          {plan.shows('recommendations') && (
          <Section title={plan.heading('recommendations')}>
            <ol className="list-decimal list-inside text-sm space-y-1 text-[#3a4152]">
              {recommendedActions.map((a) => <li key={a}>{a}</li>)}
              {recommendedActions.length === 0 && (
                <li>No remediation required — no finding reached CONFIRMED.</li>
              )}
            </ol>
          </Section>
          )}

          {/* Regression */}
          {plan.shows('regression') && (
          <Section title={plan.heading('regression')}>
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
          )}

          {/* Conclusion */}
          {plan.shows('conclusion') && (
          <Section title={plan.heading('conclusion')}>
            <p className="text-sm text-[#3a4152] leading-relaxed">
              {run.target} scored {run.risk}/100 ({run.severity}) across {run.totalFindings} finding
              {run.totalFindings === 1 ? '' : 's'}, {run.confirmed} of which reached CONFIRMED on
              deterministic evidence.
              {topCategories.length > 0 && (
                <> The heaviest exposure was in {topCategories.map((o) => `${o.id} ${o.name}`).join(' and ')}.</>
              )}
              {run.baseRejectedCases === 0 && (
                <> No probe was rejected by an input control, so no such control was observed on this target.</>
              )}
              {' '}Re-validate after remediation to confirm the score moves.
            </p>
          </Section>
          )}
        </div>

        <div className="bg-[#0a0e17] text-slate-500 text-center text-[11px] py-4">
          AegisAI — AI Application Security Validation Platform · {run.id} · Generated {run.date}
        </div>
      </div>
    </div>
  )
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
