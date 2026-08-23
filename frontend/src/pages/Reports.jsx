import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { FileText, ShieldCheck, Grid3x3, GitBranch, FileStack, Check } from 'lucide-react'
import { PageHeader, Panel } from '../components/Panel'
import { run, severityColor } from '../data/scanData'
import {
  OPTIONAL_SECTIONS, REPORT_TYPES, SEVERITY_FILTERS, OWASP_SCOPES, typeById
} from '../data/reportSections'

const TYPE_ICON = {
  executive: ShieldCheck,
  technical: FileText,
  owasp: Grid3x3,
  attackchain: GitBranch,
  evidence: FileStack
}

export default function Reports() {
  const navigate = useNavigate()
  const [selectedType, setSelectedType] = useState('technical')
  const [sections, setSections] = useState(new Set(typeById('technical').sections))
  const [severity, setSeverity] = useState('all')
  const [owaspScope, setOwaspScope] = useState('all')

  // Choosing a type reseeds the checkboxes rather than filtering silently, so
  // what the reader sees ticked is what the report will actually contain.
  const chooseType = (id) => {
    setSelectedType(id)
    setSections(new Set(typeById(id).sections))
  }

  const toggleSection = (id) => {
    setSections((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  // Query params rather than router state: this is a print surface people
  // reload and share, and router state does not survive either.
  const generate = () => {
    const params = new URLSearchParams({
      type: selectedType,
      sections: OPTIONAL_SECTIONS.filter((s) => sections.has(s.id)).map((s) => s.id).join(','),
      severity,
      owasp: owaspScope
    })
    navigate(`/reports/preview?${params}`)
  }

  return (
    <div>
      <PageHeader title="Security Report Center" subtitle="Generate evidence-backed security validation reports." />

      <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-5 gap-4 mb-6">
        {REPORT_TYPES.map((r) => {
          const Icon = TYPE_ICON[r.id] ?? FileText
          return (
            <button
              key={r.id}
              onClick={() => chooseType(r.id)}
              className={`text-left p-4 rounded-lg border transition-colors ${
                selectedType === r.id ? 'border-brand bg-base-card2 shadow-glow' : 'border-base-border bg-base-card hover:border-base-border2'
              }`}
            >
              <Icon size={18} className={selectedType === r.id ? 'text-brand' : 'text-content-dim'} />
              <div className="text-[13px] font-bold text-content mt-2">{r.name}</div>
              <div className="text-[11px] text-content-dim mt-1 leading-relaxed">{r.desc}</div>
            </button>
          )
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <Panel title="Report Builder" className="lg:col-span-2">
          <div className="grid grid-cols-2 gap-4 mb-5">
            <div>
              <label className="label-eyebrow block mb-1.5">Validation Run</label>
              <div className="w-full bg-base-card2 border border-base-border rounded-lg px-3 py-2 text-[13px] text-content">
                {run.id} — {run.target}
              </div>
            </div>
            <div>
              <label className="label-eyebrow block mb-1.5">Report Type</label>
              <select value={selectedType} onChange={(e) => chooseType(e.target.value)} className="w-full bg-base-card2 border border-base-border rounded-lg px-3 py-2 text-[13px] text-content">
                {REPORT_TYPES.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </select>
            </div>
            <div>
              <label className="label-eyebrow block mb-1.5">Severity Filter</label>
              <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="w-full bg-base-card2 border border-base-border rounded-lg px-3 py-2 text-[13px] text-content">
                {SEVERITY_FILTERS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
              </select>
            </div>
            <div>
              <label className="label-eyebrow block mb-1.5">OWASP Scope</label>
              <select value={owaspScope} onChange={(e) => setOwaspScope(e.target.value)} className="w-full bg-base-card2 border border-base-border rounded-lg px-3 py-2 text-[13px] text-content">
                {OWASP_SCOPES.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.id === 'affected' ? `${o.label} (${run.owaspAffected}/${run.owaspTotal})` : o.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <label className="label-eyebrow block mb-2">Include Sections</label>
          <div className="grid grid-cols-2 gap-2 mb-3">
            {OPTIONAL_SECTIONS.map((s) => (
              <button
                key={s.id}
                onClick={() => toggleSection(s.id)}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-[13px] text-left transition-colors ${
                  sections.has(s.id) ? 'border-brand/50 bg-brand/10 text-content' : 'border-base-border text-content-dim'
                }`}
              >
                <span className={`w-4 h-4 rounded flex items-center justify-center shrink-0 border ${sections.has(s.id) ? 'bg-brand border-brand' : 'border-base-border2'}`}>
                  {sections.has(s.id) && <Check size={12} className="text-content" />}
                </span>
                {s.label}
              </button>
            ))}
          </div>
          <div className="text-[11px] text-content-dim mb-6 leading-relaxed">
            Cover, assessment scope, findings and conclusion always appear — a report that omits
            what was tested or what was found is not a shorter report.
          </div>

          <button
            onClick={generate}
            className="w-full bg-brand hover:bg-brand/90 text-white font-bold text-sm py-3 rounded-lg transition-colors shadow-glow"
          >
            GENERATE REPORT
          </button>
        </Panel>

        <Panel title="Report Summary">
          <div className="space-y-3 text-[13px]">
            <div className="flex justify-between"><span className="text-content-dim">Target</span><span className="text-content font-medium">{run.target}</span></div>
            <div className="flex justify-between"><span className="text-content-dim">Run</span><span className="mono text-brand font-semibold">{run.id}</span></div>
            <div className="flex justify-between"><span className="text-content-dim">Overall Risk</span><span className="font-bold" style={{ color: (severityColor[run.severity] ?? severityColor.NEUTRAL).text }}>{run.risk}/100 · {run.severity}</span></div>
            <div className="flex justify-between"><span className="text-content-dim">Total Findings</span><span className="text-content font-medium">{run.totalFindings}</span></div>
            <div className="flex justify-between"><span className="text-content-dim">Sections Selected</span><span className="text-content font-medium">{sections.size}/{OPTIONAL_SECTIONS.length}</span></div>
          </div>
          <div className="mt-5 pt-4 border-t border-base-border text-[11px] text-content-dim leading-relaxed">
            Generated reports are structured as a full assessment document — cover, executive summary, scope, findings, OWASP mapping, attack chain analysis, evidence, risk attribution, target control evaluation, recommendations and regression analysis. Every figure comes from the exported scan; nothing is illustrative.
          </div>
        </Panel>
      </div>
    </div>
  )
}
