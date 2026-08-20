import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { FileText, ShieldCheck, Grid3x3, GitBranch, FileStack, Check } from 'lucide-react'
import { PageHeader, Panel } from '../components/Panel'
import { run, severityColor } from '../data/scanData'

const reportTypes = [
  { id: 'executive', name: 'Executive Report', icon: ShieldCheck, desc: 'Technical security summary for management.' },
  { id: 'technical', name: 'Technical Report', icon: FileText, desc: 'Detailed findings, evidence, attack chains and recommendations.' },
  { id: 'owasp', name: 'OWASP Report', icon: Grid3x3, desc: 'OWASP category mapping and risk analysis.' },
  { id: 'attackchain', name: 'Attack Chain Report', icon: GitBranch, desc: 'Detailed attack path and evidence.' },
  { id: 'evidence', name: 'Evidence Report', icon: FileStack, desc: 'Complete evidence package.' }
]

const sectionOptions = [
  'Executive Summary', 'Risk Score', 'OWASP Mapping', 'Attack Chain',
  'Risk Attribution', 'Evidence', 'Target Control Evaluation', 'Recommendations', 'Regression Analysis'
]

export default function Reports() {
  const navigate = useNavigate()
  const [selectedType, setSelectedType] = useState('technical')
  const [sections, setSections] = useState(new Set(sectionOptions))
  const [severity, setSeverity] = useState('All Severities')

  const toggleSection = (s) => {
    setSections((prev) => {
      const next = new Set(prev)
      next.has(s) ? next.delete(s) : next.add(s)
      return next
    })
  }

  return (
    <div>
      <PageHeader title="Security Report Center" subtitle="Generate evidence-backed security validation reports." />

      <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-5 gap-4 mb-6">
        {reportTypes.map((r) => (
          <button
            key={r.id}
            onClick={() => setSelectedType(r.id)}
            className={`text-left p-4 rounded-lg border transition-colors ${
              selectedType === r.id ? 'border-brand bg-base-card2 shadow-glow' : 'border-base-border bg-base-card hover:border-base-border2'
            }`}
          >
            <r.icon size={18} className={selectedType === r.id ? 'text-brand' : 'text-slate-500'} />
            <div className="text-[13px] font-bold text-slate-100 mt-2">{r.name}</div>
            <div className="text-[11px] text-slate-500 mt-1 leading-relaxed">{r.desc}</div>
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <Panel title="Report Builder" className="lg:col-span-2">
          <div className="grid grid-cols-2 gap-4 mb-5">
            <div>
              <label className="label-eyebrow block mb-1.5">Validation Run</label>
              <div className="w-full bg-base-card2 border border-base-border rounded-lg px-3 py-2 text-[13px] text-slate-200">
                {run.id} — {run.target}
              </div>
            </div>
            <div>
              <label className="label-eyebrow block mb-1.5">Report Type</label>
              <select value={selectedType} onChange={(e) => setSelectedType(e.target.value)} className="w-full bg-base-card2 border border-base-border rounded-lg px-3 py-2 text-[13px] text-slate-200">
                {reportTypes.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </select>
            </div>
            <div>
              <label className="label-eyebrow block mb-1.5">Severity Filter</label>
              <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="w-full bg-base-card2 border border-base-border rounded-lg px-3 py-2 text-[13px] text-slate-200">
                <option>All Severities</option>
                <option>Critical Only</option>
                <option>Critical &amp; High</option>
              </select>
            </div>
            <div>
              <label className="label-eyebrow block mb-1.5">OWASP Scope</label>
              <select className="w-full bg-base-card2 border border-base-border rounded-lg px-3 py-2 text-[13px] text-slate-200">
                <option>All Categories</option>
                <option>Affected Only ({run.owaspAffected}/{run.owaspTotal})</option>
              </select>
            </div>
          </div>

          <label className="label-eyebrow block mb-2">Include Sections</label>
          <div className="grid grid-cols-2 gap-2 mb-6">
            {sectionOptions.map((s) => (
              <button
                key={s}
                onClick={() => toggleSection(s)}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-[13px] text-left transition-colors ${
                  sections.has(s) ? 'border-brand/50 bg-brand/10 text-slate-100' : 'border-base-border text-slate-500'
                }`}
              >
                <span className={`w-4 h-4 rounded flex items-center justify-center shrink-0 border ${sections.has(s) ? 'bg-brand border-brand' : 'border-base-border2'}`}>
                  {sections.has(s) && <Check size={12} className="text-white" />}
                </span>
                {s}
              </button>
            ))}
          </div>

          <button
            onClick={() => navigate('/reports/preview')}
            className="w-full bg-brand hover:bg-brand/90 text-white font-bold text-sm py-3 rounded-lg transition-colors shadow-glow"
          >
            GENERATE REPORT
          </button>
        </Panel>

        <Panel title="Report Summary">
          <div className="space-y-3 text-[13px]">
            <div className="flex justify-between"><span className="text-slate-500">Target</span><span className="text-slate-200 font-medium">{run.target}</span></div>
            <div className="flex justify-between"><span className="text-slate-500">Run</span><span className="mono text-brand font-semibold">{run.id}</span></div>
            <div className="flex justify-between"><span className="text-slate-500">Overall Risk</span><span className="font-bold" style={{ color: (severityColor[run.severity] ?? severityColor.NEUTRAL).text }}>{run.risk}/100 · {run.severity}</span></div>
            <div className="flex justify-between"><span className="text-slate-500">Total Findings</span><span className="text-slate-200 font-medium">{run.totalFindings}</span></div>
            <div className="flex justify-between"><span className="text-slate-500">Sections Selected</span><span className="text-slate-200 font-medium">{sections.size}/{sectionOptions.length}</span></div>
          </div>
          <div className="mt-5 pt-4 border-t border-base-border text-[11px] text-slate-500 leading-relaxed">
            Generated reports are structured as a full assessment document — cover, executive summary, scope, findings, OWASP mapping, attack chain analysis, evidence, risk attribution, target control evaluation, recommendations and regression analysis. Every figure comes from the exported scan; nothing is illustrative.
          </div>
        </Panel>
      </div>
    </div>
  )
}
