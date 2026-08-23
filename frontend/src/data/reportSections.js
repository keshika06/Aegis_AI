// The report's section catalogue, shared by the builder and the preview.
//
// Both pages used to keep their own list: Reports.jsx offered nine checkboxes
// and ReportPreview.jsx hardcoded fourteen numbered sections, with nothing
// connecting them. Selections were collected and thrown away. One list means a
// section cannot exist in the builder without existing in the document.

// Sections a reader may switch off, in the order they appear in the document.
export const OPTIONAL_SECTIONS = [
  { id: 'exec', label: 'Executive Summary' },
  { id: 'risk', label: 'Risk Score' },
  { id: 'owasp', label: 'OWASP Mapping' },
  { id: 'chain', label: 'Attack Chain' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'attribution', label: 'Risk Attribution' },
  { id: 'controls', label: 'Target Control Evaluation' },
  { id: 'recommendations', label: 'Recommendations' },
  { id: 'regression', label: 'Regression Analysis' }
]

export const ALL_SECTION_IDS = OPTIONAL_SECTIONS.map((s) => s.id)

// Scope, findings and conclusion are not offered as toggles. A security report
// that omits what was tested, what was found, or what it concluded is not a
// shorter report — it is an unreadable one.
export const ALWAYS_INCLUDED = ['scope', 'findings', 'conclusion']

// Each report type is a starting selection, not a separate document. Picking
// one seeds the checkboxes; the reader is free to tweak from there.
export const REPORT_TYPES = [
  {
    id: 'executive',
    name: 'Executive Report',
    desc: 'Technical security summary for management.',
    sections: ['exec', 'risk', 'owasp', 'recommendations']
  },
  {
    id: 'technical',
    name: 'Technical Report',
    desc: 'Detailed findings, evidence, attack chains and recommendations.',
    sections: ALL_SECTION_IDS
  },
  {
    id: 'owasp',
    name: 'OWASP Report',
    desc: 'OWASP category mapping and risk analysis.',
    sections: ['exec', 'risk', 'owasp', 'attribution', 'recommendations']
  },
  {
    id: 'attackchain',
    name: 'Attack Chain Report',
    desc: 'Detailed attack path and evidence.',
    sections: ['exec', 'chain', 'evidence', 'attribution', 'recommendations']
  },
  {
    id: 'evidence',
    name: 'Evidence Report',
    desc: 'Complete evidence package.',
    sections: ['exec', 'evidence', 'controls', 'attribution']
  }
]

export const typeById = (id) => REPORT_TYPES.find((r) => r.id === id) ?? REPORT_TYPES[1]

// Severity filter. It selects which *findings* the report covers; everything
// derived from findings follows. Scan-level sections (risk score, control
// evaluation, regression) describe the whole scan and are left alone, because
// narrowing them would misreport what the scan actually did.
export const SEVERITY_FILTERS = [
  { id: 'all', label: 'All Severities', levels: null },
  { id: 'critical', label: 'Critical Only', levels: ['CRITICAL'] },
  { id: 'critical-high', label: 'Critical & High', levels: ['CRITICAL', 'HIGH'] }
]

export const severityFilterById = (id) =>
  SEVERITY_FILTERS.find((s) => s.id === id) ?? SEVERITY_FILTERS[0]

export const OWASP_SCOPES = [
  { id: 'all', label: 'All Categories' },
  { id: 'affected', label: 'Affected Only' }
]

// The order blocks appear in the document. Numbering is derived from whichever
// of these survive the reader's selection, so a report with sections switched
// off numbers 1..n with no gaps rather than jumping from 1 to 7.
export const DOCUMENT_ORDER = [
  'exec', 'scope', 'risk', 'findings', 'owasp', 'chain',
  'evidence', 'attribution', 'controls', 'recommendations', 'regression', 'conclusion'
]

export const SECTION_TITLE = {
  exec: 'Executive Summary',
  scope: 'Assessment Scope & Target Profile',
  risk: 'Risk Score',
  findings: 'Findings',
  owasp: 'OWASP Mapping',
  chain: 'Attack Chain Analysis',
  evidence: 'Evidence',
  attribution: 'Risk Attribution',
  controls: 'Target Control Evaluation',
  recommendations: 'Recommendations',
  regression: 'Regression Analysis',
  conclusion: 'Conclusion'
}

/** Resolve the builder's query params into what the document should render. */
export function planFromParams(params) {
  const raw = params.get('sections')
  // No params at all means someone opened the preview directly. A full report
  // is the honest default: silently emitting an empty one would look like a
  // scan that found nothing.
  const selected = raw === null ? new Set(ALL_SECTION_IDS) : new Set(raw.split(',').filter(Boolean))
  const included = DOCUMENT_ORDER.filter(
    (id) => ALWAYS_INCLUDED.includes(id) || selected.has(id)
  )
  const numberOf = Object.fromEntries(included.map((id, i) => [id, i + 1]))
  return {
    type: typeById(params.get('type') ?? 'technical'),
    severity: severityFilterById(params.get('severity') ?? 'all'),
    owaspScope: params.get('owasp') === 'affected' ? 'affected' : 'all',
    shows: (id) => numberOf[id] !== undefined,
    heading: (id) => `${numberOf[id]} · ${SECTION_TITLE[id]}`
  }
}
