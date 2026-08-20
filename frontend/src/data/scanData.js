// AegisAI dashboard data source.
//
// Reads scanData.json, which `aegisai dashboard export` writes from a real scan
// in the local database. There is no mock or demo fixture: if a value is not in
// the scan, the page shows an empty state rather than a plausible-looking
// placeholder. A security dashboard that invents numbers is worse than one that
// admits it has none.
//
// Every page imports from here, so wiring happens in one place.

import scan from './scanData.json'

export const dataSource = scan.meta ?? { source: 'unknown', generated_at: null, scan_id: null }
export const isLiveData = dataSource.source === 'aegisai'

// True when a newer scan exists in the database than the one exported here.
// The file is static, so this is the export-time answer - which is exactly the
// question a reader has: "am I looking at the scan I just ran?"
export const isStale =
  Boolean(dataSource.latest_scan_id) && dataSource.latest_scan_id !== dataSource.scan_id
export const latestScanId = dataSource.latest_scan_id ?? null

export const run = scan.run
export const riskRuns = scan.riskRuns ?? []
export const owaspCategories = scan.owaspCategories ?? []
export const findings = scan.findings ?? []
// Full detail for every finding, keyed by the id the tables link to, so the
// detail page shows the finding the reader clicked rather than the top one.
export const findingDetails = scan.findingDetails ?? {}
// The highest-scoring finding, for pages that describe the worst case.
export const finding_detail = scan.finding_detail ?? {}
export const attackChainNodes = scan.attackChainNodes ?? []
// One ordered phase sequence per chain: what was wanted, how it was sent,
// what each defence did, and what proves the outcome.
export const attackChains = scan.attackChains ?? []
export const attackTimeline = scan.attackTimeline ?? []
// Headline numbers for the worst chain, so pages never hardcode one.
export const chainSummary = scan.chainSummary ?? {}
export const riskComponents = scan.riskComponents ?? []
export const evidenceItems = scan.evidenceItems ?? []
export const outcomeDistribution = scan.outcomeDistribution ?? []
export const regression = scan.regression ?? {}
export const recommendedActions = scan.recommendedActions ?? []
export const targetProfile = scan.targetProfile ?? { url: '—', type: '—', endpoints: [] }

// Per-transformation-family results. AegisAI is a black-box evaluator: it never
// learns which controls a target implements, only how the target responded to
// each representation. Naming controls it never observed would be inventing
// knowledge, so this reports what was actually measured.
export const controlResults = scan.controlResults ?? []

// One row per attack objective, carrying the remediation that objective earned.
// Derived from the contract rules that fired, the runtime events the target
// emitted, its control decision and the representation that got through — so
// two scenarios differing in any of those carry different guidance.
export const attackScenarios = scan.attackScenarios ?? []

// Real decomposition of the risk score. The model multiplies likelihood by
// impact and scales by evidence confidence, so there is no single additive
// contribution per factor and presenting one would be a fabrication. What is
// true — and what this exports — is each factor's weighted share of its own
// axis, plus the two axis values and the arithmetic that combines them.
const contributions = scan.factorContributions ?? {}
export const factorContributions = contributions.features ?? []
export const contributionFinal = contributions.final ?? 0
export const contributionLikelihood = contributions.likelihood ?? null
export const contributionImpact = contributions.impact ?? null
export const contributionConfidence = contributions.confidence ?? null
export const contributionArithmetic = contributions.arithmetic ?? null
export const unestablishedFactors = contributions.unestablished ?? []

export const severityColor = {
  CRITICAL: { text: 'var(--sev-critical)', bg: 'var(--sev-critical-bg)', border: 'var(--sev-critical-border)' },
  HIGH: { text: 'var(--sev-high)', bg: 'var(--sev-high-bg)', border: 'var(--sev-high-border)' },
  MEDIUM: { text: 'var(--sev-medium)', bg: 'var(--sev-medium-bg)', border: 'var(--sev-medium-border)' },
  LOW: { text: 'var(--sev-low)', bg: 'var(--sev-low-bg)', border: 'var(--sev-low-border)' },
  INFO: { text: 'var(--sev-info)', bg: 'var(--sev-info-bg)', border: 'var(--sev-info-border)' },
  NEUTRAL: { text: 'var(--sev-neutral)', bg: 'var(--sev-neutral-bg)', border: 'var(--sev-neutral-border)' },
  CONFIRMED: { text: 'var(--sev-critical)', bg: 'var(--sev-critical-bg)', border: 'var(--sev-critical-border)' },
  LIKELY: { text: 'var(--sev-medium)', bg: 'var(--sev-medium-bg)', border: 'var(--sev-medium-border)' },
  SUSPECTED: { text: 'var(--sev-neutral)', bg: 'var(--sev-neutral-bg)', border: 'var(--sev-neutral-border)' },
  OPEN: { text: 'var(--sev-high)', bg: 'var(--sev-high-bg)', border: 'var(--sev-high-border)' },
  CLEAR: { text: 'var(--sev-low)', bg: 'var(--sev-low-bg)', border: 'var(--sev-low-border)' },
  RESOLVED: { text: 'var(--sev-low)', bg: 'var(--sev-low-bg)', border: 'var(--sev-low-border)' },
  REGRESSED: { text: 'var(--sev-critical)', bg: 'var(--sev-critical-bg)', border: 'var(--sev-critical-border)' },
  ACTIVE: { text: 'var(--sev-info)', bg: 'var(--sev-info-bg)', border: 'var(--sev-info-border)' },
  EXHAUSTED: { text: 'var(--sev-high)', bg: 'var(--sev-high-bg)', border: 'var(--sev-high-border)' }
}
