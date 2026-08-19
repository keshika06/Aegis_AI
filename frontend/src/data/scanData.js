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

// Real decomposition of the risk score. The model is a weighted linear
// combination, so weight x value is genuinely each factor's contribution — not
// an approximation of a model that was never run.
const contributions = scan.factorContributions ?? {}
export const factorContributions = contributions.features ?? []
export const contributionFinal = contributions.final ?? 0
export const unestablishedFactors = contributions.unestablished ?? []

export const severityColor = {
  CRITICAL: { text: '#ef4444', bg: '#3a1518', border: '#5c2026' },
  HIGH: { text: '#f97316', bg: '#3a220f', border: '#5c3517' },
  MEDIUM: { text: '#eab308', bg: '#3a300f', border: '#5c4d17' },
  LOW: { text: '#22c55e', bg: '#12301d', border: '#1c4d2e' },
  INFO: { text: '#3b82f6', bg: '#12213a', border: '#1c355c' },
  NEUTRAL: { text: '#64748b', bg: '#1c2333', border: '#2a3348' },
  CONFIRMED: { text: '#ef4444', bg: '#3a1518', border: '#5c2026' },
  LIKELY: { text: '#eab308', bg: '#3a300f', border: '#5c4d17' },
  SUSPECTED: { text: '#64748b', bg: '#1c2333', border: '#2a3348' },
  OPEN: { text: '#f97316', bg: '#3a220f', border: '#5c3517' },
  CLEAR: { text: '#22c55e', bg: '#12301d', border: '#1c4d2e' },
  RESOLVED: { text: '#22c55e', bg: '#12301d', border: '#1c4d2e' },
  REGRESSED: { text: '#ef4444', bg: '#3a1518', border: '#5c2026' },
  ACTIVE: { text: '#3b82f6', bg: '#12213a', border: '#1c355c' },
  EXHAUSTED: { text: '#f97316', bg: '#3a220f', border: '#5c3517' }
}
