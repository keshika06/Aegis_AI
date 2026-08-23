# AegisAI — Stage 10: Reporting & Dashboard

Frontend for the AI Application Security Validation Platform — Stage 10
(Reporting & Dashboard). Dark, enterprise, red-team/SOC-style UI covering the
full unified investigation workflow:

Overview → Dashboard → Attack Chain → Findings → OWASP Mapping → Risk Analysis
→ Risk Attribution → Evidence → Target Controls → Trends → **Report Generator**

## Stack

- React 18 + Vite
- React Router (HashRouter, so it also works as a static build with no server config)
- Tailwind CSS (custom dark cybersecurity design tokens in `tailwind.config.js`)
- Recharts (risk-score trend, severity donuts, factor bars, control outcomes, risk matrix)
- lucide-react (icons)
- Vitest + Testing Library (page render tests)

## Run locally

```bash
npm install
npm run dev
```

Then open the printed local URL (default http://localhost:5173).

## Build

```bash
npm run build
npm run preview
```

## Pages

| Route | Page |
|---|---|
| `/` | Overview |
| `/dashboard` | Security Command Center |
| `/attack-chain` | Attack Chain Explorer |
| `/findings` | Findings Explorer |
| `/findings/:id` | Finding Detail / Investigation |
| `/owasp-mapping` | OWASP AI Security Risk Mapping (heatmap) |
| `/risk-analysis` | Risk Analysis (gauge, factors, impact/likelihood matrix) |
| `/explainability` | Risk Attribution |
| `/evidence` | Evidence Explorer |
| `/security-controls` | Target Control Evaluation |
| `/trends` | Security Trends & Regression |
| `/reports` | Report Center + Report Builder |
| `/reports/preview` | Generated Report Preview (Export HTML / PDF / JSON) |

## Report generator

`/reports` builds the report; `/reports/preview` renders it. The builder's four
controls all reach the document:

- **Report type** (Executive, Technical, OWASP, Attack Chain, Evidence) seeds
  the section checkboxes. It is a starting selection, not a separate document —
  tweak the checkboxes from there.
- **Sections** decide what the report contains. Cover, assessment scope,
  findings and conclusion are not offered as toggles: a report that omits what
  was tested or what was found is not a shorter report. Surviving sections are
  numbered 1..n, so switching one off does not leave a gap in the numbering.
- **Severity filter** selects which *findings* the report covers; the findings
  table, OWASP rows and evidence follow it. Scan-level sections (risk score,
  control evaluation, regression) describe the whole scan and are left alone,
  because narrowing them would misreport what the scan did.
- **OWASP scope** limits the mapping to affected categories.

Whenever a filter is active the report carries a banner saying so, and an empty
findings table says why it is empty. A security document that silently omits
findings is the one failure mode worth engineering against.

The selection travels as query parameters (`?type=…&sections=…&severity=…`), so
a generated report survives a reload and can be shared as a link. Opening
`/reports/preview` with no parameters yields the full report.

The section catalogue lives in `src/data/reportSections.js` and is imported by
both pages, so a section cannot exist in the builder without existing in the
document.

From the preview you can:

- **Export HTML** — downloads a standalone `.html` snapshot of the report
- **Export PDF** — opens the browser print dialog (Save as PDF)
- **Export JSON** — downloads the underlying structured report data, filtered
  the same way the page is, so the file matches the report you were looking at

## Tests

```bash
npm test          # once
npm run test:watch
```

Vitest and Testing Library render every page against the committed
`scanData.json`. The assertions are derived from that same data rather than
hardcoded, so re-exporting a scan does not break them, while a dropped prop, a
renamed key or a page reading data it does not have still fails. That is not
hypothetical: the risk-score card passed `trend`/`trendUp` to a `KpiCard` that
reads `delta`/`deltaSuffix`, so the change against the previous run was silently
dropped and nothing caught it.

## Data

Every page reads `src/data/scanData.js`, which re-exports `scanData.json` —
written by `aegisai dashboard export <scan-id>` from a real scan in the local
database.

**There is no mock or demo fixture.** If a value is not in the scan, the page
shows an empty state rather than a plausible-looking placeholder: no invented
run history, no illustrative attack chain, no named controls the scanner never
observed. A security dashboard that invents numbers is worse than one that
admits it has none.

Two consequences are worth knowing before reading a page:

- **A single scan is not a trend.** Trend charts render only when the target has
  more than one recorded scan; otherwise the page says so. Deltas against a
  previous run are omitted entirely when there is no previous run.
- **Unmeasured is not zero.** A risk factor the scan could not establish is
  labelled as such and excluded from the weighting, rather than counted as
  "no risk".

To refresh what the dashboard shows:

```bash
aegisai dashboard export <scan-id>     # rewrites src/data/scanData.json
```

The topbar shows which scan is loaded, and flags it as **stale** when a newer
scan exists in the database than the one exported here.

## Reading the risk numbers

The scanner scores `risk = likelihood × impact`, scaled by how far the evidence
can be trusted — not one flat average over every factor. Three factors feed each
axis, and the pages label which axis a factor belongs to, because a reader
comparing a factor against the wrong axis would draw the wrong conclusion about
what to fix.

The headline number on Overview and Dashboard is a **risk score**: 70% the
worst objective plus 30% the mean across all objectives, so one severe finding
dominates without pinning the number, and remediation actually moves it.

## Customizing the look

Severity colors, background/panel colors, and the brand accent are defined
as Tailwind tokens in `tailwind.config.js` under `theme.extend.colors` (`sev.*`,
`base.*`, `brand.*`). Update them there to keep every page consistent.
