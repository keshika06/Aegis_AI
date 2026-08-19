# AegisAI — Stage 10: Reporting & Dashboard

Frontend for the AI Application Security Validation Platform — Stage 10
(Reporting & Dashboard). Dark, enterprise, red-team/SOC-style UI covering the
full unified investigation workflow:

Dashboard → Findings → OWASP Mapping → Attack Chain → Evidence → Risk Scoring
→ SHAP Explainability → Security Controls → Trends → **Report Generator**

## Stack

- React 18 + Vite
- React Router (HashRouter, so it also works as a static build with no server config)
- Tailwind CSS (custom dark cybersecurity design tokens in `tailwind.config.js`)
- Recharts (all charts: risk trend, donuts, SHAP waterfall, control effectiveness, risk matrix)
- lucide-react (icons)

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
| `/risk-analysis` | Risk Analysis (gauge, components, matrix) |
| `/explainability` | AI Risk Explainability (SHAP waterfall) |
| `/evidence` | Evidence Explorer |
| `/security-controls` | Security Control Effectiveness |
| `/trends` | Security Trends & Regression |
| `/reports` | Report Center + Report Builder |
| `/reports/preview` | Generated Report Preview (Export HTML / PDF / JSON) |

## Report generator

`/reports` lets you pick a report type (Executive, Technical, OWASP, Attack
Chain, Evidence), choose which sections to include, and click **Generate
Report**, which routes to `/reports/preview` — a print-optimized, light-theme,
structured security assessment report (cover, executive summary, scope,
findings, OWASP mapping, attack chain, evidence, SHAP explainability, control
effectiveness, recommendations, regression analysis, conclusion). From there
you can:

- **Export HTML** — downloads a standalone `.html` snapshot of the report
- **Export PDF** — opens the browser print dialog (Save as PDF)
- **Export JSON** — downloads the underlying structured report data

## Data

All demo data lives in `src/data/mockData.js` — a single, internally
consistent source of truth (RUN-042, 18 findings, OWASP LLM Top 10 mapping,
attack chain nodes, SHAP features, security controls, evidence, trend history
across RUN-038…RUN-042) so every page — dashboard KPIs, findings table, OWASP
heatmap, attack chain, risk scoring, SHAP explainability, evidence, and the
generated report — stays cross-referenced and connected, matching the "one
unified investigation workflow" requirement.

## Customizing the look

Severity colors, background/panel colors, and the brand accent are defined
as Tailwind tokens in `tailwind.config.js` under `theme.extend.colors` (`sev.*`,
`base.*`, `brand.*`). Update them there to keep every page consistent.
