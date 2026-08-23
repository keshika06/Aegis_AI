// Smoke-render every page against the real exported scan.
//
// These assert *wiring*, not numbers: each expectation is derived from the same
// scanData the page imports, so a re-export cannot break them, while a dropped
// prop, a renamed key or a page that reads data it does not have still fails.

import { describe, it, expect } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderPage } from './render'

import Dashboard from '../pages/Dashboard'
import AttackChain from '../pages/AttackChain'
import Findings from '../pages/Findings'
import FindingDetail from '../pages/FindingDetail'
import OwaspMapping from '../pages/OwaspMapping'
import Explainability from '../pages/Explainability'
import Evidence from '../pages/Evidence'
import SecurityControls from '../pages/SecurityControls'
import Trends from '../pages/Trends'
import Reports from '../pages/Reports'
import ReportPreview from '../pages/ReportPreview'

import { run, findings } from '../data/scanData'

const PAGES = [
  ['Dashboard', <Dashboard />, {}],
  ['AttackChain', <AttackChain />, {}],
  ['Findings', <Findings />, {}],
  ['OwaspMapping', <OwaspMapping />, {}],
  ['Explainability', <Explainability />, {}],
  ['Evidence', <Evidence />, {}],
  ['SecurityControls', <SecurityControls />, {}],
  ['Trends', <Trends />, {}],
  ['Reports', <Reports />, {}],
  ['ReportPreview', <ReportPreview />, {}],
  ['FindingDetail', <FindingDetail />, { path: `/findings/${findings[0].id}`, route: '/findings/:id' }]
]

describe('every page renders against the exported scan', () => {
  it.each(PAGES)('%s mounts without throwing', (_name, ui, opts) => {
    const { container } = renderPage(ui, opts)
    expect(container.textContent.length).toBeGreaterThan(0)
  })
})

describe('Dashboard headline', () => {
  it('shows the risk score from the scan, not a hardcoded one', () => {
    renderPage(<Dashboard />)
    const card = screen.getByText('Risk Score').closest('.card')
    expect(card).toHaveTextContent(`${run.risk}/100`)
    expect(card).toHaveTextContent(run.severity)
  })

  it('renders the change against the previous run', () => {
    // Regression: the card passed `trend`/`trendUp`, which KpiCard does not
    // read, so the delta was silently dropped and the card showed no change.
    renderPage(<Dashboard />)
    const card = screen.getByText('Risk Score').closest('.card')

    if (run.previousRisk === null || run.previousRisk === undefined) {
      expect(card.textContent).not.toMatch(/[↑↓]/)
      return
    }
    const delta = run.risk - run.previousRisk
    if (delta === 0) {
      expect(card).toHaveTextContent('no change')
    } else {
      expect(card).toHaveTextContent(new RegExp(`${delta > 0 ? '↑' : '↓'}\\s*${Math.abs(delta)}`))
    }
  })

  it('renders the attack success rate delta', () => {
    renderPage(<Dashboard />)
    const card = screen.getByText('Attack Success Rate').closest('.card')
    const d = run.attackSuccessDelta

    if (d === null || d === undefined) {
      expect(card.textContent).not.toMatch(/[↑↓]/)
    } else if (d === 0) {
      expect(card).toHaveTextContent('no change')
    } else {
      expect(card).toHaveTextContent(new RegExp(`${d > 0 ? '↑' : '↓'}\\s*${Math.abs(d)}%`))
    }
  })

  it('lists the highest-scoring findings, worst first', () => {
    renderPage(<Dashboard />)
    const expected = [...findings].sort((a, b) => b.risk - a.risk).slice(0, 8)
    const table = screen.getByText('Top Security Findings').closest('.card')
    for (const f of expected) {
      expect(within(table).getByText(f.id)).toBeInTheDocument()
    }
  })
})

describe('no page still calls the score a posture score', () => {
  it.each(PAGES)('%s', (_name, ui, opts) => {
    const { container } = renderPage(ui, opts)
    expect(container.textContent).not.toMatch(/posture/i)
  })
})
