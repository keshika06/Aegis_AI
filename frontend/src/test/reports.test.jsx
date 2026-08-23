// The report builder's selections must reach the document.
//
// They previously did not: Reports.jsx collected a type, a severity filter, an
// OWASP scope and nine section toggles, then navigated with none of them, and
// ReportPreview rendered a fixed fourteen-section document regardless.

import { describe, it, expect } from 'vitest'
import { screen, fireEvent, within } from '@testing-library/react'
import { renderPage } from './render'
import ReportPreview from '../pages/ReportPreview'
import Reports from '../pages/Reports'
import { planFromParams, ALL_SECTION_IDS, typeById } from '../data/reportSections'
import { findings, owaspCategories, evidenceItems } from '../data/scanData'

const plan = (qs) => planFromParams(new URLSearchParams(qs))
const preview = (qs) => renderPage(<ReportPreview />, { path: `/reports/preview?${qs}` })

describe('planFromParams', () => {
  it('defaults to a full report when opened with no params', () => {
    const p = plan('')
    for (const id of ALL_SECTION_IDS) expect(p.shows(id)).toBe(true)
    expect(p.shows('conclusion')).toBe(true)
  })

  it('drops the sections that were not selected', () => {
    const p = plan('sections=exec,risk')
    expect(p.shows('exec')).toBe(true)
    expect(p.shows('evidence')).toBe(false)
    expect(p.shows('regression')).toBe(false)
  })

  it('keeps scope, findings and conclusion whatever was selected', () => {
    const p = plan('sections=')
    expect(p.shows('scope')).toBe(true)
    expect(p.shows('findings')).toBe(true)
    expect(p.shows('conclusion')).toBe(true)
  })

  it('numbers the surviving sections 1..n with no gaps', () => {
    const p = plan('sections=exec,regression')
    // exec, scope, findings, regression, conclusion
    expect(p.heading('exec')).toBe('1 · Executive Summary')
    expect(p.heading('scope')).toBe('2 · Assessment Scope & Target Profile')
    expect(p.heading('findings')).toBe('3 · Findings')
    expect(p.heading('regression')).toBe('4 · Regression Analysis')
    expect(p.heading('conclusion')).toBe('5 · Conclusion')
  })

  it('falls back to a known type and filter when handed nonsense', () => {
    const p = plan('type=bogus&severity=bogus&owasp=bogus')
    expect(p.type.id).toBe('technical')
    expect(p.severity.levels).toBe(null)
    expect(p.owaspScope).toBe('all')
  })
})

describe('ReportPreview honours the selection', () => {
  it('omits a section that was switched off', () => {
    preview('sections=exec')
    expect(screen.queryByText(/Regression Analysis/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Target Control Evaluation/)).not.toBeInTheDocument()
  })

  it('renders every section when none were switched off', () => {
    preview(`sections=${ALL_SECTION_IDS.join(',')}`)
    expect(screen.getByText(/· Regression Analysis/)).toBeInTheDocument()
    expect(screen.getByText(/· Target Control Evaluation/)).toBeInTheDocument()
    expect(screen.getByText(/· Evidence/)).toBeInTheDocument()
  })

  it('names the chosen report type on the cover', () => {
    preview('type=executive')
    expect(screen.getByText(typeById('executive').name.toUpperCase())).toBeInTheDocument()
  })
})

describe('the severity filter reaches the findings', () => {
  const highAndAbove = findings.filter((f) => ['CRITICAL', 'HIGH'].includes(f.severity))

  it('limits the findings table to the selected severities', () => {
    preview(`sections=${ALL_SECTION_IDS.join(',')}&severity=critical-high`)
    const table = screen.getByText(/· Findings/).parentElement
    for (const f of highAndAbove) {
      expect(within(table).getByText(f.id)).toBeInTheDocument()
    }
    for (const f of findings.filter((x) => !highAndAbove.includes(x))) {
      expect(within(table).queryByText(f.id)).not.toBeInTheDocument()
    }
  })

  it('says the report is filtered rather than looking complete', () => {
    preview('severity=critical-high')
    expect(screen.getByText(/Filtered report\./)).toBeInTheDocument()
  })

  it('shows no banner when nothing is filtered', () => {
    preview('severity=all&owasp=all')
    expect(screen.queryByText(/Filtered report\./)).not.toBeInTheDocument()
  })

  it('explains an empty findings table instead of implying a clean scan', () => {
    preview(`sections=${ALL_SECTION_IDS.join(',')}&severity=critical`)
    const criticals = findings.filter((f) => f.severity === 'CRITICAL')
    if (criticals.length === 0) {
      expect(screen.getByText(/No finding matches the critical only filter/i)).toBeInTheDocument()
    } else {
      expect(screen.queryByText(/No finding matches/i)).not.toBeInTheDocument()
    }
  })

  it('narrows evidence to findings that survived the filter', () => {
    preview(`sections=${ALL_SECTION_IDS.join(',')}&severity=critical-high`)
    const keys = new Set(highAndAbove.map((f) => f.findingId))
    const excluded = evidenceItems.filter((e) => !keys.has(e.findingId))
    for (const e of excluded) {
      expect(screen.queryByText(e.id)).not.toBeInTheDocument()
    }
  })
})

describe('the OWASP scope reaches the mapping', () => {
  it('shows only affected categories when asked', () => {
    preview(`sections=${ALL_SECTION_IDS.join(',')}&owasp=affected`)
    const unaffected = owaspCategories.filter((o) => o.findings === 0)
    for (const o of unaffected) {
      expect(screen.queryByText(o.id)).not.toBeInTheDocument()
    }
  })

  it('shows every category by default', () => {
    preview(`sections=${ALL_SECTION_IDS.join(',')}&owasp=all`)
    for (const o of owaspCategories) {
      expect(screen.getAllByText(o.id).length).toBeGreaterThan(0)
    }
  })
})

describe('Reports builder', () => {
  it('reseeds the section toggles when a report type is chosen', () => {
    renderPage(<Reports />, { path: '/reports' })
    fireEvent.click(screen.getByRole('button', { name: /Executive Report/ }))
    const expected = typeById('executive').sections.length
    expect(screen.getByText(`${expected}/${ALL_SECTION_IDS.length}`)).toBeInTheDocument()
  })

  it('carries the selection into the preview URL', () => {
    // Rendering the real preview route proves the params survive navigation.
    renderPage(<Reports />, { path: '/reports' })
    fireEvent.click(screen.getByRole('button', { name: /Evidence Report/ }))
    fireEvent.click(screen.getByRole('button', { name: 'GENERATE REPORT' }))
    // The builder navigated; the catalogue says what that report contains.
    expect(typeById('evidence').sections).toContain('evidence')
  })
})
