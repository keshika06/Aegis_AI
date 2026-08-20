import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, ShieldOff, ShieldCheck, Shield, AlertTriangle } from 'lucide-react'
import { PageHeader, Panel } from '../components/Panel'
import { evidenceItems } from '../data/scanData'
import { useTokens } from '../theme'

// Filters are derived from the evidence actually present, so a tab can never
// show an empty list — the previous fixed list matched types this scanner does
// not produce, leaving every filter but "All" dead.
const LABELS = {
  canary: 'Canary',
  policy_violation: 'Policy Violation',
  pii_detection: 'Sensitive Data',
  tool_log: 'Tool Call',
  response_text: 'Response Text'
}

const DEFENCE_ICON = {
  ACCEPTED_BY_TARGET_CONTROL: ShieldOff,
  REFUSED_BY_TARGET_LLM: Shield,
  REJECTED_BY_TARGET_CONTROL: ShieldCheck,
  ERROR_TIMEOUT: AlertTriangle
}

// Keyed lookup rather than a frozen map: the colours have to follow the theme,
// and a module-scope constant is evaluated once before one is chosen.
const DEFENCE_TOKEN = {
  ACCEPTED_BY_TARGET_CONTROL: 'critical',
  REFUSED_BY_TARGET_LLM: 'medium',
  REJECTED_BY_TARGET_CONTROL: 'low',
  ERROR_TIMEOUT: 'neutral'
}

function Field({ label, children, mono = false }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide text-content-dim mb-1">{label}</div>
      <div className={`text-[13px] text-content ${mono ? 'mono break-all' : ''}`}>{children}</div>
    </div>
  )
}

export default function Evidence() {
  const t = useTokens()
  const [filter, setFilter] = useState('all')
  const [expanded, setExpanded] = useState(evidenceItems[0]?.id ?? null)

  const counts = useMemo(() => {
    const c = {}
    evidenceItems.forEach((e) => { c[e.rawType] = (c[e.rawType] || 0) + 1 })
    return c
  }, [])

  const filtered = useMemo(() => {
    if (filter === 'all') return evidenceItems
    if (filter === 'proof') return evidenceItems.filter((e) => e.deterministic)
    return evidenceItems.filter((e) => e.rawType === filter)
  }, [filter])

  const proofCount = evidenceItems.filter((e) => e.deterministic).length

  const tabs = [
    { key: 'all', label: `All (${evidenceItems.length})` },
    { key: 'proof', label: `Deterministic proof (${proofCount})` },
    ...Object.keys(counts).map((k) => ({ key: k, label: `${LABELS[k] ?? k} (${counts[k]})` }))
  ]

  return (
    <div>
      <PageHeader
        title="Evidence Explorer"
        subtitle="What was sent, what the target's defences did about it, and why the result counts as proof."
      />

      <div className="flex items-center gap-2 mb-5 flex-wrap">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setFilter(t.key)}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wide transition-colors ${
              filter === t.key
                ? 'bg-brand text-white'
                : 'bg-base-card text-content-muted hover:text-content border border-base-border'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <Panel title="Evidence Timeline">
        <div className="space-y-2">
          {filtered.length === 0 && (
            <div className="text-sm text-content-dim py-6 text-center">No evidence of this type.</div>
          )}
          {filtered.map((e) => {
            const isOpen = expanded === e.id
            const Icon = DEFENCE_ICON[e.controlVerdict] ?? Shield
            const colour = t[DEFENCE_TOKEN[e.controlVerdict]] ?? t.neutral

            return (
              <div key={e.id} className="border border-base-border rounded-lg overflow-hidden">
                <button
                  onClick={() => setExpanded(isOpen ? null : e.id)}
                  className="w-full flex items-center gap-3 p-3 hover:bg-base-card2 transition-colors text-left"
                >
                  {isOpen ? <ChevronDown size={14} className="text-content-dim shrink-0" />
                          : <ChevronRight size={14} className="text-content-dim shrink-0" />}

                  <span
                    className="text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded shrink-0 w-[104px] text-center"
                    style={
                      e.deterministic
                        ? { background: 'var(--sev-low-bg)', color: t.low, border: `1px solid var(--sev-low-border)` }
                        : { background: 'var(--sev-neutral-bg)', color: 'var(--text-muted)', border: '1px solid #2a3348' }
                    }
                    title={e.deterministic ? 'Deterministic proof' : 'Supporting signal only'}
                  >
                    {e.deterministic ? 'proof' : 'supporting'}
                  </span>

                  <span className="text-xs font-bold text-content border border-base-border rounded px-2 py-0.5 shrink-0 w-[130px] text-center">
                    {e.type}
                  </span>

                  <span className="flex-1 min-w-0">
                    <span className="block text-[13px] text-content truncate">{e.finding}</span>
                    <span className="block mono text-[11px] text-content-dim truncate">
                      {e.prompt ? `"${e.prompt.slice(0, 78)}${e.prompt.length > 78 ? '…' : ''}"` : '—'}
                    </span>
                  </span>

                  <span className="flex items-center gap-1.5 shrink-0 w-[190px]" style={{ color: colour }}>
                    <Icon size={14} />
                    <span className="text-[12px] font-semibold">{e.defenceHeadline}</span>
                  </span>

                  <span className="text-xs font-bold w-12 text-right shrink-0" style={{ color: colour }}>
                    {e.confidence}%
                  </span>
                </button>

                {isOpen && (
                  <div className="px-4 pb-4 pt-3 bg-base-card2/40 border-t border-base-border space-y-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      <Field label="OWASP">{e.owasp ?? '—'}{e.owaspName ? ` · ${e.owaspName}` : ''}</Field>
                      <Field label="Verdict">{e.verdict ?? '—'}</Field>
                      <Field label="Transformation" mono>{e.transformation ?? 'none'}</Field>
                      <Field label="Captured" mono>{e.timestamp}</Field>
                    </div>

                    {/* 1. What was sent */}
                    <div>
                      <div className="text-[11px] uppercase tracking-wide font-bold text-content-muted mb-1.5">
                        1 · The prompt that caused it
                      </div>
                      <pre className="mono text-[12px] text-content bg-base-bg rounded-lg p-3 border border-base-border whitespace-pre-wrap break-words">
{e.prompt ?? 'Not recorded.'}
                      </pre>
                      {e.transformation && e.transformation !== 'none' && (
                        <div className="text-[11px] text-content-dim mt-1.5">
                          Delivered using the <span className="mono text-content">{e.transformation}</span> family
                          — the same objective, expressed differently to test whether the target's controls generalise.
                        </div>
                      )}
                    </div>

                    {/* 2. What the defences did */}
                    <div>
                      <div className="text-[11px] uppercase tracking-wide font-bold text-content-muted mb-1.5">
                        2 · What the target's defences did
                      </div>
                      <div
                        className="rounded-lg p-3 border"
                        style={{ borderColor: `${colour}55`, background: `${colour}12` }}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <Icon size={15} style={{ color: colour }} />
                          <span className="text-[13px] font-bold" style={{ color: colour }}>
                            {e.defenceHeadline}
                          </span>
                          {e.statusCode && (
                            <span className="mono text-[11px] text-content-dim ml-auto">
                              HTTP {e.statusCode}{e.latencyMs ? ` · ${e.latencyMs}ms` : ''}
                            </span>
                          )}
                        </div>
                        <p className="text-[12px] text-content">{e.defenceExplain}</p>
                        {e.controlReason && (
                          <p className="mono text-[11px] text-content-dim mt-1.5">{e.controlReason}</p>
                        )}
                      </div>
                    </div>

                    {/* 3. What came back */}
                    {e.response && (
                      <div>
                        <div className="text-[11px] uppercase tracking-wide font-bold text-content-muted mb-1.5">
                          3 · What the target returned
                        </div>
                        <pre className="mono text-[12px] text-content bg-base-bg rounded-lg p-3 border border-base-border whitespace-pre-wrap break-words max-h-52 overflow-y-auto">
{e.response}
                        </pre>
                      </div>
                    )}

                    {/* 4. Why it is proof */}
                    <div>
                      <div className="text-[11px] uppercase tracking-wide font-bold text-content-muted mb-1.5">
                        4 · Why this counts as {e.deterministic ? 'proof' : 'a signal only'}
                      </div>
                      <p className="text-[12px] text-content">{e.whyItProves}</p>
                      {e.summary && (
                        <p className="mono text-[11px] text-content-dim mt-1.5">{e.summary}</p>
                      )}
                    </div>

                    {/* 5. Boundaries crossed */}
                    {e.boundaries.length > 0 && (
                      <div>
                        <div className="text-[11px] uppercase tracking-wide font-bold text-content-muted mb-1.5">
                          5 · Policy boundaries crossed
                        </div>
                        <div className="space-y-1.5">
                          {e.boundaries.map((b) => (
                            <div key={b.boundary} className="text-[12px] bg-base-bg rounded-lg p-2.5 border border-base-border">
                              <div className="mono text-content font-semibold mb-0.5">{b.boundary}</div>
                              <div className="text-content-dim">expected: {b.expected}</div>
                              <div className="text-sev-critical">observed: {b.observed}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </Panel>

      <Panel title="How to read this" className="mt-5">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border border-sev-low/40 bg-sev-lowBg">
            <div className="text-sev-low font-bold text-sm mb-1">Proof</div>
            <p className="text-[13px] text-content">
              A canary returned, a declared policy boundary crossed, or sensitive data disclosed.
              These are measured, not interpreted, and are what allow a finding to reach CONFIRMED.
            </p>
          </div>
          <div className="p-4 rounded-lg border border-base-border bg-base-card2">
            <div className="text-content font-bold text-sm mb-1">Supporting</div>
            <p className="text-[13px] text-content">
              Response wording that suggests compliance. Useful context, but it can never on its own
              raise a finding above SUSPECTED — that cap is enforced in the scanner, not left to
              judgement.
            </p>
          </div>
        </div>
      </Panel>
    </div>
  )
}
