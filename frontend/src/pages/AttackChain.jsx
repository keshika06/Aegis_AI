import { useState } from 'react'
import { ShieldOff, ShieldCheck, Circle, ChevronRight, Zap } from 'lucide-react'
import { PageHeader, Panel } from '../components/Panel'
import AttackFlowGraph from '../components/AttackFlowGraph'
import DefenceLayers from '../components/DefenceLayers'
import { attackChains, attackTimeline } from '../data/scanData'

const STATUS = {
  failed: { color: '#ef4444', bg: '#3a1518', border: '#5c2026', Icon: ShieldOff, word: 'failed' },
  ok: { color: '#22c55e', bg: '#12301d', border: '#1c4d2e', Icon: ShieldCheck, word: 'held' },
  info: { color: '#64748b', bg: '#1c2333', border: '#2a3348', Icon: Circle, word: 'observed' }
}

function Phase({ phase, isLast }) {
  const s = STATUS[phase.status] ?? STATUS.info
  const { Icon } = s

  return (
    <div className="flex gap-4">
      {/* Rail: the connector makes the sequence read as one path, not five cards */}
      <div className="flex flex-col items-center shrink-0">
        <div
          className="w-9 h-9 rounded-full flex items-center justify-center border-2 shrink-0"
          style={{ borderColor: s.color, background: s.bg }}
        >
          <Icon size={16} style={{ color: s.color }} />
        </div>
        {!isLast && <div className="w-0.5 flex-1 min-h-[28px] bg-base-border mt-1" />}
      </div>

      <div className="pb-7 min-w-0 flex-1">
        <div className="flex items-baseline gap-2 flex-wrap mb-1">
          <span className="mono text-[11px] text-slate-500">PHASE {phase.n}</span>
          <span className="text-[15px] font-bold text-slate-100">{phase.name}</span>
          <span
            className="text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded-full"
            style={{ background: s.bg, color: s.color, border: `1px solid ${s.border}` }}
          >
            {s.word}
          </span>
        </div>

        <div className="text-[14px] font-semibold mb-1" style={{ color: s.color }}>
          {phase.headline}
        </div>
        <p className="text-[13px] text-slate-400 max-w-[70ch]">{phase.detail}</p>

        {phase.data?.text && (
          <div className="mt-2.5">
            <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-1">
              {phase.data.label}
            </div>
            <pre className="mono text-[12px] text-slate-200 bg-base-bg rounded-lg p-3 border border-base-border whitespace-pre-wrap break-words max-h-40 overflow-y-auto">
{phase.data.text}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

export default function AttackChain() {
  const [selected, setSelected] = useState(0)
  const [focusPhase, setFocusPhase] = useState(null)
  const chain = attackChains[selected]

  if (!chain) {
    return (
      <div>
        <PageHeader title="Attack Chain Explorer" subtitle="How an objective became a confirmed finding, phase by phase." />
        <Panel><div className="text-sm text-slate-500 py-6 text-center">No attack chains in this scan.</div></Panel>
      </div>
    )
  }

  return (
    <div>
      <PageHeader
        title="Attack Chain Explorer"
        subtitle="How one objective travelled from prompt to proof, and which defence failed at each step."
      />

      {/* Chain selector — several objectives usually reach a finding */}
      {attackChains.length > 1 && (
        <div className="flex items-center gap-2 mb-5 flex-wrap">
          {attackChains.map((c, i) => (
            <button
              key={c.id}
              onClick={() => { setSelected(i); }}
              className={`px-3 py-2 rounded-lg text-left transition-colors border ${
                i === selected
                  ? 'bg-brand text-white border-brand'
                  : 'bg-base-card text-slate-400 hover:text-slate-200 border-base-border'
              }`}
            >
              <div className="text-[12px] font-bold truncate max-w-[220px]">{c.findingTitle}</div>
              <div className={`text-[10px] mono ${i === selected ? 'text-white/70' : 'text-slate-500'}`}>
                {c.failedPhases} phase{c.failedPhases === 1 ? '' : 's'} failed · risk {c.risk}
              </div>
            </button>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-5">
        <Panel title="Attack path" className="xl:col-span-2">
          <AttackFlowGraph
            phases={chain.phases}
            selected={focusPhase}
            onSelect={(n) => {
              setFocusPhase(n)
              document.getElementById(`phase-${n}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
            }}
          />
          <div className="flex items-center gap-4 mt-3 pt-3 border-t border-base-border flex-wrap text-[11px]">
            <span className="flex items-center gap-1.5 text-slate-400">
              <span className="w-3 h-0.5 bg-sev-critical inline-block" /> attack still travelling
            </span>
            <span className="flex items-center gap-1.5 text-slate-400">
              <span className="w-3 h-0.5 inline-block" style={{ background: '#3f4a63' }} /> stopped here
            </span>
            <span className="text-slate-500 ml-auto">click any phase to jump to its detail</span>
          </div>
        </Panel>

        <Panel title="Defence layers">
          <DefenceLayers phases={chain.phases} />
        </Panel>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-5">
        <Panel title="Attack sequence" className="xl:col-span-2">
          <div className="mb-5 p-3 rounded-lg border border-base-border bg-base-card2">
            <div className="text-[13px] font-bold text-slate-100 mb-0.5">{chain.findingTitle}</div>
            <div className="text-[12px] text-slate-400">
              {chain.owasp.join(', ') || 'unmapped'} · {chain.verdict} ·{' '}
              <span className="font-bold" style={{ color: STATUS.failed.color }}>
                {chain.failedPhases} of {chain.phases.length} phases failed
              </span>
            </div>
          </div>

          <div>
            {chain.phases.map((p, i) => (
              <div key={p.n} id={`phase-${p.n}`}>
                <Phase phase={p} isLast={i === chain.phases.length - 1} />
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Where it broke down">
          <p className="text-[13px] text-slate-400 mb-4">
            Each phase is a place something could have stopped this. Green means a defence held;
            red means it should have acted and did not.
          </p>
          <div className="space-y-2">
            {chain.phases.map((p) => {
              const s = STATUS[p.status] ?? STATUS.info
              return (
                <div
                  key={p.n}
                  className="flex items-center gap-2.5 p-2.5 rounded-lg border"
                  style={{ borderColor: `${s.color}44`, background: `${s.color}0f` }}
                >
                  <span className="mono text-[11px] text-slate-500 w-4 shrink-0">{p.n}</span>
                  <span className="text-[13px] text-slate-200 flex-1 min-w-0 truncate">{p.name}</span>
                  <span className="text-[11px] font-bold uppercase shrink-0" style={{ color: s.color }}>
                    {s.word}
                  </span>
                </div>
              )
            })}
          </div>

          <div className="mt-5 pt-4 border-t border-base-border">
            <div className="text-[11px] uppercase tracking-wide text-slate-500 mb-1.5">Remediation</div>
            <p className="text-[13px] text-slate-300">
              {chain.phases.find((p) => p.n === 8)?.detail || 'No mitigation recorded.'}
            </p>
          </div>
        </Panel>
      </div>

      <Panel title="Runtime activity">
        <p className="text-[13px] text-slate-400 mb-4">
          What the application did while the scan ran. Privileged actions are listed first — those
          changed state, rather than only producing text.
        </p>
        <div className="space-y-1.5">
          {attackTimeline.length === 0 && (
            <div className="text-sm text-slate-500 py-4 text-center">
              The target exposed no runtime telemetry for this scan.
            </div>
          )}
          {attackTimeline.slice(0, 25).map((t, i) => (
            <div
              key={i}
              className="flex items-start gap-3 p-2.5 rounded-lg border border-base-border hover:bg-base-card2 transition-colors"
            >
              <span className="mono text-[11px] text-slate-500 shrink-0 w-[70px]">{t.time}</span>
              {t.kind === 'tool_call'
                ? <Zap size={14} className="shrink-0 mt-0.5" style={{ color: t.critical ? '#ef4444' : '#eab308' }} />
                : <Circle size={8} className="shrink-0 mt-1.5 text-slate-600" />}
              <span className="min-w-0 flex-1">
                <span className="block text-[13px] text-slate-200">
                  {t.label}
                  {t.note && <span className="mono text-[11px] text-slate-500 ml-2">{t.note}</span>}
                </span>
                {t.detail && (
                  <span className="block mono text-[11px] text-slate-500 truncate">{t.detail}</span>
                )}
                {t.prompt && (
                  <span className="block mono text-[11px] text-slate-600 truncate mt-0.5">
                    <ChevronRight size={10} className="inline" /> caused by: "{t.prompt}"
                  </span>
                )}
              </span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}
