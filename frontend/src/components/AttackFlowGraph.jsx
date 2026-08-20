// Visual attack path: eight phases drawn as a flow the eye can follow.
import { useTokens } from '../theme'
//
// Two decisions carry the meaning:
//   * Both rows read left-to-right. A serpentine layout doubles back, which
//     makes a *sequence* diagram momentarily unreadable.
//   * The colour of each connector says whether the attack was still travelling
//     after that phase — that, not the node colour, is the story.


const W = 168
const H = 92
const GAP = 34
const ROW_GAP = 56
const PAD_X = 14
const PAD_TOP = 10

const statusFor = (t) => ({
  failed: { stroke: t.critical, fill: 'var(--sev-critical-bg)', accent: t.critical, label: 'BREACHED' },
  ok: { stroke: t.low, fill: 'var(--sev-low-bg)', accent: t.low, label: 'HELD' },
  info: { stroke: t.rail, fill: 'var(--sev-neutral-bg)', accent: 'var(--text-muted)', label: 'OBSERVED' }
})

function clamp(text, max) {
  const t = String(text ?? '')
  return t.length > max ? `${t.slice(0, max - 1)}…` : t
}

export default function AttackFlowGraph({ phases, onSelect, selected }) {
  const t = useTokens()
  const STATUS = statusFor(t)
  if (!phases?.length) return null

  const perRow = Math.ceil(phases.length / 2)
  const width = PAD_X * 2 + perRow * W + (perRow - 1) * GAP
  const height = PAD_TOP + H * 2 + ROW_GAP + 14

  const pos = (i) => {
    const row = Math.floor(i / perRow)
    const col = i % perRow
    return { x: PAD_X + col * (W + GAP), y: PAD_TOP + row * (H + ROW_GAP), row }
  }

  return (
    <div className="overflow-x-auto -mx-1 px-1">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        style={{ minWidth: 720, width: '100%', height: 'auto' }}
        role="img"
        aria-label={`Attack path across ${phases.length} phases`}
      >
        <defs>
          <marker id="afgRed" markerWidth="10" markerHeight="10" refX="8" refY="3.2"
                  orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6.4 L9,3.2 z" fill={t.critical} />
          </marker>
          <marker id="afgGrey" markerWidth="10" markerHeight="10" refX="8" refY="3.2"
                  orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6.4 L9,3.2 z" fill={t.rail} />
          </marker>
          <filter id="afgGlow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="3" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {phases.slice(0, -1).map((p, i) => {
          const a = pos(i)
          const b = pos(i + 1)
          const stopped = p.status === 'ok'
          const stroke = stopped ? t.rail : t.critical
          const marker = stopped ? 'url(#afgGrey)' : 'url(#afgRed)'
          const dash = stopped ? '6 5' : undefined

          if (a.row === b.row) {
            const y = a.y + H / 2
            return (
              <line key={i} x1={a.x + W + 3} y1={y} x2={b.x - 5} y2={y}
                    stroke={stroke} strokeWidth="2.2" markerEnd={marker} strokeDasharray={dash} />
            )
          }
          // Wrap from the end of row 1 back to the start of row 2, routed under
          // the first row so it never crosses a node.
          const startX = a.x + W / 2
          const midY = a.y + H + ROW_GAP / 2
          const endX = b.x + W / 2
          return (
            <path
              key={i}
              d={`M ${startX} ${a.y + H + 3} L ${startX} ${midY} L ${endX} ${midY} L ${endX} ${b.y - 6}`}
              fill="none" stroke={stroke} strokeWidth="2.2"
              markerEnd={marker} strokeDasharray={dash}
            />
          )
        })}

        {phases.map((p, i) => {
          const { x, y } = pos(i)
          const s = STATUS[p.status] ?? STATUS.info
          const isSel = selected === p.n
          const isBreach = p.status === 'failed'

          return (
            <g key={p.n} onClick={() => onSelect?.(p.n)}
               style={{ cursor: onSelect ? 'pointer' : 'default' }}>
              <rect
                x={x} y={y} width={W} height={H} rx="12"
                fill={s.fill}
                stroke={isSel ? t.brand : s.stroke}
                strokeWidth={isSel ? 2.4 : 1.5}
                opacity={isBreach ? 1 : 0.96}
              />

              {/* A thin severity rail rather than an all-over glow: the card stays
                  readable and the eye still finds the breaches. */}
              <rect x={x} y={y} width="3.5" height={H} rx="2" fill={s.stroke}
                    filter={isBreach ? 'url(#afgGlow)' : undefined} />

              <circle cx={x + 24} cy={y + 22} r="11" fill={s.stroke} opacity="0.18" />
              <text x={x + 24} y={y + 26} textAnchor="middle" fill={s.accent}
                    fontSize="11" fontWeight="700" fontFamily="ui-monospace, monospace">
                {p.n}
              </text>

              <text x={x + 42} y={y + 26} fill={t.needle} fontSize="12.5" fontWeight="700">
                {clamp(p.name, 20)}
              </text>

              <text x={x + 14} y={y + 50} fill={s.accent} fontSize="9"
                    fontWeight="700" fontFamily="ui-monospace, monospace" letterSpacing="0.9">
                {s.label}
              </text>

              <text x={x + 14} y={y + 68} fill={t.axis} fontSize="10.5">
                {clamp(p.headline, 26)}
              </text>
              <text x={x + 14} y={y + 82} fill={t.axis} fontSize="9.5">
                {clamp(p.detail, 30)}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
