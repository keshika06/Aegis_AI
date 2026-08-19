// Visual attack path: eight phases, drawn as a flow the eye can follow.
//
// The colour of each *connector* is the point of the diagram — it shows whether
// the attack was still travelling after that phase. A red edge leaving a phase
// means nothing stopped it there; a green node means a defence held.

const W = 150      // node width
const H = 82       // node height
const GAP = 52     // horizontal gap between nodes
const ROW_GAP = 60 // vertical gap between the two rows
const PAD = 20

const STATUS = {
  failed: { stroke: '#ef4444', fill: '#2a1518', text: '#ef4444', label: 'BREACHED' },
  ok: { stroke: '#22c55e', fill: '#12301d', text: '#22c55e', label: 'HELD' },
  info: { stroke: '#3f4a63', fill: '#161d2e', text: '#8b97b0', label: 'OBSERVED' }
}

function wrap(text, max = 15) {
  const words = String(text).split(' ')
  const lines = []
  let line = ''
  words.forEach((w) => {
    if ((line + ' ' + w).trim().length > max) {
      if (line) lines.push(line.trim())
      line = w
    } else {
      line = (line + ' ' + w).trim()
    }
  })
  if (line) lines.push(line)
  return lines.slice(0, 2)
}

export default function AttackFlowGraph({ phases, onSelect, selected }) {
  if (!phases?.length) return null

  const perRow = Math.ceil(phases.length / 2)
  const width = PAD * 2 + perRow * W + (perRow - 1) * GAP
  const height = PAD * 2 + H * 2 + ROW_GAP + 34

  const pos = (i) => {
    const row = Math.floor(i / perRow)
    const col = row === 0 ? i % perRow : perRow - 1 - (i % perRow) // serpentine
    return { x: PAD + col * (W + GAP), y: PAD + 24 + row * (H + ROW_GAP), row }
  }

  return (
    <div className="overflow-x-auto">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        style={{ minWidth: Math.min(width, 900), width: '100%', height: 'auto' }}
        role="img"
        aria-label="Attack path across eight phases"
      >
        <defs>
          <marker id="arrowRed" markerWidth="9" markerHeight="9" refX="7" refY="3"
                  orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L8,3 z" fill="#ef4444" />
          </marker>
          <marker id="arrowGrey" markerWidth="9" markerHeight="9" refX="7" refY="3"
                  orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L8,3 z" fill="#3f4a63" />
          </marker>
          <filter id="glow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="4" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        <text x={PAD} y={14} fill="#5b6579" fontSize="10" fontFamily="ui-monospace, monospace"
              letterSpacing="1.4">
          ATTACK PATH — colour of each arrow shows whether the attack was still travelling
        </text>

        {/* Connectors first so nodes draw on top */}
        {phases.slice(0, -1).map((p, i) => {
          const a = pos(i)
          const b = pos(i + 1)
          // The attack continued past this phase unless a defence held here.
          const stopped = p.status === 'ok'
          const stroke = stopped ? '#3f4a63' : '#ef4444'
          const marker = stopped ? 'url(#arrowGrey)' : 'url(#arrowRed)'

          if (a.row === b.row) {
            const x1 = a.x + W
            const x2 = b.x
            const y = a.y + H / 2
            const dir = x2 > x1 ? 1 : -1
            return (
              <line key={i} x1={x1 + 2 * dir} y1={y} x2={x2 - 6 * dir} y2={y}
                    stroke={stroke} strokeWidth="2" markerEnd={marker}
                    strokeDasharray={stopped ? '5 4' : undefined} />
            )
          }
          // Row change: drop down the outer edge.
          const onLeft = a.x < W
          const edgeX = onLeft ? a.x + W / 2 : a.x + W / 2
          const path = `M ${edgeX} ${a.y + H} L ${edgeX} ${b.y - 14} L ${b.x + W / 2} ${b.y - 14} L ${b.x + W / 2} ${b.y - 6}`
          return (
            <path key={i} d={path} fill="none" stroke={stroke} strokeWidth="2"
                  markerEnd={marker} strokeDasharray={stopped ? '5 4' : undefined} />
          )
        })}

        {phases.map((p, i) => {
          const { x, y } = pos(i)
          const s = STATUS[p.status] ?? STATUS.info
          const isSel = selected === p.n
          const lines = wrap(p.name)

          return (
            <g key={p.n} onClick={() => onSelect?.(p.n)} style={{ cursor: onSelect ? 'pointer' : 'default' }}>
              <rect
                x={x} y={y} width={W} height={H} rx="10"
                fill={s.fill} stroke={isSel ? '#7c5cff' : s.stroke}
                strokeWidth={isSel ? 2.5 : 1.6}
                filter={p.status === 'failed' ? 'url(#glow)' : undefined}
                opacity={p.status === 'failed' ? 1 : 0.95}
              />

              {/* phase number badge */}
              <circle cx={x + 17} cy={y + 17} r="10.5" fill={s.stroke} opacity="0.22" />
              <text x={x + 17} y={y + 21} textAnchor="middle" fill={s.text}
                    fontSize="11" fontWeight="700" fontFamily="ui-monospace, monospace">
                {p.n}
              </text>

              {lines.map((ln, k) => (
                <text key={k} x={x + 34} y={y + 16 + k * 13} fill="#e2e8f0"
                      fontSize="11.5" fontWeight="600">
                  {ln}
                </text>
              ))}

              <text x={x + 12} y={y + H - 26} fill={s.text} fontSize="9"
                    fontWeight="700" fontFamily="ui-monospace, monospace" letterSpacing="0.8">
                {s.label}
              </text>
              <text x={x + 12} y={y + H - 11} fill="#8b97b0" fontSize="9.5">
                {String(p.headline).slice(0, 24)}{String(p.headline).length > 24 ? '…' : ''}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
