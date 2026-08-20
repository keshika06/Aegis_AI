// Defence-in-depth view: concentric layers the attack had to pass to reach impact.
import { useTokens } from '../theme'
//
// Reads at a glance in a way a table does not — a breached layer is drawn broken,
// so the number of gaps between the attacker and the asset is the message.


const LAYERS = [
  { phase: 3, name: 'Input control', short: 'Filter / moderation' },
  { phase: 4, name: 'Model refusal', short: 'Alignment' },
  { phase: 5, name: 'Action authorization', short: 'Tool policy' },
  { phase: 6, name: 'Behaviour policy', short: 'Declared contract' }
]

const SIZE = 300
const CENTER = SIZE / 2

export default function DefenceLayers({ phases }) {
  const t = useTokens()
  const byPhase = Object.fromEntries((phases ?? []).map((p) => [p.n, p]))
  const breached = LAYERS.filter((l) => byPhase[l.phase]?.status === 'failed').length
  // The centre must not claim the asset was reached when a layer held. Phase 7
  // is where deterministic proof is recorded, so it is what decides this.
  const reached = byPhase[7]?.status === 'failed'
  const assetColour = reached ? t.critical : t.rail

  return (
    <div className="flex flex-col items-center">
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} style={{ width: '100%', maxWidth: 300, height: 'auto' }}
           role="img" aria-label="Defence layers and which were breached">
        <defs>
          <marker id="arrowRedLayer" markerWidth="9" markerHeight="9" refX="7" refY="3"
                  orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L8,3 z" fill={t.critical} />
          </marker>
          <filter id="breachGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {LAYERS.map((layer, i) => {
          const r = 132 - i * 26
          const status = byPhase[layer.phase]?.status
          const isBreached = status === 'failed'
          const held = status === 'ok'
          const colour = isBreached ? t.critical : held ? t.low : t.rail

          return (
            <g key={layer.phase}>
              <circle
                cx={CENTER} cy={CENTER} r={r}
                fill="none" stroke={colour} strokeWidth={isBreached ? 2.5 : 1.8}
                // A breached layer is drawn as a broken ring — the gap is the point.
                strokeDasharray={isBreached ? '14 10' : held ? undefined : '3 5'}
                opacity={isBreached ? 1 : 0.85}
                filter={isBreached ? 'url(#breachGlow)' : undefined}
              />
              <text
                x={CENTER} y={CENTER - r + 13} textAnchor="middle"
                fill={colour} fontSize="8.5" fontWeight="700"
                fontFamily="ui-monospace, monospace" letterSpacing="0.5"
              >
                {layer.name.toUpperCase()}
              </text>
            </g>
          )
        })}

        {/* The asset at the centre */}
        <circle cx={CENTER} cy={CENTER} r="28" fill={reached ? 'var(--sev-critical-bg)' : 'var(--sev-neutral-bg)'}
                stroke={assetColour} strokeWidth="2" />
        <text x={CENTER} y={CENTER - 2} textAnchor="middle" fill={assetColour}
              fontSize="9.5" fontWeight="700">ASSET</text>
        <text x={CENTER} y={CENTER + 10} textAnchor="middle" fill={t.axis} fontSize="8">
          {reached ? 'reached' : 'not proven'}
        </text>

        {/* Attack vector punching in from the edge */}
        <line x1="6" y1={CENTER} x2={CENTER - 30} y2={CENTER}
              stroke={assetColour} strokeWidth="2.5"
              markerEnd={reached ? 'url(#arrowRedLayer)' : undefined} />
        <text x="6" y={CENTER - 9} fill={assetColour} fontSize="9"
              fontWeight="700" fontFamily="ui-monospace, monospace">ATTACK</text>
      </svg>

      <div className="text-center mt-3">
        <div className="text-[13px] text-content">
          <span className="font-bold text-sev-critical">{breached}</span> of {LAYERS.length} defence
          layers breached
        </div>
        <div className="text-[11px] text-content-dim mt-0.5">
          {breached === LAYERS.length
            ? 'Nothing stood between the probe and the asset.'
            : reached
            ? `${LAYERS.length - breached} layer(s) held, but the attack still reached impact.`
            : `${LAYERS.length - breached} layer(s) held, and no deterministic proof of impact was collected.`}
        </div>
      </div>
    </div>
  )
}
