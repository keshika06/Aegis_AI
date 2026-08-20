
import { useTokens } from '../theme'
function bandColor(score, t) {
  if (score >= 80) return t.critical
  if (score >= 60) return t.high
  if (score >= 35) return t.medium
  return t.low
}

export default function RiskGauge({ score, label, size = 200 }) {
  const t = useTokens()
  const angle = (score / 100) * 180
  const r = size / 2 - 14
  const cx = size / 2
  const cy = size / 2
  const polar = (deg) => {
    const rad = (Math.PI * (180 - deg)) / 180
    return [cx + r * Math.cos(rad), cy - r * Math.sin(rad)]
  }
  const [x1, y1] = polar(0)
  const [x2, y2] = polar(angle)
  const bands = [
    { from: 0, to: 35, color: t.low },
    { from: 35, to: 60, color: t.medium },
    { from: 60, to: 80, color: t.high },
    { from: 80, to: 100, color: t.critical }
  ]
  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size / 1.75} viewBox={`0 0 ${size} ${size / 1.75}`}>
        {bands.map((b, i) => {
          const [bx1, by1] = polar((b.from / 100) * 180)
          const [bx2, by2] = polar((b.to / 100) * 180)
          const large = b.to - b.from > 50 ? 1 : 0
          return (
            <path
              key={i}
              d={`M ${bx1} ${by1} A ${r} ${r} 0 ${large} 1 ${bx2} ${by2}`}
              stroke={b.color}
              strokeWidth="14"
              fill="none"
              strokeLinecap="butt"
              opacity="0.35"
            />
          )
        })}
        <path
          d={`M ${x1} ${y1} A ${r} ${r} 0 ${angle > 180 ? 1 : 0} 1 ${x2} ${y2}`}
          stroke={bandColor(score, t)}
          strokeWidth="14"
          fill="none"
          strokeLinecap="round"
        />
        <line
          x1={cx}
          y1={cy}
          x2={polar(angle)[0]}
          y2={polar(angle)[1]}
          stroke={t.needle}
          strokeWidth="2"
        />
        <circle cx={cx} cy={cy} r="4" fill={t.needle} />
      </svg>
      <div className="text-center -mt-2">
        <div className="text-4xl font-extrabold" style={{ color: bandColor(score, t) }}>
          {score}<span className="text-lg text-content-dim">/100</span>
        </div>
        {label && <div className="text-xs font-bold uppercase tracking-wide text-content-muted mt-1">{label}</div>}
      </div>
    </div>
  )
}
