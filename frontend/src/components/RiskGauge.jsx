function bandColor(score) {
  if (score >= 80) return '#ef4444'
  if (score >= 60) return '#f97316'
  if (score >= 35) return '#eab308'
  return '#22c55e'
}

export default function RiskGauge({ score, label, size = 200 }) {
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
    { from: 0, to: 35, color: '#22c55e' },
    { from: 35, to: 60, color: '#eab308' },
    { from: 60, to: 80, color: '#f97316' },
    { from: 80, to: 100, color: '#ef4444' }
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
          stroke={bandColor(score)}
          strokeWidth="14"
          fill="none"
          strokeLinecap="round"
        />
        <line
          x1={cx}
          y1={cy}
          x2={polar(angle)[0]}
          y2={polar(angle)[1]}
          stroke="#e6e9f0"
          strokeWidth="2"
        />
        <circle cx={cx} cy={cy} r="4" fill="#e6e9f0" />
      </svg>
      <div className="text-center -mt-2">
        <div className="text-4xl font-extrabold" style={{ color: bandColor(score) }}>
          {score}<span className="text-lg text-slate-500">/100</span>
        </div>
        {label && <div className="text-xs font-bold uppercase tracking-wide text-slate-400 mt-1">{label}</div>}
      </div>
    </div>
  )
}
