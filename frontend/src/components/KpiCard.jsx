// `delta` is the signed change against the previous run, or null when there is
// no comparable previous run. Null renders nothing rather than an arrow, and
// zero renders as unchanged — a down arrow on a delta of zero would read as an
// improvement that did not happen.
export default function KpiCard({ icon: Icon, label, value, valueColor, sub, delta, deltaSuffix = '', accent }) {
  const hasDelta = delta !== null && delta !== undefined
  const colour = !hasDelta || delta === 0 ? 'text-content-muted' : delta > 0 ? 'text-sev-high' : 'text-sev-low'
  const arrow = !hasDelta || delta === 0 ? '·' : delta > 0 ? '↑' : '↓'

  return (
    <div className="card p-4 flex flex-col gap-2 hover:border-base-border2 transition-colors">
      <div className="flex items-center justify-between">
        <span className="label-eyebrow">{label}</span>
        {Icon && <Icon size={15} className="text-content-dim" />}
      </div>
      <div className="flex items-baseline gap-2">
        <span className="text-2xl font-bold" style={{ color: valueColor || 'var(--text)' }}>{value}</span>
        {hasDelta && (
          <span className={`text-xs font-semibold ${colour}`}>
            {arrow} {delta === 0 ? 'no change' : `${Math.abs(delta)}${deltaSuffix}`}
          </span>
        )}
      </div>
      {sub && <span className="text-xs text-content-dim">{sub}</span>}
      {accent && <div className="h-1 rounded-full mt-1" style={{ backgroundColor: accent, opacity: 0.6 }} />}
    </div>
  )
}
