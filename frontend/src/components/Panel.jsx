export function PageHeader({ title, subtitle, right }) {
  return (
    <div className="flex items-start justify-between mb-6 gap-4 flex-wrap">
      <div>
        <h1 className="text-2xl font-bold text-content">{title}</h1>
        {subtitle && <p className="text-sm text-content-dim mt-1 max-w-xl">{subtitle}</p>}
      </div>
      {right && <div className="text-right">{right}</div>}
    </div>
  )
}

export function Panel({ title, icon: Icon, right, children, className = '' }) {
  return (
    <div className={`card p-5 ${className}`}>
      {(title || right) && (
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            {Icon && <Icon size={15} className="text-brand" />}
            {title && <h3 className="text-[13px] font-bold text-content uppercase tracking-wide">{title}</h3>}
          </div>
          {right}
        </div>
      )}
      {children}
    </div>
  )
}

export function Bar({ label, score, max = 100, color, sub }) {
  const pct = Math.min(100, (score / max) * 100)
  return (
    <div className="mb-3.5 last:mb-0">
      <div className="flex items-center justify-between text-[13px] mb-1">
        <span className="text-content font-medium">{label}</span>
        <span className="mono font-bold text-content">{score}</span>
      </div>
      <div className="h-2 rounded-full bg-base-card2 overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color || '#7c5cff' }} />
      </div>
      {sub && <div className="text-[11px] text-content-dim mt-1">{sub}</div>}
    </div>
  )
}
