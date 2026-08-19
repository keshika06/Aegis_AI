export default function KpiCard({ icon: Icon, label, value, valueColor, sub, trend, trendUp, accent }) {
  return (
    <div className="card p-4 flex flex-col gap-2 hover:border-base-border2 transition-colors">
      <div className="flex items-center justify-between">
        <span className="label-eyebrow">{label}</span>
        {Icon && <Icon size={15} className="text-slate-500" />}
      </div>
      <div className="flex items-baseline gap-2">
        <span className="text-2xl font-bold" style={{ color: valueColor || '#e6e9f0' }}>{value}</span>
        {trend && (
          <span className={`text-xs font-semibold ${trendUp ? 'text-sev-high' : 'text-sev-low'}`}>
            {trendUp ? '↑' : '↓'} {trend}
          </span>
        )}
      </div>
      {sub && <span className="text-xs text-slate-500">{sub}</span>}
      {accent && <div className="h-1 rounded-full mt-1" style={{ backgroundColor: accent, opacity: 0.6 }} />}
    </div>
  )
}
