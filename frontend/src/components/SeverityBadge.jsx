import { severityColor } from '../data/scanData'

export default function SeverityBadge({ level, size = 'sm' }) {
  const c = severityColor[level?.toUpperCase()] || severityColor.NEUTRAL
  const sizeCls = size === 'lg' ? 'text-xs px-2.5 py-1' : 'text-[10px] px-2 py-0.5'
  return (
    <span
      className={`inline-flex items-center gap-1 font-bold uppercase tracking-wide rounded ${sizeCls} border`}
      style={{ color: c.text, backgroundColor: c.bg, borderColor: c.border }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: c.text }} />
      {level}
    </span>
  )
}
