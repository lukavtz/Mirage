import { motion } from 'motion/react'
import { Skeleton } from '@/components/ui/skeleton'
import { OsIcon, normalizeOsLabel } from '@/components/charts/os-icon'
import { useI18n } from '@/lib/i18n'
import { cn } from '@/lib/utils'

interface OSChartProps {
  data: Array<{ os: string; count: number }>
  isLoading: boolean
  onSelect?: (os: string) => void
  selectedOs?: string
}

export function OSChart({ data, isLoading, onSelect, selectedOs }: OSChartProps) {
  const { t } = useI18n()

  if (isLoading) {
    return (
      <div className="space-y-1.5">
        {Array.from({ length: 7 }).map((_, i) => (
          <Skeleton key={i} className="h-9 w-full rounded-md" />
        ))}
      </div>
    )
  }

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-40 text-muted-foreground text-sm">
        {t('chart.no_os')}
      </div>
    )
  }

  const total = data.reduce((s, d) => s + d.count, 0)
  const max = Math.max(...data.map(d => d.count), 1)
  const top = data.slice(0, 7)

  return (
    <div className="space-y-1.5">
      {top.map((d, i) => {
        const pct = ((d.count / total) * 100).toFixed(1)
        const ratio = d.count / max
        const isActive = d.os === selectedOs
        const label = normalizeOsLabel(d.os)
        return (
          <motion.button
            key={d.os || 'unknown'}
            initial={{ opacity: 0, x: -6 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.32, ease: [0.16, 1, 0.3, 1], delay: i * 0.04 }}
            onClick={() => onSelect?.(d.os === selectedOs ? '' : d.os)}
            className={cn(
              'group w-full flex items-center gap-3 py-1.5 px-2 text-left transition-colors',
              'hover:bg-accent/50',
              isActive && 'bg-accent ring-1 ring-inset ring-border',
            )}
          >
            <span className="text-[11px] mono text-muted-foreground/60 w-3 text-right tabular-nums">
              {String(i + 1).padStart(2, '0')}
            </span>
            <OsIcon os={d.os} size={16} />
            <span className="text-[12.5px] font-medium flex-1 truncate text-foreground">
              {label}
            </span>
            <span className="mono text-[11px] tabular-nums text-foreground w-10 text-right">
              {d.count.toLocaleString()}
            </span>
            <span className="text-[10px] text-muted-foreground mono tabular-nums w-10 text-right">
              {pct}%
            </span>
            <div className="w-16 h-1 bg-muted overflow-hidden">
              <motion.div
                className="h-full bg-foreground"
                initial={{ width: 0 }}
                animate={{ width: `${ratio * 100}%` }}
                transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1], delay: i * 0.04 }}
              />
            </div>
          </motion.button>
        )
      })}
    </div>
  )
}
