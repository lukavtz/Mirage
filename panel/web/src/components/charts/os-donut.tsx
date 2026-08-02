import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'
import { PIE_COLORS } from '@/lib/chart-tokens'
import { useI18n } from '@/lib/i18n'

interface OSDonutProps {
  data: Array<{ os: string; count: number }>
  isLoading: boolean
}

export function OSDonut({ data, isLoading }: OSDonutProps) {
  const { t } = useI18n()

  if (isLoading) return <Skeleton className="h-[260px] w-full rounded-xl" />
  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-[260px] text-muted-foreground text-sm">
        {t('chart.no_os')}
      </div>
    )
  }

  const total = data.reduce((s, d) => s + d.count, 0)

  return (
    <div className="flex flex-col items-center">
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie
            data={data}
            dataKey="count"
            nameKey="os"
            cx="50%"
            cy="50%"
            innerRadius="55%"
            outerRadius="80%"
            strokeWidth={2}
            stroke="hsl(var(--background))"
          >
            {data.map((_, i) => (
              <Cell key={i} fill={PIE_COLORS[Math.min(i, PIE_COLORS.length - 1)]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: 'hsl(var(--popover))',
              border: '1px solid hsl(var(--border))',
              borderRadius: 'var(--radius)',
              fontSize: 12,
            }}
            formatter={(value: any) => [`${((Number(value) / total) * 100).toFixed(1)}%`, '']}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="flex flex-wrap justify-center gap-3 mt-2">
        {data.slice(0, 5).map((d, i) => (
          <div key={d.os} className="flex items-center gap-1.5 text-xs">
            <div className="h-2 w-2 rounded-sm" style={{ backgroundColor: PIE_COLORS[Math.min(i, PIE_COLORS.length - 1)] }} />
            <span className="text-muted-foreground truncate max-w-[80px]">{d.os || t('chart.unknown')}</span>
            <span className="font-medium tabular-nums">{((d.count / total) * 100).toFixed(1)}%</span>
          </div>
        ))}
      </div>
    </div>
  )
}
