import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'
import { useChartGradientId } from '@/lib/chart-tokens'
import { useI18n } from '@/lib/i18n'

interface TimelineProps {
  data: Array<{ date: string; count: number }>
  isLoading: boolean
}

export function Timeline({ data, isLoading }: TimelineProps) {
  const gradientId = useChartGradientId('timeline')
  const { t } = useI18n()

  if (isLoading) {
    return <Skeleton className="h-[300px] w-full" />
  }

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-[300px] text-muted-foreground text-sm">
        {t('chart.no_timeline')}
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <AreaChart data={data} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.35} />
            <stop offset="55%" stopColor="hsl(var(--primary))" stopOpacity={0.08} />
            <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="hsl(var(--border))" strokeDasharray="3 3" vertical={false} />
        <XAxis
          dataKey="date"
          tick={{ fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          stroke="hsl(var(--muted-foreground))"
          tickFormatter={(val, i) => (i % 5 === 0 ? val : '')}
        />
        <YAxis
          allowDecimals={false}
          tick={{ fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          stroke="hsl(var(--muted-foreground))"
        />
        <Tooltip
          contentStyle={{
            background: 'hsl(var(--popover))',
            border: '1px solid hsl(var(--border))',
            borderRadius: 'var(--radius)',
            fontSize: 13,
          }}
          labelFormatter={(label) => label ?? ''}
          formatter={(value) => Number(value ?? 0).toLocaleString()}
        />
        <Area type="monotone" dataKey="count" name={t('chart.sessions')} stroke="hsl(var(--primary))" fill={`url(#${gradientId})`} strokeWidth={2.5} />
      </AreaChart>
    </ResponsiveContainer>
  )
}
