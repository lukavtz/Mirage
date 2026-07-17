import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'

interface BrowserPieProps {
  data: Array<{ name: string; count: number }>
  isLoading: boolean
}

const PIE_COLORS = [
  'hsl(var(--chart-1))',
  'hsl(var(--chart-2))',
  'hsl(var(--chart-3))',
  'hsl(var(--chart-4))',
  'hsl(var(--chart-5))',
]

export function BrowserPie({ data, isLoading }: BrowserPieProps) {
  if (isLoading) {
    return <Skeleton className="h-[300px] w-full rounded-full" />
  }

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-[300px] text-muted-foreground text-sm">
        No browser data yet
      </div>
    )
  }

  return (
    <div className="flex flex-col items-center">
      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            data={data}
            dataKey="count"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius="60%"
            outerRadius="80%"
            strokeWidth={0}
            label={({ name, percent }) =>
              `${name ?? ''} ${((percent ?? 0) * 100).toFixed(0)}%`
            }
            labelLine
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
              fontSize: 13,
            }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="flex flex-wrap justify-center gap-4 mt-4">
        {data.map((b, i) => (
          <div key={b.name} className="flex items-center gap-2 text-sm">
            <div className="h-3 w-3 rounded-full" style={{ backgroundColor: PIE_COLORS[Math.min(i, PIE_COLORS.length - 1)] }} />
            <span className="text-muted-foreground">{b.name}</span>
            <span className="font-medium">{b.count.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
