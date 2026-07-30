import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'
import { FlagIcon } from '@/components/charts/flag-icon'

interface GeoBarProps {
  data: Array<{ country: string; count: number }>
  isLoading: boolean
}

interface CustomYAxisTickProps {
  x: number
  y: number
  payload: { value: string }
}

function CustomYAxisTick({ x, y, payload }: CustomYAxisTickProps) {
  return (
    <g transform={`translate(${x},${y})`}>
      <foreignObject x={-28} y={-10} width={28} height={20}>
        <FlagIcon country={payload.value} width={20} height={20} />
      </foreignObject>
    </g>
  )
}

export function GeoBar({ data, isLoading }: GeoBarProps) {
  if (isLoading) {
    return <Skeleton className="h-[300px] w-full" />
  }

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-[300px] text-muted-foreground text-sm">
        No geo data yet
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data} layout="vertical" margin={{ top: 5, right: 40, left: 32, bottom: 0 }}>
        <XAxis type="number" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} stroke="hsl(var(--muted-foreground))" />
        <YAxis
          type="category"
          dataKey="country"
          tick={<CustomYAxisTick x={0} y={0} payload={{ value: '' }} />}
          tickLine={false}
          axisLine={false}
          width={32}
        />
        <Tooltip
          contentStyle={{
            background: 'hsl(var(--popover))',
            border: '1px solid hsl(var(--border))',
            borderRadius: 'var(--radius)',
            fontSize: 13,
          }}
          formatter={(value) => Number(value ?? 0).toLocaleString()}
        />
        <Bar dataKey="count" name="Sessions" fill="hsl(var(--primary))" radius={[0, 4, 4, 0]} barSize={20} label={{ position: 'right', fontSize: 11, fill: 'hsl(var(--muted-foreground))' }} />
      </BarChart>
    </ResponsiveContainer>
  )
}
