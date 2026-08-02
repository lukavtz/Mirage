import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { TrendingUp, TrendingDown, type LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface KpiCardProps {
  title: string
  value: number
  change: number
  sparkline?: number[]
  icon: LucideIcon
  color: string
  isLoading: boolean
  vsLabel?: string
}

export function KpiCard({ title, value, change, sparkline, icon: Icon, color, isLoading, vsLabel }: KpiCardProps) {
  if (isLoading) {
    return (
      <Card className="relative overflow-hidden rounded-xl border border-border bg-card shadow-lg">
        <CardHeader className="flex flex-row items-center justify-between pb-2 p-4">
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-4 w-4 rounded" />
        </CardHeader>
        <CardContent className="px-4 pb-4">
          <Skeleton className="h-8 w-16 mb-2" />
          <Skeleton className="h-3 w-24" />
        </CardContent>
      </Card>
    )
  }

  const isPositive = change >= 0

  return (
    <Card className="relative overflow-hidden rounded-xl border border-border bg-card shadow-lg">
      <div className={cn('absolute inset-x-0 top-0 h-0.5')} style={{ background: color }} />
      <CardHeader className="flex flex-row items-center justify-between pb-1 p-4">
        <p className="text-xs font-medium text-muted-foreground">{title}</p>
        <div className={cn('h-7 w-7 rounded-lg flex items-center justify-center')} style={{ background: color + '20' }}>
          <Icon className="h-3.5 w-3.5" style={{ color }} />
        </div>
      </CardHeader>
      <CardContent className="px-4 pb-4">
        <div className="flex items-end justify-between">
          <div>
            <p className="text-2xl font-bold tabular-nums tracking-tight">{value.toLocaleString()}</p>
            <div className={cn('flex items-center gap-1 mt-1 text-xs font-medium', isPositive ? 'text-green-500' : 'text-red-500')}>
              {isPositive ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
              <span>{vsLabel ?? `${isPositive ? '+' : ''}${change.toFixed(1)}%`}</span>
            </div>
          </div>
          {sparkline && sparkline.length > 0 && (
            <svg width="64" height="28" viewBox="0 0 64 28" className="opacity-60">
              <polyline
                fill="none"
                stroke={color}
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                points={sparkline.map((v, i) => {
                  const max = Math.max(...sparkline)
                  const min = Math.min(...sparkline)
                  const range = max - min || 1
                  const x = (i / (sparkline.length - 1)) * 64
                  const y = 26 - ((v - min) / range) * 24
                  return `${x},${y}`
                }).join(' ')}
              />
            </svg>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
