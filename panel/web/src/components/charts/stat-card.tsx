import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import type { LucideIcon } from 'lucide-react'

interface StatCardProps {
  title: string
  value: number
  subtitle?: string
  icon: LucideIcon
  isLoading: boolean
  /** 'default' = white value; 'warning' = amber value (KPI highlight). */
  accent?: 'default' | 'warning'
}

export function StatCard({ title, value, subtitle, icon: Icon, isLoading, accent = 'default' }: StatCardProps) {
  if (isLoading) {
    return (
      <Card className="relative overflow-hidden rounded-xl border border-border bg-card p-5 shadow-card-lg">
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary to-transparent" />
        <CardHeader className="flex flex-row items-center justify-between pb-2 p-0">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-4 w-4" />
        </CardHeader>
        <CardContent className="p-0">
          <Skeleton className="h-8 w-16 mb-1" />
          <Skeleton className="h-3 w-20" />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="relative overflow-hidden rounded-xl border border-border bg-card p-5 shadow-card-lg">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary to-transparent" />
      <CardHeader className="flex flex-row items-center justify-between pb-2 p-0">
        <p className="text-sm font-medium text-muted-foreground">{title}</p>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent className="p-0">
        <p className={`text-3xl font-semibold tracking-tight tabular-nums ${accent === 'warning' ? 'text-warning' : 'text-foreground'}`}>
          {value.toLocaleString()}
        </p>
        {subtitle && <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>}
      </CardContent>
    </Card>
  )
}
