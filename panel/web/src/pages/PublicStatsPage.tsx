import { useQuery } from '@tanstack/react-query'
import { Users, Key, Wallet, Cookie, TrendingUp } from 'lucide-react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, PieChart, Pie, Cell } from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { FlagIcon } from '@/components/charts/flag-icon'
import { api } from '@/lib/api'
import { useI18n } from '@/lib/i18n'
import { PIE_COLORS, useChartGradientId } from '@/lib/chart-tokens'
import { COUNTRY_NAMES } from '@/lib/countries'

interface PublicStats {
  total_sessions: number
  today_sessions: number
  total_passwords: number
  total_wallets: number
  total_cookies: number
  total_cards: number
  crypto_logs_pct: number
  duplicates_pct: number
  country_distribution: Array<{ country: string; count: number }>
  browser_distribution: Array<{ browser: string; count: number }>
  timeline: Array<{ date: string; count: number }>
}

export default function PublicStatsPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['public-stats'],
    queryFn: () => api.get<PublicStats>('/api/public/stats'),
    retry: 1,
    staleTime: 60000,
  })

  const { t } = useI18n()
  const timelineGradientId = useChartGradientId('public-timeline')

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Skeleton className="h-8 w-48" />
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="min-h-screen bg-background flex flex-col items-center justify-center gap-4">
        <TrendingUp className="h-12 w-12 text-muted-foreground/40" />
        <p className="text-muted-foreground text-sm">{t('public.disabled')}</p>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-6xl mx-auto p-6 space-y-6">
        <div className="flex items-center gap-3 mb-2">
          <div className="rounded-lg bg-primary/10 p-2">
            <TrendingUp className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">{t('public.title')}</h1>
            <p className="text-xs text-muted-foreground">{t('public.subtitle')}</p>
          </div>
        </div>

        <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-muted-foreground">{t('public.total_sessions')}</p>
                <Users className="h-4 w-4 text-muted-foreground" />
              </div>
              <p className="text-2xl font-bold tabular-nums">{data.total_sessions.toLocaleString()}</p>
              <p className="text-xs text-muted-foreground mt-1">+{data.today_sessions} today</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-muted-foreground">{t('nav.passwords')}</p>
                <Key className="h-4 w-4 text-muted-foreground" />
              </div>
              <p className="text-2xl font-bold tabular-nums">{data.total_passwords.toLocaleString()}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-muted-foreground">{t('nav.wallets')}</p>
                <Wallet className="h-4 w-4 text-muted-foreground" />
              </div>
              <p className="text-2xl font-bold tabular-nums">{data.total_wallets.toLocaleString()}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-muted-foreground">{t('nav.cookies')}</p>
                <Cookie className="h-4 w-4 text-muted-foreground" />
              </div>
              <p className="text-2xl font-bold tabular-nums">{data.total_cookies.toLocaleString()}</p>
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <Card>
            <CardHeader><CardTitle className="text-sm font-medium">{t('dashboard.timeline')}</CardTitle></CardHeader>
            <CardContent>
              {data.timeline.length === 0 ? (
                <div className="flex items-center justify-center h-[200px] text-muted-foreground text-xs">No data</div>
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={data.timeline}>
                    <defs>
                      <linearGradient id={timelineGradientId} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.25} />
                        <stop offset="55%" stopColor="var(--primary)" stopOpacity={0.08} />
                        <stop offset="100%" stopColor="var(--primary)" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="date" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} stroke="var(--muted-foreground)" tickFormatter={(v, i) => i % 5 === 0 ? v : ''} />
                    <YAxis allowDecimals={false} tick={{ fontSize: 10 }} tickLine={false} axisLine={false} stroke="var(--muted-foreground)" />
                    <Tooltip contentStyle={{ background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', fontSize: 12 }} />
                    <Area type="monotone" dataKey="count" stroke="var(--primary)" fill={`url(#${timelineGradientId})`} strokeWidth={2.5} />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle className="text-sm font-medium">{t('dashboard.top_countries')}</CardTitle></CardHeader>
            <CardContent>
              {data.country_distribution.length === 0 ? (
                <div className="flex items-center justify-center h-[200px] text-muted-foreground text-xs">No data</div>
              ) : (
                <div className="space-y-2 max-h-[200px] overflow-y-auto">
                  {data.country_distribution.map(c => (
                    <div key={c.country} className="flex items-center gap-3">
                      <FlagIcon country={c.country} width={18} height={18} />
                      <div className="flex-1">
                        <div className="flex justify-between text-xs mb-0.5">
                          <span className="text-muted-foreground">{COUNTRY_NAMES[c.country] || c.country}</span>
                          <span className="font-medium tabular-nums">{c.count.toLocaleString()}</span>
                        </div>
                        <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full bg-primary rounded-full transition-all"
                            style={{ width: `${(c.count / Math.max(...data.country_distribution.map(x => x.count))) * 100}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <Card>
            <CardHeader><CardTitle className="text-sm font-medium">{t('dashboard.browsers')}</CardTitle></CardHeader>
            <CardContent>
              {data.browser_distribution.length === 0 ? (
                <div className="flex items-center justify-center h-[200px] text-muted-foreground text-xs">No data</div>
              ) : (
                <div className="flex flex-col items-center">
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie data={data.browser_distribution} dataKey="count" nameKey="browser" cx="50%" cy="50%" innerRadius={50} outerRadius={70} strokeWidth={0} label={({ name, percent }) => `${name ?? ''} ${((percent ?? 0) * 100).toFixed(0)}%`} labelLine>
                        {data.browser_distribution.map((_, i) => <Cell key={i} fill={PIE_COLORS[Math.min(i, PIE_COLORS.length - 1)]} />)}
                      </Pie>
                      <Tooltip contentStyle={{ background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', fontSize: 12 }} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="flex flex-wrap justify-center gap-3 mt-2">
                    {data.browser_distribution.map((b, i) => (
                      <div key={b.browser} className="flex items-center gap-1.5 text-xs">
                        <div className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: PIE_COLORS[Math.min(i, PIE_COLORS.length - 1)] }} />
                        <span className="text-muted-foreground">{b.browser}</span>
                        <span className="font-medium">{b.count.toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-sm font-medium">{t('public.overview')}</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <div className="flex justify-between items-center py-2 border-b border-border/50">
                <span className="text-xs text-muted-foreground">{t('nav.cards')}</span>
                <span className="text-sm font-medium tabular-nums">{data.total_cards.toLocaleString()}</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-border/50">
                <span className="text-xs text-muted-foreground">{t('public.crypto_logs')}</span>
                <span className="text-sm font-medium tabular-nums">{data.crypto_logs_pct.toFixed(1)}%</span>
              </div>
              <div className="flex justify-between items-center py-2">
                <span className="text-xs text-muted-foreground">{t('public.duplicates')}</span>
                <span className="text-sm font-medium tabular-nums">{data.duplicates_pct.toFixed(1)}%</span>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
