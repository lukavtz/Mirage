import { Users, Key, Cookie, CreditCard, Activity, BarChart3, Globe } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { StatCard } from '@/components/charts/stat-card'
import { Timeline } from '@/components/charts/timeline'
import { GeoBar } from '@/components/charts/geo-bar'
import { BrowserPie } from '@/components/charts/browser-pie'
import { useDashboard } from '@/hooks/use-dashboard'
import { t } from '@/lib/i18n'

export default function Dashboard() {
  const { data, isLoading } = useDashboard()

  if (isLoading) {
    return (
      <div className="space-y-6 relative before:fixed before:inset-0 before:-z-10 before:bg-[radial-gradient(1200px_600px_at_50%_-200px,hsl(262_64%_53%/0.12),transparent)] before:pointer-events-none">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <StatCard title={t('dashboard.sessions')} value={0} icon={Users} isLoading />
          <StatCard title={t('dashboard.passwords')} value={0} icon={Key} isLoading />
          <StatCard title={t('dashboard.cookies')} value={0} icon={Cookie} isLoading />
          <StatCard title={t('dashboard.wallets')} value={0} icon={CreditCard} isLoading />
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <Card><CardHeader><CardTitle className="text-sm font-medium">{t('dashboard.timeline')}</CardTitle></CardHeader><CardContent><Timeline data={[]} isLoading /></CardContent></Card>
          <Card><CardHeader><CardTitle className="text-sm font-medium">{t('dashboard.geo')}</CardTitle></CardHeader><CardContent><GeoBar data={[]} isLoading /></CardContent></Card>
        </div>
        <Card><CardHeader><CardTitle className="text-sm font-medium">{t('dashboard.browsers')}</CardTitle></CardHeader><CardContent><BrowserPie data={[]} isLoading /></CardContent></Card>
        <Card><CardHeader><CardTitle className="text-sm font-medium">{t('dashboard.top_domains')}</CardTitle></CardHeader><CardContent>{Array.from({ length: 5 }).map((_, i) => (<Skeleton key={i} className="h-8 w-full mb-2" />))}</CardContent></Card>
      </div>
    )
  }

  if (!data || data.sessions.total === 0) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[70vh] gap-8">
        <div className="relative">
          <div className="rounded-2xl bg-gradient-to-br from-primary/10 via-primary/15 to-transparent p-8 ring-1 ring-primary/15 shadow-glow">
            <Activity className="h-16 w-16 text-primary/40" />
          </div>
          <div className="absolute -top-2 -right-2">
            <div className="rounded-full bg-muted p-2 animate-pulse">
              <BarChart3 className="h-4 w-4 text-muted-foreground" />
            </div>
          </div>
        </div>
        <div className="text-center space-y-2 max-w-sm">
          <h2 className="text-xl font-semibold text-foreground">{t('dashboard.title')}</h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            {t('dashboard.no_data')}
          </p>
        </div>
        <div className="flex gap-4 text-xs text-muted-foreground">
          <div className="flex items-center gap-1.5">
            <Globe className="h-3.5 w-3.5" />
            <span>Logs appear here</span>
          </div>
          <div className="flex items-center gap-1.5">
            <BarChart3 className="h-3.5 w-3.5" />
            <span>Charts auto-populate</span>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6 relative before:fixed before:inset-0 before:-z-10 before:bg-[radial-gradient(1200px_600px_at_50%_-200px,hsl(262_64%_53%/0.12),transparent)] before:pointer-events-none">
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard title={t('dashboard.sessions')} value={data.sessions.total} subtitle={t('dashboard.today', { n: data.sessions.today })} icon={Users} isLoading={false} accent="warning" />
        <StatCard title={t('dashboard.passwords')} value={data.passwords.total} icon={Key} isLoading={false} accent="warning" />
        <StatCard title={t('dashboard.cookies')} value={data.cookies.total} icon={Cookie} isLoading={false} accent="warning" />
        <StatCard title={t('dashboard.wallets')} value={data.wallets.total} icon={CreditCard} isLoading={false} accent="warning" />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="col-span-full md:col-span-1">
          <CardHeader><CardTitle className="text-sm font-medium">{t('dashboard.timeline')}</CardTitle></CardHeader>
          <CardContent><Timeline data={data.timeline} isLoading={false} /></CardContent>
        </Card>
        <Card className="col-span-full md:col-span-1">
          <CardHeader><CardTitle className="text-sm font-medium">{t('dashboard.geo')}</CardTitle></CardHeader>
          <CardContent><GeoBar data={data.geo} isLoading={false} /></CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">{t('dashboard.browsers')}</CardTitle></CardHeader>
        <CardContent><BrowserPie data={data.browsers} isLoading={false} /></CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">{t('dashboard.top_domains')}</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8">#</TableHead>
                <TableHead>{t('dashboard.top_domains')}</TableHead>
                <TableHead className="text-right">{t('dashboard.sessions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.top_domains.map((d, i) => (
                <TableRow key={d.domain}>
                  <TableCell className="text-muted-foreground text-xs">{i + 1}</TableCell>
                  <TableCell className="font-mono text-sm">{d.domain}</TableCell>
                  <TableCell className="text-right tabular-nums">{d.count.toLocaleString()}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
