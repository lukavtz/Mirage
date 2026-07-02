import { Users, Key, Cookie, CreditCard, Inbox } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { StatCard } from '@/components/charts/stat-card'
import { Timeline } from '@/components/charts/timeline'
import { GeoBar } from '@/components/charts/geo-bar'
import { BrowserPie } from '@/components/charts/browser-pie'
import { useDashboard } from '@/hooks/use-dashboard'

export default function Dashboard() {
  const { data, isLoading } = useDashboard()

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <StatCard title="Sessions" value={0} icon={Users} isLoading />
          <StatCard title="Passwords" value={0} icon={Key} isLoading />
          <StatCard title="Cookies" value={0} icon={Cookie} isLoading />
          <StatCard title="Wallets" value={0} icon={CreditCard} isLoading />
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <Card>
            <CardHeader><CardTitle className="text-sm font-medium">Timeline (30 days)</CardTitle></CardHeader>
            <CardContent><Timeline data={[]} isLoading /></CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle className="text-sm font-medium">Geo Distribution</CardTitle></CardHeader>
            <CardContent><GeoBar data={[]} isLoading /></CardContent>
          </Card>
        </div>
        <Card>
          <CardHeader><CardTitle className="text-sm font-medium">Browser Distribution</CardTitle></CardHeader>
          <CardContent><BrowserPie data={[]} isLoading /></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm font-medium">Top Domains</CardTitle></CardHeader>
          <CardContent>
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-8 w-full" />
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (!data || data.sessions.total === 0) {
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
        <StatCard title="Sessions" value={data.sessions.total} subtitle={`+${data.sessions.today} today`} icon={Users} isLoading={false} />
        <StatCard title="Passwords" value={data.passwords.total} icon={Key} isLoading={false} />
        <StatCard title="Cookies" value={data.cookies.total} icon={Cookie} isLoading={false} />
        <StatCard title="Wallets" value={data.wallets.total} icon={CreditCard} isLoading={false} />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="col-span-full md:col-span-1">
          <CardHeader>
            <CardTitle className="text-sm font-medium">Timeline (30 days)</CardTitle>
          </CardHeader>
          <CardContent>
            <Timeline data={data.timeline} isLoading={false} />
          </CardContent>
        </Card>

        <Card className="col-span-full md:col-span-1">
          <CardHeader>
            <CardTitle className="text-sm font-medium">Geo Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <GeoBar data={data.geo} isLoading={false} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Browser Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <BrowserPie data={data.browsers} isLoading={false} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Top Domains</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8">#</TableHead>
                <TableHead>Domain</TableHead>
                <TableHead className="text-right">Sessions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.top_domains.map((d, i) => (
                <TableRow key={d.domain}>
                  <TableCell className="text-muted-foreground">{i + 1}</TableCell>
                  <TableCell className="font-mono">{d.domain}</TableCell>
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
