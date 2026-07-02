import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { useTheme } from '@/lib/theme-provider'
import { getLang, setLang, t } from '@/lib/i18n'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Sun, Moon, CheckCircle, XCircle, Loader2 } from 'lucide-react'

interface AppSettings {
  panel: { port: number; auth_token: string }
  telegram: { token: string; chat_id: string }
  rate_limit: number
}

interface DbStats {
  sessions: number
  size_mb: number
  connected: boolean
}

interface AuditEntry {
  id: string
  time: string
  user: string
  action: string
  details: string
}

export default function Settings() {
  const { theme, toggle } = useTheme()
  const queryClient = useQueryClient()
  const currentLang = getLang()

  const settingsQuery = useQuery<AppSettings>({
    queryKey: ['settings'],
    queryFn: () => api.get('/api/settings'),
  })

  const dbQuery = useQuery<DbStats>({
    queryKey: ['db-stats'],
    queryFn: () => api.get('/api/database/stats'),
  })

  const auditQuery = useQuery<{ data: AuditEntry[] }>({
    queryKey: ['audit'],
    queryFn: () => api.get('/api/audit', { limit: 50 }),
  })

  const [port, setPort] = useState(8080)
  const [authToken, setAuthToken] = useState('')
  const [rateLimit, setRateLimit] = useState(100)
  const [tgToken, setTgToken] = useState('')
  const [tgChatId, setTgChatId] = useState('')

  useEffect(() => {
    if (settingsQuery.data) {
      setPort(settingsQuery.data.panel.port)
      setAuthToken(settingsQuery.data.panel.auth_token)
      setRateLimit(settingsQuery.data.rate_limit)
      setTgToken(settingsQuery.data.telegram.token)
      setTgChatId(settingsQuery.data.telegram.chat_id)
    }
  }, [settingsQuery.data])

  const saveMutation = useMutation({
    mutationFn: () =>
      api.put('/api/settings', {
        panel: { port, auth_token: authToken },
        telegram: { token: tgToken, chat_id: tgChatId },
        rate_limit: rateLimit,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] })
    },
  })

  const regenTokenMutation = useMutation({
    mutationFn: () => api.post<{ auth_token: string }>('/api/settings/panel/token'),
    onSuccess: (data) => {
      setAuthToken(data.auth_token)
      queryClient.invalidateQueries({ queryKey: ['settings'] })
    },
  })

  const testTelegramMutation = useMutation({
    mutationFn: () => api.post('/api/settings/telegram/test', { token: tgToken, chat_id: tgChatId }),
  })

  const vacuumMutation = useMutation({
    mutationFn: () => api.post('/api/database/vacuum'),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['db-stats'] }),
  })

  if (settingsQuery.isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (settingsQuery.isError) {
    return (
      <div className="flex items-center justify-center min-h-[60vh] text-destructive">
        Failed to load settings
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t('settings')}</h1>

      <Card>
        <CardHeader>
          <CardTitle>Panel</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="port">Port</Label>
              <Input
                id="port"
                type="number"
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="rate-limit">Rate Limit (req/min)</Label>
              <Input
                id="rate-limit"
                type="number"
                value={rateLimit}
                onChange={(e) => setRateLimit(Number(e.target.value))}
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="auth-token">Auth Token</Label>
            <div className="flex gap-2">
              <Input
                id="auth-token"
                type="password"
                value={authToken}
                readOnly
                className="font-mono"
              />
              <Button
                variant="outline"
                onClick={() => regenTokenMutation.mutate()}
                disabled={regenTokenMutation.isPending}
              >
                {regenTokenMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                Regenerate
              </Button>
            </div>
          </div>
          <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
            {saveMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Save
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Telegram</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="tg-token">Token</Label>
            <div className="flex gap-2">
              <Input
                id="tg-token"
                type="password"
                value={tgToken}
                onChange={(e) => setTgToken(e.target.value)}
                className="font-mono"
              />
              <Button
                variant="outline"
                onClick={() => testTelegramMutation.mutate()}
                disabled={testTelegramMutation.isPending}
              >
                {testTelegramMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                Test
              </Button>
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="tg-chat-id">Chat ID</Label>
            <div className="flex gap-2">
              <Input
                id="tg-chat-id"
                value={tgChatId}
                onChange={(e) => setTgChatId(e.target.value)}
                className="font-mono"
              />
              <Button
                variant="outline"
                onClick={() => testTelegramMutation.mutate()}
                disabled={testTelegramMutation.isPending}
              >
                {testTelegramMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                Test
              </Button>
            </div>
          </div>
          <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
            {saveMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Save
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Appearance</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Theme</Label>
            <div className="flex gap-2">
              <Button
                variant={theme === 'dark' ? 'default' : 'outline'}
                size="sm"
                onClick={() => { if (theme !== 'dark') toggle() }}
              >
                <Moon className="h-4 w-4 mr-2" />
                Dark
              </Button>
              <Button
                variant={theme === 'light' ? 'default' : 'outline'}
                size="sm"
                onClick={() => { if (theme !== 'light') toggle() }}
              >
                <Sun className="h-4 w-4 mr-2" />
                Light
              </Button>
            </div>
          </div>
          <div className="space-y-2">
            <Label>Language</Label>
            <div className="flex gap-2">
              <Button
                variant={currentLang === 'en' ? 'default' : 'outline'}
                size="sm"
                onClick={() => { setLang('en'); window.location.reload() }}
              >
                English
              </Button>
              <Button
                variant={currentLang === 'ru' ? 'default' : 'outline'}
                size="sm"
                onClick={() => { setLang('ru'); window.location.reload() }}
              >
                Русский
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Database</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4 text-sm">
            <span className="text-muted-foreground">
              Sessions: <strong className="text-foreground tabular-nums">{(dbQuery.data?.sessions ?? 0).toLocaleString()}</strong>
            </span>
            <span className="text-muted-foreground">
              Size: <strong className="text-foreground tabular-nums">{dbQuery.data?.size_mb ?? 0} MB</strong>
            </span>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => vacuumMutation.mutate()}
              disabled={vacuumMutation.isPending}
            >
              {vacuumMutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1" />}
              Vacuum
            </Button>
            <Button variant="outline" size="sm">
              Export All
            </Button>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <Label>Connection:</Label>
            {dbQuery.data?.connected ? (
              <span className="flex items-center gap-1 text-emerald-500">
                <CheckCircle className="h-3.5 w-3.5" />
                Connected
              </span>
            ) : (
              <span className="flex items-center gap-1 text-red-500">
                <XCircle className="h-3.5 w-3.5" />
                Disconnected
              </span>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Audit Log (last 50)</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>User</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {auditQuery.data?.data?.length ? (
                auditQuery.data.data.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell className="font-mono text-xs">{entry.time}</TableCell>
                    <TableCell>{entry.user}</TableCell>
                    <TableCell>{entry.action}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{entry.details}</TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-muted-foreground py-8">
                    {auditQuery.isLoading ? 'Loading...' : 'No audit entries yet'}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
