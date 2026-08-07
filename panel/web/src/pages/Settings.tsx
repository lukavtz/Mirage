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
import { Sun, Moon, Loader2 } from 'lucide-react'
import { TotpSetupCard } from '@/components/totp-setup'

interface SettingsResponse {
  settings: Record<string, string>
  audit: Array<{ id: string; user_id?: string; action: string; details?: string; ip?: string; created_at: string }>
}

export default function Settings() {
  const { theme, toggle } = useTheme()
  const queryClient = useQueryClient()
  const currentLang = getLang()

  const settingsQuery = useQuery<SettingsResponse>({
    queryKey: ['settings'],
    queryFn: () => api.get('/api/settings'),
  })

  const s = settingsQuery.data?.settings ?? {}
  const audit = settingsQuery.data?.audit ?? []

  const [tgToken, setTgToken] = useState('')
  const [tgChatId, setTgChatId] = useState('')
  const [rateLimit, setRateLimit] = useState(100)

  useEffect(() => {
    if (settingsQuery.data) {
      setTgToken(s.telegram_token ?? '')
      setTgChatId(s.telegram_chat_id ?? '')
      setRateLimit(parseInt(s.rate_limit ?? '100'))
    }
  }, [settingsQuery.data])

  const saveMutation = useMutation({
    mutationFn: () => api.put('/api/settings', {
      telegram_token: tgToken,
      telegram_chat_id: tgChatId,
      rate_limit: String(rateLimit),
    }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['settings'] }),
  })

  const testTelegramMutation = useMutation({
    mutationFn: () => api.post('/api/settings/telegram/test', { token: tgToken, chat_id: tgChatId }),
  })

  if (settingsQuery.isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight">{t('settings.title')}</h1>

      <Card>
        <CardHeader><CardTitle>{t('settings.telegram')}</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="tg-token">{t('build.tg_token')}</Label>
            <div className="flex gap-2">
              <Input id="tg-token" type="password" value={tgToken} onChange={(e) => setTgToken(e.target.value)} className="font-mono" />
              <Button variant="outline" onClick={() => testTelegramMutation.mutate()} disabled={testTelegramMutation.isPending}>
                {testTelegramMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                {t('settings.test')}
              </Button>
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="tg-chat-id">{t('build.tg_chat')}</Label>
            <Input id="tg-chat-id" value={tgChatId} onChange={(e) => setTgChatId(e.target.value)} className="font-mono" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="rate-limit">{t('settings.rate_limit')}</Label>
            <Input id="rate-limit" type="number" min={10} max={1000} value={rateLimit} onChange={(e) => setRateLimit(parseInt(e.target.value) || 100)} />
          </div>
          <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
            {saveMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            {t('common.save')}
          </Button>
          {saveMutation.isSuccess && <p className="text-sm text-success">{t('common.saved')}</p>}
          {saveMutation.isError && <p className="text-sm text-destructive">Failed to save</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>{t('settings.appearance')}</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>{t('settings.theme')}</Label>
            <div className="flex gap-2">
              <Button variant={theme === 'dark' ? 'default' : 'outline'} size="sm" onClick={() => { if (theme !== 'dark') toggle() }}>
                <Moon className="h-4 w-4 mr-2" />{t('settings.dark')}
              </Button>
              <Button variant={theme === 'light' ? 'default' : 'outline'} size="sm" onClick={() => { if (theme !== 'light') toggle() }}>
                <Sun className="h-4 w-4 mr-2" />{t('settings.light')}
              </Button>
            </div>
          </div>
          <div className="space-y-2">
            <Label>{t('settings.language')}</Label>
            <div className="flex gap-2">
              <Button variant={currentLang === 'en' ? 'default' : 'outline'} size="sm" onClick={() => { setLang('en'); window.location.reload() }}>English</Button>
              <Button variant={currentLang === 'ru' ? 'default' : 'outline'} size="sm" onClick={() => { setLang('ru'); window.location.reload() }}>Русский</Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <TotpSetupCard />

      <Card>
        <CardHeader><CardTitle>{t('settings.database')}</CardTitle></CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <span className="inline-block h-2 w-2 rounded-full bg-success" />
            <span>PostgreSQL</span>
            <span className="text-xs">— connected</span>
          </div>
        </CardContent>
      </Card>

      {audit.length > 0 && (
        <Card>
          <CardHeader><CardTitle>{t('settings.audit')}</CardTitle></CardHeader>
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
                {audit.slice(0, 50).map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell className="text-xs text-muted-foreground">{entry.created_at}</TableCell>
                    <TableCell className="text-xs">{entry.user_id ?? '-'}</TableCell>
                    <TableCell className="text-xs">{entry.action}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{entry.details ?? entry.ip ?? '-'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
