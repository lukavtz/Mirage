import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Loader2, CheckCircle2, XCircle } from 'lucide-react'
import { useI18n } from '@/lib/i18n'

interface CookieItem {
  domain: string
  name: string
  value: string
  path: string
}

interface RestoreResult {
  session_id: string
  proxy: string
  count: number
  cookies: CookieItem[]
}

export default function Restore() {
  const [sessionId, setSessionId] = useState('')
  const [proxy, setProxy] = useState('')
  const { t } = useI18n()

  const restoreMutation = useMutation({
    mutationFn: () =>
      api.post<RestoreResult>('/api/restore/cookies', {
        session_id: sessionId,
        proxy,
      }),
  })

  const result = restoreMutation.data
  const error = restoreMutation.error as { error?: string } | null

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight">{t('restore.title')}</h1>

      <Card>
        <CardHeader>
          <CardTitle>{t('restore.config')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="session-id">{t('restore.session_id')}</Label>
            <Input
              id="session-id"
              placeholder="a1b2c3d4..."
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
              className="font-mono"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="proxy">{t('restore.proxy')}</Label>
            <Input
              id="proxy"
              placeholder="socks5://user:pass@host:1080"
              value={proxy}
              onChange={(e) => setProxy(e.target.value)}
              className="font-mono"
            />
          </div>

          <Button
            onClick={() => restoreMutation.mutate()}
            disabled={restoreMutation.isPending || !sessionId || !proxy}
          >
            {restoreMutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
            {t('restore.start')}
          </Button>
        </CardContent>
      </Card>

      {error && (
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-destructive">
              <XCircle className="h-5 w-5" />
              <span>{error.error || t('restore.failed')}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {result && (
        <Card>
          <CardHeader>
            <CardTitle>{t('restore.progress', { n: result.count })}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {result.cookies.map((c, i) => (
                <div key={i} className="flex items-center gap-2 text-sm font-mono">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-success" />
                  <span className="text-muted-foreground">{c.domain}</span>
                  <span>{c.name}</span>
                </div>
              ))}
            </div>
            {result.cookies.length === 0 && (
              <p className="text-muted-foreground text-sm">{t('restore.no_cookies')}</p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
