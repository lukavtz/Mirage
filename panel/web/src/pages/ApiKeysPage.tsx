import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { useI18n } from '@/lib/i18n'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { Key, Trash2, Loader2, Eye, EyeOff } from 'lucide-react'

interface ApiKey {
  id: string
  name: string
  key?: string
  scope: string
  rate_limit: number
  created_at: string
}

export default function ApiKeysPage() {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [scope, setScope] = useState('read')
  const [rateLimit, setRateLimit] = useState(100)
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [showKey, setShowKey] = useState(false)

  const keysQuery = useQuery<{ keys: ApiKey[] }>({
    queryKey: ['api-keys'],
    queryFn: () => api.get('/api/keys'),
  })

  const createMutation = useMutation({
    mutationFn: () => api.post<{ id: string; key: string }>('/api/keys', { name, scope, rate_limit: rateLimit }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] })
      setCreatedKey(data.key)
      setName('')
      setRateLimit(100)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.del(`/api/keys/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['api-keys'] }),
  })

  const keys = keysQuery.data?.keys ?? []

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
        <Key className="h-5 w-5" />{t('api_keys.title')}
      </h1>

      <Card>
        <CardHeader><CardTitle>{t('api_keys.create')}</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label htmlFor="key-name">{t('api_keys.name')}</Label>
              <Input id="key-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="My API Key" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="key-scope">{t('api_keys.scope')}</Label>
              <select
                id="key-scope"
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                className="h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                <option value="read">read</option>
                <option value="write">write</option>
                <option value="admin">admin</option>
              </select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="key-rate">{t('api_keys.rate_limit')}</Label>
              <Input id="key-rate" type="number" min={1} max={10000} value={rateLimit} onChange={(e) => setRateLimit(parseInt(e.target.value) || 100)} />
            </div>
          </div>
          <Button onClick={() => createMutation.mutate()} disabled={!name || createMutation.isPending}>
            {createMutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
            {t('api_keys.create')}
          </Button>
          {createdKey && (
            <div className="flex items-center gap-2 p-3 rounded-md bg-muted font-mono text-sm">
              <span className="flex-1 truncate">{showKey ? createdKey : '\u2022'.repeat(40)}</span>
              <Button variant="ghost" size="sm" onClick={() => setShowKey(!showKey)}>
                {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => { navigator.clipboard.writeText(createdKey); setCreatedKey(null) }}>
                {t('common.copy')}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {keysQuery.isLoading ? (
        <Skeleton className="h-48" />
      ) : keys.length === 0 ? (
        <p className="text-muted-foreground text-center py-8">{t('api_keys.no_keys')}</p>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('api_keys.name')}</TableHead>
                  <TableHead>{t('api_keys.scope')}</TableHead>
                  <TableHead>{t('api_keys.rate_limit')}</TableHead>
                  <TableHead>{t('common.created')}</TableHead>
                  <TableHead className="w-12"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map((k) => (
                  <TableRow key={k.id}>
                    <TableCell className="font-medium">{k.name}</TableCell>
                    <TableCell>
                      <span className="inline-block px-2 py-0.5 rounded text-xs bg-muted">{k.scope}</span>
                    </TableCell>
                    <TableCell>{k.rate_limit}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{k.created_at}</TableCell>
                    <TableCell>
                      <Button variant="ghost" size="sm" onClick={() => deleteMutation.mutate(k.id)} disabled={deleteMutation.isPending}>
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </TableCell>
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
