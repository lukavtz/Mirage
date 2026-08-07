import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { ArrowLeft, Eye, EyeOff, Key, Cookie, CreditCard, Wallet, FileText, Monitor, Server, Download, Trash2, MessageSquare, Image, Lock, Unlock } from 'lucide-react'
import { api } from '@/lib/api'
import { wsClient } from '@/lib/ws'
import { useI18n } from '@/lib/i18n'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from '@/components/ui/dropdown-menu'
import {
  AlertDialog,
  AlertDialogTrigger,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogCancel,
  AlertDialogAction,
} from '@/components/ui/alert-dialog'
import { FlagIcon } from '@/components/charts/flag-icon'
import type { SessionDetail, Note } from '@/types'

function formatBytes(bytes?: number): string {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

export default function SessionDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { t } = useI18n()
  const [revealed, setRevealed] = useState<Set<string>>(new Set())
  const [activeTab, setActiveTab] = useState('passwords')
  const [screenshotState, setScreenshotState] = useState<{
    status: 'loading' | 'present' | 'absent' | 'gone'
    width: number
    height: number
    sizeKb: number
    objectUrl: string | null
  }>({ status: 'loading', width: 0, height: 0, sizeKb: 0, objectUrl: null })

  const query = useQuery<SessionDetail>({
    queryKey: ['session', id],
    queryFn: () => api.get<SessionDetail>(`/api/sessions/${id}`),
    enabled: !!id,
  })

  const queryClient = useQueryClient()
  const [newNote, setNewNote] = useState('')

  const notesQuery = useQuery<Note[]>({
    queryKey: ['notes', id],
    queryFn: () => api.get<Note[]>(`/api/sessions/${id}/notes`),
    enabled: !!id,
  })

  const addNoteMutation = useMutation({
    mutationFn: (content: string) => api.post(`/api/sessions/${id}/notes`, { content }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notes', id] })
      setNewNote('')
    },
  })

  const deleteNoteMutation = useMutation({
    mutationFn: (noteId: string) => api.del(`/api/notes/${noteId}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['notes', id] }),
  })

  const lockMutation = useMutation({
    mutationFn: () => api.post(`/api/sessions/${id}/lock`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['session', id] }),
  })

  const unlockMutation = useMutation({
    mutationFn: () => api.post(`/api/sessions/${id}/unlock`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['session', id] }),
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.del(`/api/sessions/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
      navigate('/sessions')
    },
  })

  const toggleReveal = (id: string) => {
    setRevealed(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  // Fetch the screenshot as a blob (auth required, JWT lives in localStorage).
  // The blob URL is set on screenshotState for use by both the header
  // thumbnail and the tab body <img> tag.
  useEffect(() => {
    if (!id) return
    const token = typeof window !== 'undefined' ? localStorage.getItem('token') : null
    const headers: Record<string, string> = {}
    if (token) headers['Authorization'] = `Bearer ${token}`
    let cancelled = false
    let blobUrl: string | null = null
    fetch(`/api/sessions/${id}/screenshot`, { method: 'GET', headers })
      .then(async (res) => {
        if (cancelled) return
        if (res.status === 404) {
          setScreenshotState({ status: 'absent', width: 0, height: 0, sizeKb: 0, objectUrl: null })
          return
        }
        if (res.status === 410) {
          setScreenshotState({ status: 'gone', width: 0, height: 0, sizeKb: 0, objectUrl: null })
          return
        }
        if (!res.ok) {
          setScreenshotState({ status: 'absent', width: 0, height: 0, sizeKb: 0, objectUrl: null })
          return
        }
        const buf = new Uint8Array(await res.arrayBuffer())
        const sizeBytes = Number(res.headers.get('Content-Length') ?? buf.length)
        let w = 0
        let h = 0
        if (buf.length >= 30 && buf[0] === 0x42 && buf[1] === 0x4d) {
          const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
          if (dv.getUint32(14, true) >= 40) {
            w = dv.getInt32(18, true)
            h = dv.getInt32(22, true)
          }
        }
        const blob = new Blob([buf], { type: res.headers.get('Content-Type') ?? 'image/bmp' })
        blobUrl = URL.createObjectURL(blob)
        setScreenshotState({
          status: 'present',
          width: w,
          height: h,
          sizeKb: Math.max(1, Math.round(sizeBytes / 1024)),
          objectUrl: blobUrl,
        })
      })
      .catch(() => {
        if (!cancelled) setScreenshotState({ status: 'absent', width: 0, height: 0, sizeKb: 0, objectUrl: null })
      })
    return () => {
      cancelled = true
      if (blobUrl) URL.revokeObjectURL(blobUrl)
    }
  }, [id])

  // Auto-refresh on session update via WebSocket
  useEffect(() => {
    if (!id) return
    const unsub = wsClient.on('session_update', (data: any) => {
      if (data?.session_id === id) {
        queryClient.invalidateQueries({ queryKey: ['session', id] })
        queryClient.invalidateQueries({ queryKey: ['notes', id] })
      }
    })
    return unsub
  }, [id, queryClient])

  if (query.isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-4 w-96" />
        <div className="space-y-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      </div>
    )
  }

  if (!query.data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-muted-foreground gap-4">
        <p className="text-lg font-medium">{t('session.not_found')}</p>
        <Button variant="outline" onClick={() => navigate('/sessions')}>
          {t('session.back')}
        </Button>
      </div>
    )
  }

  const session = query.data
  const isLocked = (session as any).locked as boolean | undefined

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" onClick={() => navigate('/sessions')}>
            <ArrowLeft className="h-4 w-4 mr-1" />
            Sessions
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <Download className="h-4 w-4 mr-2" />
                {t('session.export')}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem onClick={() => window.open(`/api/export/session/${id}?format=json`)}>
                {t('session.export')} as JSON
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => window.open(`/api/export/session/${id}?format=html`)}>
                {t('session.export')} as HTML
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
        <div className="flex items-center gap-2">
          {isLocked ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => unlockMutation.mutate()}
              disabled={unlockMutation.isPending}
            >
              <Unlock className="h-4 w-4 mr-2" />
              Unlock
            </Button>
          ) : (
            <Button
              variant="outline"
              size="sm"
              onClick={() => lockMutation.mutate()}
              disabled={lockMutation.isPending}
            >
              <Lock className="h-4 w-4 mr-2" />
              Lock
            </Button>
          )}
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="destructive" size="sm">
                <Trash2 className="h-4 w-4 mr-2" />
                Delete
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete Session</AlertDialogTitle>
                <AlertDialogDescription>
                  Are you sure you want to delete this session? This action cannot be undone.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={() => deleteMutation.mutate()} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
                  Delete
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </div>

      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight font-mono">{session.ip}</h1>
          <FlagIcon country={session.country_code ?? ''} width={24} height={24} />
          <span className="text-sm text-muted-foreground font-mono">{session.country_code}</span>
          {isLocked && (
            <span className="inline-flex items-center gap-1 text-xs text-amber-500 bg-amber-500/10 px-2 py-0.5 rounded-full">
              <Lock className="h-3 w-3" /> Locked
            </span>
          )}
        </div>
        {screenshotState.status !== 'absent' && screenshotState.status !== 'gone' && id && (
          <button
            type="button"
            onClick={() => setActiveTab('screenshot')}
            className="relative h-12 w-20 overflow-hidden rounded-md border border-border bg-muted hover:opacity-90 transition-opacity shrink-0"
            aria-label={t('session.screenshot')}
          >
            {screenshotState.objectUrl && (
              <img
                src={screenshotState.objectUrl}
                alt=""
                className="h-full w-full object-cover"
              />
            )}
          </button>
        )}
      </div>

      <div className="flex flex-wrap gap-3 text-sm text-muted-foreground">
        <span>HWID: <span className="font-mono text-foreground">{session.hwid ?? '-'}</span></span>
        <span>OS: <span className="font-mono text-foreground">{session.os ?? '-'}</span></span>
        <span>Username: <span className="font-mono text-foreground">{session.username ?? '-'}</span></span>
        <span>Build: <span className="font-mono text-foreground">{session.build_id ?? '-'}</span></span>
        <span>Created: <span className="font-mono text-foreground">{formatDistanceToNow(new Date(session.created_at), { addSuffix: true })}</span></span>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="w-full justify-start bg-muted/60 border border-border p-1">
          <TabsTrigger value="passwords">
            <Key className="h-4 w-4 mr-1" />
            {t("session.passwords")} ({session.passwords?.length ?? 0})
          </TabsTrigger>
          <TabsTrigger value="cookies">
            <Cookie className="h-4 w-4 mr-1" />
            {t("session.cookies")} ({session.cookies?.length ?? 0})
          </TabsTrigger>
          <TabsTrigger value="cards">
            <CreditCard className="h-4 w-4 mr-1" />
            {t("session.cards")} ({session.cards?.length ?? 0})
          </TabsTrigger>
          <TabsTrigger value="wallets">
            <Wallet className="h-4 w-4 mr-1" />
            {t("session.wallets")} ({session.wallets?.length ?? 0})
          </TabsTrigger>
          <TabsTrigger value="files">
            <FileText className="h-4 w-4 mr-1" />
            {t("session.files")} ({session.files?.length ?? 0})
          </TabsTrigger>
          <TabsTrigger value="system">
            <Monitor className="h-4 w-4 mr-1" />
            {t('session.system')}
          </TabsTrigger>
          <TabsTrigger value="screenshot">
            <Image className="h-4 w-4 mr-1" />
            {t('session.screenshot')}
          </TabsTrigger>
          <TabsTrigger value="notes">
            <MessageSquare className="h-4 w-4 mr-1" />
            Notes
          </TabsTrigger>
        </TabsList>

        <TabsContent value="passwords">
          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-8">#</TableHead>
                    <TableHead>{t('table.url')}</TableHead>
                    <TableHead>{t('table.username')}</TableHead>
                    <TableHead>{t('table.password')}</TableHead>
                    <TableHead>{t('table.browser')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {session.passwords?.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-muted-foreground">
                        {t('session.no_passwords')}
                      </TableCell>
                    </TableRow>
                  ) : (
                    session.passwords?.map((pwd, i) => (
                      <TableRow key={pwd.id}>
                        <TableCell className="text-muted-foreground text-xs">{i + 1}</TableCell>
                        <TableCell className="max-w-xs truncate font-mono text-xs">{pwd.url ?? '-'}</TableCell>
                        <TableCell className="font-mono text-xs">{pwd.username ?? '-'}</TableCell>
                        <TableCell className="font-mono text-xs">
                          <div className="flex items-center gap-2">
                            <span className="font-mono">
                              {revealed.has(pwd.id) ? (pwd.password_value ?? '') : '••••••••'}
                            </span>
                            <button
                              onClick={() => toggleReveal(pwd.id)}
                              className="text-muted-foreground hover:text-foreground"
                            >
                              {revealed.has(pwd.id) ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                            </button>
                          </div>
                        </TableCell>
                        <TableCell className="text-xs">{pwd.browser ?? '-'}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="cookies">
          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-8">#</TableHead>
                    <TableHead>{t('table.domain')}</TableHead>
                    <TableHead>{t('table.name')}</TableHead>
                    <TableHead>{t('table.value')}</TableHead>
                    <TableHead>{t('table.path')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {session.cookies?.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-muted-foreground">
                        {t('session.no_cookies')}
                      </TableCell>
                    </TableRow>
                  ) : (
                    session.cookies?.map((ck, i) => (
                      <TableRow key={ck.id}>
                        <TableCell className="text-muted-foreground text-xs">{i + 1}</TableCell>
                        <TableCell className="font-mono text-xs">{ck.domain ?? '-'}</TableCell>
                        <TableCell className="font-mono text-xs max-w-[200px] truncate">{ck.name ?? '-'}</TableCell>
                        <TableCell className="font-mono text-xs max-w-[300px] truncate">{ck.value ?? '-'}</TableCell>
                        <TableCell className="font-mono text-xs">{ck.path ?? '-'}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="cards">
          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-8">#</TableHead>
                    <TableHead>{t('table.number')}</TableHead>
                    <TableHead>{t('table.expires')}</TableHead>
                    <TableHead>{t('table.holder')}</TableHead>
                    <TableHead>{t('table.cvc')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {session.cards?.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-muted-foreground">
                        {t('session.no_cards')}
                      </TableCell>
                    </TableRow>
                  ) : (
                    session.cards?.map((cd, i) => (
                      <TableRow key={cd.id}>
                        <TableCell className="text-muted-foreground text-xs">{i + 1}</TableCell>
                        <TableCell className="font-mono text-xs">{cd.number ? `•••• •••• •••• ${cd.number.slice(-4)}` : '-'}</TableCell>
                        <TableCell className="text-xs">{cd.exp_month && cd.exp_year ? `${cd.exp_month}/${cd.exp_year}` : '-'}</TableCell>
                         <TableCell className="text-xs">{cd.holder ?? '-'}</TableCell>
                         <TableCell className="font-mono text-xs">
                           {cd.cvc ? (
                             <button
                               onClick={() => setRevealed(prev => {
                                 const next = new Set(prev)
                                 next.has(`cvc-${cd.id}`) ? next.delete(`cvc-${cd.id}`) : next.add(`cvc-${cd.id}`)
                                 return next
                               })}
                               className="inline-flex items-center gap-1 hover:text-foreground"
                             >
                               {revealed.has(`cvc-${cd.id}`) ? cd.cvc : '•••'}
                               {revealed.has(`cvc-${cd.id}`) ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                             </button>
                           ) : '-'}
                         </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="wallets">
          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-8">#</TableHead>
                    <TableHead>{t('table.name')}</TableHead>
                    <TableHead>{t('table.path')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {session.wallets?.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={3} className="h-24 text-center text-muted-foreground">
                        {t('session.no_wallets')}
                      </TableCell>
                    </TableRow>
                  ) : (
                    session.wallets?.map((w, i) => (
                      <TableRow key={w.id}>
                        <TableCell className="text-muted-foreground text-xs">{i + 1}</TableCell>
                        <TableCell className="text-xs">{w.name ?? '-'}</TableCell>
                        <TableCell className="font-mono text-xs">{w.path ?? '-'}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="files">
          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-8">#</TableHead>
                    <TableHead>{t('table.filename')}</TableHead>
                    <TableHead className="text-right">{t('table.size')}</TableHead>
                    <TableHead className="w-12"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {session.files?.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="h-24 text-center text-muted-foreground">
                        {t('session.no_files')}
                      </TableCell>
                    </TableRow>
                  ) : (
                    session.files?.map((f, i) => (
                      <TableRow key={f.id}>
                        <TableCell className="text-muted-foreground text-xs">{i + 1}</TableCell>
                        <TableCell className="font-mono text-xs">{f.filename ?? '-'}</TableCell>
                        <TableCell className="text-right tabular-nums text-xs">{formatBytes(f.size)}</TableCell>
                        <TableCell className="text-right">
                          <a
                            href={`/api/sessions/${id}/files/${f.id}/download`}
                            className="inline-flex items-center text-muted-foreground hover:text-foreground"
                            title="Download"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <Download className="h-3.5 w-3.5" />
                          </a>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="system">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {session.system_info ? (
              <>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">{t('system.cpu')}</CardTitle>
                    <Server className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.cpu ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">{t('system.gpu')}</CardTitle>
                    <Monitor className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.gpu ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">{t('system.ram')}</CardTitle>
                    <Server className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.ram ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">{t('system.os')}</CardTitle>
                    <Monitor className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.os ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">{t('system.screen')}</CardTitle>
                    <Monitor className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.screen ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">{t('system.hostname')}</CardTitle>
                    <Server className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.hostname ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">{t('system.local_ip')}</CardTitle>
                    <Server className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.local_ip ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">{t('system.mac')}</CardTitle>
                    <Server className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.mac ?? '-'}</p>
                  </CardContent>
                </Card>
              </>
            ) : (
              <div className="col-span-full text-center text-muted-foreground py-8">
                {t('session.no_system')}
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="screenshot">
          <Card>
            <CardContent className="pt-6">
              {screenshotState.status === 'loading' ? (
                <Skeleton className="w-full aspect-video rounded-md" />
              ) : screenshotState.status === 'gone' ? (
                <div className="text-sm text-muted-foreground">{t('session.screenshot_missing')}</div>
              ) : screenshotState.status === 'absent' ? (
                <div className="text-sm text-muted-foreground">{t('session.no_screenshot')}</div>
              ) : (
                <div className="space-y-3">
                  <div className="relative w-full overflow-hidden rounded-md border border-border bg-muted">
                    {screenshotState.objectUrl && (
                      <img
                        src={screenshotState.objectUrl}
                        alt={t('session.screenshot')}
                        className="w-full h-auto block"
                      />
                    )}
                  </div>
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <div className="font-mono">
                      {screenshotState.width}×{screenshotState.height} · {screenshotState.sizeKb} KB
                    </div>
                    <a
                      href={screenshotState.objectUrl ?? '#'}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 hover:text-foreground"
                      download={`screenshot-${id}.bmp`}
                    >
                      <Download className="h-3 w-3" /> {t('session.screenshot_open')}
                    </a>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="notes">
          <Card>
            <CardContent className="space-y-4 pt-6">
              <div className="flex gap-2">
                <textarea
                  className="flex min-h-[80px] w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                  placeholder={t('session.add_note')}
                  value={newNote}
                  onChange={e => setNewNote(e.target.value)}
                />
                <Button
                  className="self-end"
                  size="sm"
                  onClick={() => addNoteMutation.mutate(newNote)}
                  disabled={!newNote.trim() || addNoteMutation.isPending}
                >
                  Add Note
                </Button>
              </div>

              {notesQuery.isLoading ? (
                <div className="space-y-2">
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                </div>
              ) : notesQuery.data?.length === 0 ? (
                <p className="text-center text-muted-foreground py-4">{t('session.no_notes')}</p>
              ) : (
                <div className="space-y-2">
                  {notesQuery.data?.map(note => (
                    <div key={note.id} className="flex items-start justify-between rounded-md border p-3">
                      <div className="space-y-1 flex-1 min-w-0">
                        <p className="text-sm whitespace-pre-wrap break-words">{note.content}</p>
                        <p className="text-xs text-muted-foreground">
                          {note.created_by} &middot; {formatDistanceToNow(new Date(note.created_at), { addSuffix: true })}
                        </p>
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="ml-2 shrink-0"
                        onClick={() => deleteNoteMutation.mutate(note.id)}
                        disabled={deleteNoteMutation.isPending}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
