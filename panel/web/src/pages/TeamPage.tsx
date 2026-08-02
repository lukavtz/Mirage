import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { Users as UsersIcon, Shield, Trash2, Loader2 } from 'lucide-react'
import { useI18n } from '@/lib/i18n'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog'

interface TeamMember {
  id: string; username: string; role: string
  status: string; last_login: string | null
  sessions: number; created_at: string
}

export default function TeamPage() {
  const queryClient = useQueryClient()
  const { t } = useI18n()
  const [roleFilter, setRoleFilter] = useState('')
  const [removeTarget, setRemoveTarget] = useState<TeamMember | null>(null)
  const [roleTarget, setRoleTarget] = useState<TeamMember | null>(null)
  const [newRole, setNewRole] = useState('worker')

  const { data: members, isLoading } = useQuery({
    queryKey: ['team', roleFilter],
    queryFn: () => api.get<TeamMember[]>('/api/team', roleFilter ? { role: roleFilter } : undefined),
  })

  const removeMutation = useMutation({
    mutationFn: (id: string) => api.del(`/api/team/${id}`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['team'] }); setRemoveTarget(null) },
  })

  const roleMutation = useMutation({
    mutationFn: ({ id, role }: { id: string; role: string }) => api.put(`/api/team/${id}/role`, { role }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['team'] }); setRoleTarget(null) },
  })

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2"><UsersIcon className="h-5 w-5" />{t('team.title')}</h1>

      <div className="flex items-center gap-2">
        <select
          value={roleFilter}
          onChange={(e) => setRoleFilter(e.target.value)}
          className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm"
        >
          <option value="">{t('team.all_roles')}</option>
          <option value="admin">Admin</option>
          <option value="worker">Worker</option>
          <option value="viewer">Viewer</option>
        </select>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">{t('team.members')}</CardTitle></CardHeader>
        <CardContent>
          {isLoading ? <Skeleton className="h-64" /> : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('table.username')}</TableHead>
                  <TableHead>{t('users.role')}</TableHead>
                  <TableHead>{t('team.status')}</TableHead>
                  <TableHead>{t('team.last_active')}</TableHead>
                  <TableHead>{t('team.sessions')}</TableHead>
                  <TableHead className="text-right">{t('common.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(members ?? []).length === 0 ? (
                  <TableRow><TableCell colSpan={6} className="h-24 text-center text-muted-foreground">{t('team.no_members')}</TableCell></TableRow>
                ) : (members ?? []).map(m => (
                  <TableRow key={m.id}>
                    <TableCell className="font-mono text-xs">{m.username}</TableCell>
                    <TableCell><span className={`text-xs px-2 py-0.5 rounded-full ${m.role === 'admin' ? 'bg-brand-500/20 text-brand-400' : 'bg-brand-400/20 text-brand-400'}`}>{m.role}</span></TableCell>
                    <TableCell><span className={`inline-block w-2 h-2 rounded-full ${m.status === 'online' ? 'bg-success' : 'bg-muted-foreground'}`} /> {m.status}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{m.last_login ?? t('team.never')}</TableCell>
                    <TableCell>{m.sessions}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="sm" onClick={() => { setRoleTarget(m); setNewRole(m.role) }}>
                          <Shield className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => setRemoveTarget(m)}>
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={!!removeTarget} onOpenChange={() => setRemoveTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('team.remove_title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('team.remove_confirm', { name: removeTarget?.username ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={() => removeTarget && removeMutation.mutate(removeTarget.id)}>
              {removeMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <Dialog open={!!roleTarget} onOpenChange={() => setRoleTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('team.change_role', { name: roleTarget?.username ?? '' })}</DialogTitle>
          </DialogHeader>
          <div className="py-4">
            <select
              value={newRole}
              onChange={(e) => setNewRole(e.target.value)}
              className="w-full h-10 rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="admin">Admin</option>
              <option value="worker">Worker</option>
              <option value="viewer">Viewer</option>
            </select>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRoleTarget(null)}>{t('common.cancel')}</Button>
            <Button onClick={() => roleTarget && roleMutation.mutate({ id: roleTarget.id, role: newRole })}>
              {roleMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              {t('common.save')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
