import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { Users as UsersIcon, Shield, Trash2, Loader2 } from 'lucide-react'
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
      <h1 className="text-2xl font-bold flex items-center gap-2"><UsersIcon className="h-5 w-5" />Team</h1>

      <div className="flex items-center gap-2">
        <select
          value={roleFilter}
          onChange={(e) => setRoleFilter(e.target.value)}
          className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm"
        >
          <option value="">All roles</option>
          <option value="admin">Admin</option>
          <option value="worker">Worker</option>
          <option value="viewer">Viewer</option>
        </select>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">Team Members</CardTitle></CardHeader>
        <CardContent>
          {isLoading ? <Skeleton className="h-64" /> : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Username</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Active</TableHead>
                  <TableHead>Sessions</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(members ?? []).length === 0 ? (
                  <TableRow><TableCell colSpan={6} className="h-24 text-center text-muted-foreground">No members</TableCell></TableRow>
                ) : (members ?? []).map(m => (
                  <TableRow key={m.id}>
                    <TableCell className="font-mono text-xs">{m.username}</TableCell>
                    <TableCell><span className={`text-xs px-2 py-0.5 rounded-full ${m.role === 'admin' ? 'bg-purple-500/20 text-purple-400' : 'bg-blue-500/20 text-blue-400'}`}>{m.role}</span></TableCell>
                    <TableCell><span className={`inline-block w-2 h-2 rounded-full ${m.status === 'online' ? 'bg-emerald-500' : 'bg-gray-500'}`} /> {m.status}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{m.last_login ?? 'Never'}</TableCell>
                    <TableCell>{m.sessions}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="sm" onClick={() => { setRoleTarget(m); setNewRole(m.role) }}>
                          <Shield className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => setRemoveTarget(m)}>
                          <Trash2 className="h-4 w-4 text-red-400" />
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
            <AlertDialogTitle>Remove member</AlertDialogTitle>
            <AlertDialogDescription>
              Remove {removeTarget?.username} from the team? This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
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
            <DialogTitle>Change role — {roleTarget?.username}</DialogTitle>
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
            <Button variant="outline" onClick={() => setRoleTarget(null)}>Cancel</Button>
            <Button onClick={() => roleTarget && roleMutation.mutate({ id: roleTarget.id, role: newRole })}>
              {roleMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
