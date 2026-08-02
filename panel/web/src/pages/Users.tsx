import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Copy, Check, Users as UsersIcon, Loader2 } from 'lucide-react'
import { useI18n } from '@/lib/i18n'

interface UserRecord {
    id: string; username: string; role: string; tier: string; created_at: string
}

interface InviteResponse {
    code: string
}

export default function UsersPage() {
    const [role, setRole] = useState('worker')
    const [tier, setTier] = useState('starter')
    const [maxUses, setMaxUses] = useState(5)
    const [inviteCode, setInviteCode] = useState('')
    const [copied, setCopied] = useState(false)
    const { t } = useI18n()

    const usersQuery = useQuery({
        queryKey: ['users'],
        queryFn: () => api.get<UserRecord[]>('/api/users'),
    })

    const inviteMutation = useMutation({
        mutationFn: () => api.post<InviteResponse>('/api/users/invite', { role, tier, max_uses: maxUses }),
        onSuccess: (data) => { setInviteCode(data.code) },
    })

    return (
        <div className="space-y-6">
            <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2"><UsersIcon className="h-5 w-5" />{t("users.title")}</h1>

            <Card>
                <CardHeader><CardTitle className="text-sm font-medium">{t("users.title")}</CardTitle></CardHeader>
                <CardContent>
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>{t("auth.username")}</TableHead>
                                <TableHead>{t('users.role')}</TableHead>
                                <TableHead>{t('users.tier')}</TableHead>
                                <TableHead>{t('common.created')}</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {usersQuery.data?.map(u => (
                                <TableRow key={u.id}>
                                    <TableCell className="font-mono text-xs">{u.username}</TableCell>
                                    <TableCell>{u.role}</TableCell>
                                    <TableCell className="capitalize">{u.tier}</TableCell>
                                    <TableCell className="text-xs text-muted-foreground">{u.created_at}</TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>

            <Card>
                <CardHeader><CardTitle className="text-sm font-medium">{t("users.invite")}</CardTitle></CardHeader>
                <CardContent className="space-y-4">
                    <div className="flex gap-4 items-end">
                        <div className="space-y-2">
                            <Label>{t('users.role')}</Label>
                            <select className="h-10 rounded-md border border-input bg-background px-3 text-sm" value={role} onChange={e => setRole(e.target.value)}>
                                <option value="worker">Worker</option>
                                <option value="viewer">Viewer</option>
                            </select>
                        </div>
                        <div className="space-y-2">
                            <Label>{t('users.tier')}</Label>
                            <select className="h-10 rounded-md border border-input bg-background px-3 text-sm" value={tier} onChange={e => setTier(e.target.value)}>
                                <option value="starter">Starter</option>
                                <option value="pro">Pro</option>
                                <option value="team">Team</option>
                            </select>
                        </div>
                        <div className="space-y-2">
                            <Label>{t('users.max_uses')}</Label>
                            <Input type="number" min={1} max={100} value={maxUses} onChange={e => setMaxUses(parseInt(e.target.value) || 1)} className="w-20" />
                        </div>
                        <Button onClick={() => inviteMutation.mutate()} disabled={inviteMutation.isPending}>
                            {inviteMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                            {t('users.generate')}
                        </Button>
                    </div>
                    {inviteCode && (
                        <div className="flex items-center gap-2 rounded-md bg-muted p-3">
                            <code className="font-mono text-sm flex-1">{inviteCode}</code>
                            <Button variant="ghost" size="sm" onClick={() => { navigator.clipboard.writeText(inviteCode); setCopied(true); setTimeout(() => setCopied(false), 2000) }}>
                                {copied ? <Check className="h-4 w-4 text-success" /> : <Copy className="h-4 w-4" />}
                            </Button>
                        </div>
                    )}
                </CardContent>
            </Card>
        </div>
    )
}
