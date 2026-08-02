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
import { MessageSquare, Loader2, XCircle } from 'lucide-react'

interface Ticket {
  id: string
  user_id: string
  subject: string
  category: string
  status: string
  created_at: string
  updated_at: string
}

const CATEGORIES = ['bug', 'feature', 'question', 'other']

export default function SupportPage() {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const [subject, setSubject] = useState('')
  const [category, setCategory] = useState('question')

  const ticketsQuery = useQuery<Ticket[]>({
    queryKey: ['tickets'],
    queryFn: () => api.get('/api/support/tickets'),
  })

  const createMutation = useMutation({
    mutationFn: () => api.post('/api/support/tickets', { subject, category }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tickets'] })
      setSubject('')
    },
  })

  const closeMutation = useMutation({
    mutationFn: (id: string) => api.put(`/api/support/tickets/${id}/close`, {}),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['tickets'] }),
  })

  const tickets = ticketsQuery.data ?? []

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
        <MessageSquare className="h-5 w-5" />{t('support.title')}
      </h1>

      <Card>
        <CardHeader><CardTitle>{t('support.new_ticket')}</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="ticket-subject">{t('support.subject')}</Label>
              <Input id="ticket-subject" value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Describe your issue" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ticket-category">{t('support.category')}</Label>
              <select
                id="ticket-category"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                {CATEGORIES.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>
          </div>
          <Button onClick={() => createMutation.mutate()} disabled={!subject || createMutation.isPending}>
            {createMutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
            {t('support.new_ticket')}
          </Button>
        </CardContent>
      </Card>

      {ticketsQuery.isLoading ? (
        <Skeleton className="h-48" />
      ) : tickets.length === 0 ? (
        <p className="text-muted-foreground text-center py-8">{t('support.no_tickets')}</p>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('support.subject')}</TableHead>
                  <TableHead>{t('support.category')}</TableHead>
                  <TableHead>{t('common.status')}</TableHead>
                  <TableHead>{t('common.created')}</TableHead>
                  <TableHead className="w-12"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tickets.map((ticket) => (
                  <TableRow key={ticket.id}>
                    <TableCell className="font-medium">{ticket.subject}</TableCell>
                    <TableCell>
                      <span className="inline-block px-2 py-0.5 rounded text-xs bg-muted">{ticket.category}</span>
                    </TableCell>
                    <TableCell>
                      <span className={`inline-block px-2 py-0.5 rounded text-xs ${ticket.status === 'closed' ? 'bg-muted text-muted-foreground' : 'bg-primary/10 text-primary'}`}>
                        {ticket.status}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{ticket.created_at}</TableCell>
                    <TableCell>
                      {ticket.status !== 'closed' && (
                        <Button variant="ghost" size="sm" onClick={() => closeMutation.mutate(ticket.id)} disabled={closeMutation.isPending}>
                          <XCircle className="h-4 w-4 text-muted-foreground" />
                        </Button>
                      )}
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
