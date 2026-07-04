import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Search as SearchIcon, Key, Cookie, CreditCard } from 'lucide-react'
import { t } from '@/lib/i18n'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { api } from '@/lib/api'

interface SearchResult {
  type: string; session_id: string; field1?: string; field2?: string
  field3?: string; field4?: string; matched_field?: string
}

interface SearchResponse {
  results: SearchResult[]; total: number; page: number; limit: number; pages: number
}

const typeIcons: Record<string, typeof Key> = {
  password: Key, cookie: Cookie, card: CreditCard,
}

const typeLabels: Record<string, string> = {
  password: 'Password', cookie: 'Cookie', card: 'Credit Card',
}

export default function SearchPage() {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [debounced, setDebounced] = useState('')
  const [type, setType] = useState('all')
  const [page, setPage] = useState(1)

  useEffect(() => {
    const t = setTimeout(() => { setDebounced(query); setPage(1) }, 300)
    return () => clearTimeout(t)
  }, [query])

  const { data, isLoading } = useQuery<SearchResponse>({
    queryKey: ['search', debounced, type, page],
    queryFn: () => api.get<SearchResponse>('/api/search', { q: debounced, type: type === 'all' ? undefined : type, page, limit: 50 }),
    enabled: debounced.length >= 2,
    placeholderData: (prev) => prev,
  })

  function highlight(text: string | undefined | null, query: string) {
    if (!text || !query) return text ?? '—'
    const idx = text.toLowerCase().indexOf(query.toLowerCase())
    if (idx === -1) return text
    return (
      <>
        {text.slice(0, idx)}
        <mark className="bg-yellow-500/20 text-foreground rounded-sm px-0.5">{text.slice(idx, idx + query.length)}</mark>
        {text.slice(idx + query.length)}
      </>
    )
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">{t('search.title')}</h1>

      <div className="flex gap-2">
        <div className="relative flex-1">
          <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            className="pl-9"
            placeholder={t('search.placeholder')}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
          />
        </div>
        <select
          className="h-10 rounded-md border border-input bg-background px-3 text-sm"
          value={type} onChange={(e) => setType(e.target.value)}
        >
          <option value="all">{t('search.all')}</option>
          <option value="passwords">{t('dashboard.passwords')}</option>
          <option value="cookies">{t('dashboard.cookies')}</option>
          <option value="cards">{t('session.cards')}</option>
        </select>
      </div>

      {(isLoading || data) && (
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-24">{t('search.title')}</TableHead>
                <TableHead>URL / Domain</TableHead>
                <TableHead>{t('auth.username')} / Name</TableHead>
                <TableHead>Value</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && Array.from({length: 5}).map((_, i) => (
                <TableRow key={i}><TableCell colSpan={4}><Skeleton className="h-8 w-full" /></TableCell></TableRow>
              ))}
              {data?.results.map((r, i) => {
                const Icon = typeIcons[r.type] ?? Key
                return (
                  <TableRow key={i} className="cursor-pointer" onClick={() => navigate(`/sessions/${r.session_id}`)}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                        <span className="text-xs text-muted-foreground">{typeLabels[r.type]}</span>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{highlight(r.field1, debounced)}</TableCell>
                    <TableCell className="text-xs">{highlight(r.field2, debounced)}</TableCell>
                    <TableCell className="text-xs font-mono max-w-[200px] truncate">{r.type === 'password' ? '••••••••' : highlight(r.field3, debounced)}</TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      )}

      {!isLoading && debounced.length >= 2 && data?.results.length === 0 && (
        <div className="text-center py-12 text-muted-foreground">{t('search.no_results')}</div>
      )}

      {data && data.pages > 1 && (
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">{data.total} results</span>
          <div className="flex gap-1">
            <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Previous</Button>
            <span className="flex items-center px-3 text-sm">Page {page} of {data.pages}</span>
            <Button variant="outline" size="sm" disabled={page >= data.pages} onClick={() => setPage(p => p + 1)}>Next</Button>
          </div>
        </div>
      )}
    </div>
  )
}
