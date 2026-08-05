import { describe, it, expect, vi, beforeEach, afterEach, beforeAll } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { I18nProvider } from '@/lib/i18n'

vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    del: vi.fn(),
    fetchCsrf: vi.fn().mockResolvedValue(null),
    clearCsrf: vi.fn(),
  },
}))

vi.mock('@/lib/ws', () => ({
  wsClient: { on: vi.fn(), off: vi.fn(), connect: vi.fn(), disconnect: vi.fn() },
}))

import { api } from '@/lib/api'
import Dashboard from './Dashboard'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const renderPage = () =>
  render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter>
        <I18nProvider>
          <Dashboard />
        </I18nProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )

const stats = {
  sessions: { total: 1234, today: 12, yesterday: 8, change: 5.2 },
  passwords: { total: 999, today: 10, change: 1 },
  cookies: { total: 888, today: 9, change: -2 },
  cards: { total: 77, today: 3, change: 0 },
  wallets: { total: 44, today: 1, change: 0 },
  duplicates: { hwid: 3, ip: 5 },
  quality: { valid: 950, total: 1000, percentage: 95 },
  countries: 17,
  geo: [
    { country_code: 'US', count: 500 },
    { country_code: 'DE', count: 200 },
  ],
  browsers: [{ browser: 'Chrome', count: 10 }],
  os_distribution: [
    { os: 'Windows 10', count: 700 },
    { os: 'Windows 11', count: 300 },
  ],
  timeline: [{ date: '2026-01-01', count: 5 }],
  top_domains: [{ domain: 'example.com', count: 9 }],
}

const health = {
  status: 'ok',
  goroutines: 5,
  mem_alloc_mb: 10,
  mem_sys_mb: 20,
  mem_heap_mb: 8,
  gc_cycles: 3,
  go_version: '1.22',
}

const sessionsPage = {
  sessions: [
    {
      id: 'abc',
      ip: '9.9.9.9',
      country_code: 'US',
      os: 'Windows 10',
      browser: 'Chrome',
      passwords_count: 4,
      cookies_count: 2,
      wallets_count: 1,
      hwid: 'hw1',
      viewed: false,
      created_at: '2026-01-01T00:00:00Z',
    },
  ],
  total: 12,
  page: 1,
  limit: 5,
  pages: 3,
}

beforeAll(() => {
  Object.defineProperty(URL, 'createObjectURL', {
    configurable: true,
    value: vi.fn(() => 'blob:fake'),
  })
  Object.defineProperty(URL, 'revokeObjectURL', {
    configurable: true,
    value: vi.fn(),
  })
})

beforeEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
  vi.mocked(api.get).mockImplementation((url: string) => {
    if (url === '/api/stats') return Promise.resolve(stats)
    if (url === '/api/system/health') return Promise.resolve(health)
    if (url === '/api/sessions') return Promise.resolve(sessionsPage)
    return Promise.reject(new Error('unexpected: ' + url))
  })
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, blob: async () => new Blob(['x']) }))
})

afterEach(() => {
  vi.unstubAllGlobals()
})

const lastSessionsCall = () => {
  const calls = vi.mocked(api.get).mock.calls
  return calls.filter(c => c[0] === '/api/sessions').at(-1)
}

describe('Dashboard', () => {
  it('shows skeletons while stats are loading', () => {
    const { promise } = Promise.withResolvers<unknown>()
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === '/api/stats') return promise as Promise<never>
      if (url === '/api/system/health') return Promise.resolve(health)
      return Promise.resolve(sessionsPage)
    })
    const { container } = renderPage()
    expect(container.querySelectorAll('[class*="h-[104px]"]')).toHaveLength(8)
    expect(container.querySelector('[class*="h-[400px]"]')).toBeTruthy()
    expect(screen.queryByText('Latest Logs')).toBeNull()
  })

  it('renders KPI cards and the latest logs table', async () => {
    renderPage()
    // Numeric values use toLocaleString(), so assert locale-independent texts.
    expect(await screen.findByText('Total Logs')).toBeInTheDocument()
    expect(screen.getByText('New Today')).toBeInTheDocument()
    expect(screen.getByText('Quality')).toBeInTheDocument()
    // 'Passwords'/'Cookies'/'Wallets' appear both as KPI labels and table headers.
    expect(screen.getAllByText('Passwords').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('Countries')).toBeInTheDocument()
    expect(screen.getAllByText('Cookies').length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('Wallets').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('Duplicates')).toBeInTheDocument()
    expect(screen.getAllByText('+5.2%').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('-2.0%')).toBeInTheDocument()
    expect(screen.getByText('95%')).toBeInTheDocument()
    expect(screen.getByText('999')).toBeInTheDocument()
    expect(screen.getByText('888')).toBeInTheDocument()
    expect(screen.getByText('17')).toBeInTheDocument()
    expect(screen.getByText('8')).toBeInTheDocument()
    expect(screen.getByText('Latest Logs')).toBeInTheDocument()
    expect(screen.getByText('9.9.9.9')).toBeInTheDocument()
    expect(screen.getByText('12 total')).toBeInTheDocument()
    expect(screen.getByText(/Showing 1–5 of 12/)).toBeInTheDocument()
    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
  })

  it('shows the no-data view when there are zero sessions', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === '/api/stats') return Promise.resolve({ ...stats, sessions: { ...stats.sessions, total: 0 } })
      if (url === '/api/system/health') return Promise.resolve(health)
      return Promise.resolve(sessionsPage)
    })
    renderPage()
    expect(await screen.findByText('No data yet — waiting for first log')).toBeInTheDocument()
  })

  it('falls back to skeletons when stats fail to load', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === '/api/stats') return Promise.reject(new Error('stats down'))
      if (url === '/api/system/health') return Promise.resolve(health)
      return Promise.resolve(sessionsPage)
    })
    const { container } = renderPage()
    await waitFor(() => {
      expect(container.querySelectorAll('[class*="h-[104px]"]')).toHaveLength(8)
    })
  })

  it('refetches sessions when typing in the search box', async () => {
    renderPage()
    await screen.findByText('9.9.9.9')
    fireEvent.change(screen.getByPlaceholderText('Search IP, HWID, OS, country...'), {
      target: { value: '9.9.9.9' },
    })
    await waitFor(() => {
      expect(lastSessionsCall()?.[1]).toMatchObject({ q: '9.9.9.9' })
    })
  })

  it('filters sessions by country and OS', async () => {
    renderPage()
    await screen.findByText('9.9.9.9')
    const [countrySelect, osSelect] = screen.getAllByRole('combobox')
    fireEvent.change(countrySelect, { target: { value: 'US' } })
    await waitFor(() => {
      expect(lastSessionsCall()?.[1]).toMatchObject({ country: 'US' })
    })
    fireEvent.change(osSelect, { target: { value: 'Windows 11' } })
    await waitFor(() => {
      expect(lastSessionsCall()?.[1]).toMatchObject({ os: 'Windows 11' })
    })
  })

  it('toggles the unviewed-only checkbox', async () => {
    renderPage()
    await screen.findByText('9.9.9.9')
    fireEvent.click(screen.getByText('Unviewed only'))
    await waitFor(() => {
      expect(lastSessionsCall()?.[1]).toMatchObject({ unviewed_only: true })
    })
  })

  it('paginates to the next page', async () => {
    renderPage()
    await screen.findByText('9.9.9.9')
    fireEvent.click(document.querySelector('.lucide-chevron-right')!.closest('button')!)
    await waitFor(() => {
      expect(lastSessionsCall()?.[1]).toMatchObject({ page: 2 })
    })
  })

  it('changes the page size', async () => {
    renderPage()
    await screen.findByText('9.9.9.9')
    const sizeSelect = screen.getAllByRole('combobox')[2]
    fireEvent.change(sizeSelect, { target: { value: '25' } })
    await waitFor(() => {
      expect(lastSessionsCall()?.[1]).toMatchObject({ limit: 25 })
    })
  })

  it('exports a single session row as JSON', async () => {
    renderPage()
    await screen.findByText('9.9.9.9')
    const jsonBtn = screen.getAllByRole('button', { name: 'JSON' })[0]
    fireEvent.click(jsonBtn)
    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        '/api/export/session/abc?format=json',
        expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer null' }) }),
      )
    })
  })

  it('selects rows and exports them in bulk', async () => {
    renderPage()
    await screen.findByText('9.9.9.9')
    // Checkbox order: [0] unviewed-only, [1] header select-all, [2] row.
    const rowCheckbox = screen.getAllByRole('checkbox')[2]
    // Click the cell (the td's onClick toggles selection once; clicking the
    // checkbox itself would also bubble to the td and cancel the toggle).
    fireEvent.click(rowCheckbox.closest('td')!)
    await waitFor(() => {
      expect(screen.getAllByRole('button', { name: 'JSON' })).toHaveLength(2)
    })
    // First JSON button lives in the CardHeader (bulk export).
    const bulkJson = screen.getAllByRole('button', { name: 'JSON' })[0]
    fireEvent.click(bulkJson)
    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        '/api/export/bulk',
        expect.objectContaining({ body: JSON.stringify({ session_ids: ['abc'], format: 'json' }) }),
      )
    })
  })

  it('selects and deselects all rows via the header checkbox', async () => {
    renderPage()
    await screen.findByText('9.9.9.9')
    // [0] unviewed-only, [1] header select-all, [2] row.
    const headerCheckbox = screen.getAllByRole('checkbox')[1]
    const rowCheckbox = () => screen.getAllByRole('checkbox')[2]
    fireEvent.click(headerCheckbox)
    expect(rowCheckbox()).toBeChecked()
    fireEvent.click(headerCheckbox)
    expect(rowCheckbox()).not.toBeChecked()
  })

  it('clears all filters with the reset button', async () => {
    renderPage()
    await screen.findByText('9.9.9.9')
    fireEvent.change(screen.getByPlaceholderText('Search IP, HWID, OS, country...'), {
      target: { value: 'foo' },
    })
    await waitFor(() => {
      expect(lastSessionsCall()?.[1]).toMatchObject({ q: 'foo' })
    })
    fireEvent.click(document.querySelector('.lucide-x')!.closest('button')!)
    await waitFor(() => {
      expect((lastSessionsCall()?.[1] as Record<string, unknown>)?.q).toBeUndefined()
    })
  })
})
