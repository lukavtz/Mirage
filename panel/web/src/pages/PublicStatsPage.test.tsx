import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { I18nProvider } from '@/lib/i18n'
import PublicStatsPage from './PublicStatsPage'
import { api } from '@/lib/api'

vi.mock('@/lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), fetchCsrf: vi.fn(), clearCsrf: vi.fn() },
}))

const STATS = {
  total_sessions: 900,
  today_sessions: 56,
  total_passwords: 987,
  total_wallets: 42,
  total_cookies: 333,
  total_cards: 7,
  crypto_logs_pct: 12.34,
  duplicates_pct: 1.5,
  country_distribution: [
    { country: 'US', count: 100 },
    { country: 'DE', count: 50 },
  ],
  browser_distribution: [
    { browser: 'Chrome', count: 80 },
    { browser: 'Firefox', count: 20 },
  ],
  timeline: [
    { date: '2026-07-01', count: 5 },
    { date: '2026-07-02', count: 7 },
    { date: '2026-07-03', count: 3 },
    { date: '2026-07-04', count: 9 },
    { date: '2026-07-05', count: 11 },
    { date: '2026-07-06', count: 4 },
  ],
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <I18nProvider>
        <MemoryRouter>
          <PublicStatsPage />
        </MemoryRouter>
      </I18nProvider>
    </QueryClientProvider>
  )
}

describe('PublicStatsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows a skeleton while loading', () => {
    const { promise } = Promise.withResolvers<void>()
    vi.mocked(api.get).mockReturnValue(promise as never)
    const { container } = renderPage()
    expect(container.querySelector('.animate-pulse')).not.toBeNull()
  })

  it('renders stats with charts and distribution data', async () => {
    vi.mocked(api.get).mockResolvedValue(STATS)
    renderPage()

    expect(await screen.findByText('Mirage — Public Statistics')).toBeInTheDocument()
    expect(screen.getByText('Total Sessions')).toBeInTheDocument()
    expect(screen.getByText('900')).toBeInTheDocument()
    expect(screen.getByText('+56 today')).toBeInTheDocument()
    expect(screen.getByText('987')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('333')).toBeInTheDocument()
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(screen.getByText('12.3%')).toBeInTheDocument()
    expect(screen.getByText('1.5%')).toBeInTheDocument()
    // country distribution
    expect(screen.getByText('United States')).toBeInTheDocument()
    expect(screen.getByText('Germany')).toBeInTheDocument()
    // browser distribution
    expect(screen.getByText('Chrome')).toBeInTheDocument()
    expect(screen.getByText('Firefox')).toBeInTheDocument()
    expect(vi.mocked(api.get)).toHaveBeenCalledWith('/api/public/stats')
  })

  it('shows "No data" placeholders when all distributions are empty', async () => {
    vi.mocked(api.get).mockResolvedValue({
      ...STATS,
      timeline: [],
      country_distribution: [],
      browser_distribution: [],
    })
    renderPage()

    expect(await screen.findAllByText('No data')).toHaveLength(3)
  })

  it('shows disabled message when the request fails', async () => {
    vi.mocked(api.get).mockRejectedValue(new Error('boom'))
    renderPage()
    // the hook sets retry: 1 with default backoff, so the error lands after the retry delay
    expect(await screen.findByText('Public stats are not enabled', {}, { timeout: 5000 })).toBeInTheDocument()
  })

  it('shows disabled message when the response is empty', async () => {
    vi.mocked(api.get).mockResolvedValue(undefined)
    renderPage()
    expect(await screen.findByText('Public stats are not enabled')).toBeInTheDocument()
  })
})
