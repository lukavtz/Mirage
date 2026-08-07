import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { useDashboard } from './use-dashboard'

// -- mocks --
const { apiGet, wsHandlers, wsOff } = vi.hoisted(() => {
  const handlers = new Map<string, (data: unknown) => void>()
  return {
    apiGet: vi.fn(),
    wsHandlers: handlers,
    wsOff: vi.fn(),
  }
})

vi.mock('@/lib/api', () => ({
  api: { get: apiGet },
}))

vi.mock('@/lib/ws', () => ({
  wsClient: {
    on: vi.fn((type: string, handler: (data: unknown) => void) => {
      wsHandlers.set(type, handler)
      return () => wsHandlers.delete(type)
    }),
    off: wsOff,
    connect: vi.fn(),
    disconnect: vi.fn(),
  },
}))

// -- helpers --
function createQueryClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function renderWithClient(el: ReactNode) {
  const qc = createQueryClient()
  return {
    qc,
    ...render(<QueryClientProvider client={qc}>{el}</QueryClientProvider>),
  }
}

function DashboardProbe() {
  const { stats, health } = useDashboard()
  return (
    <div>
      <span data-testid="stats-loading">{String(stats.isLoading)}</span>
      <span data-testid="stats-sessions">{stats.data?.sessions?.total ?? 'none'}</span>
      <span data-testid="health-loading">{String(health.isLoading)}</span>
      <span data-testid="health-status">{health.data?.status ?? 'none'}</span>
    </div>
  )
}

// -- tests --
describe('useDashboard', () => {
  beforeEach(() => {
    wsHandlers.clear()
    vi.clearAllMocks()

    apiGet.mockImplementation((url: string) => {
      if (url === '/api/stats') return Promise.resolve({ sessions: { total: 3 }, countries: 2, geo: [], browsers: [], os_distribution: [], timeline: [], top_domains: [], passwords: { count: 10 }, cookies: { count: 5 }, cards: { count: 1 }, wallets: { count: 0 }, duplicates: { count: 0 }, quality: { score: 0.8 } })
      if (url === '/api/system/health') return Promise.resolve({ status: 'ok', goroutines: 5, mem_alloc_mb: 10, mem_sys_mb: 20, mem_heap_mb: 8, gc_cycles: 100 })
      return Promise.resolve({})
    })
  })

  afterEach(() => {
    wsHandlers.clear()
  })

  it('renders with loading true initially and shows data after resolve', async () => {
    renderWithClient(<DashboardProbe />)

    expect(screen.getByTestId('stats-loading')).toHaveTextContent('true')
    expect(screen.getByTestId('health-loading')).toHaveTextContent('true')

    await waitFor(() => {
      expect(screen.getByTestId('stats-sessions')).toHaveTextContent('3')
    })
    expect(screen.getByTestId('health-status')).toHaveTextContent('ok')
  })

  it('calls api.get again after stats_update ws event', async () => {
    renderWithClient(<DashboardProbe />)
    await waitFor(() => expect(screen.getByTestId('stats-sessions')).toHaveTextContent('3'))
    apiGet.mockClear()

    const handler = wsHandlers.get('stats_update')
    expect(handler).toBeDefined()
    handler!({})

    await waitFor(() => {
      expect(apiGet).toHaveBeenCalledWith('/api/stats')
    })
  })

  it('calls api.get again after new_session ws event', async () => {
    renderWithClient(<DashboardProbe />)
    await waitFor(() => expect(screen.getByTestId('stats-sessions')).toHaveTextContent('3'))
    apiGet.mockClear()

    const handler = wsHandlers.get('new_session')
    expect(handler).toBeDefined()
    handler!({})

    await waitFor(() => {
      expect(apiGet).toHaveBeenCalledWith('/api/stats')
    })
  })

  it('unmount cleans up wsClient.off', () => {
    const { unmount } = renderWithClient(<DashboardProbe />)

    unmount()

    expect(wsOff).toHaveBeenCalledWith('stats_update', expect.any(Function))
    expect(wsOff).toHaveBeenCalledWith('new_session', expect.any(Function))
  })
})