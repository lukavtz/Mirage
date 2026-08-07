import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import App, { router } from '@/App'
import { api } from '@/lib/api'
import { wsClient } from '@/lib/ws'

vi.mock('@/lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), fetchCsrf: vi.fn(), clearCsrf: vi.fn() },
}))
vi.mock('@/lib/ws', () => ({
  wsClient: { connect: vi.fn(), disconnect: vi.fn(), on: vi.fn(), off: vi.fn(), ping: vi.fn() },
}))

const PUBLIC_STATS = {
  total_sessions: 900,
  today_sessions: 56,
  total_passwords: 100,
  total_wallets: 20,
  total_cookies: 30,
  total_cards: 5,
  crypto_logs_pct: 12.3,
  duplicates_pct: 1.5,
  country_distribution: [],
  browser_distribution: [],
  timeline: [],
}

function mockApi() {
  vi.mocked(api.get).mockImplementation((path: string) => {
    if (path === '/api/auth/me') return Promise.resolve({ user_id: 'u1', username: 'v0lk', role: 'operator' })
    if (path === '/api/public/stats') return Promise.resolve(PUBLIC_STATS)
    if (path === '/api/stats') {
      return Promise.resolve({
        sessions: { total: 0, today: 0, yesterday: 0, change: 0 },
        passwords: { total: 0, today: 0, change: 0 },
        cookies: { total: 0, today: 0, change: 0 },
        wallets: { total: 0 },
        countries: 0,
        geo: [],
        duplicates: { hwid: 0, ip: 0 },
        quality: { percentage: 0, valid: 0 },
      })
    }
    if (path === '/api/system/health') return Promise.resolve({ status: 'ok' })
    if (path === '/api/sessions') return Promise.resolve({ items: [], total: 0 })
    return Promise.resolve({})
  })
}

beforeEach(async () => {
  vi.clearAllMocks()
  localStorage.clear()
  sessionStorage.clear()
  mockApi()
  await router.navigate('/')
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('App', () => {
  it('redirects unauthenticated users to the login page', async () => {
    render(<App />)
    expect(await screen.findByText('Welcome back')).toBeInTheDocument()
    expect(screen.getByText('Username')).toBeInTheDocument()
  })

  it('renders PublicStatsPage at /public', async () => {
    render(<App />)
    await screen.findByText('Welcome back')

    await router.navigate('/public')
    expect(await screen.findByText('Mirage — Public Statistics')).toBeInTheDocument()
    expect(screen.getByText('900')).toBeInTheDocument()
  })

  it('renders RefundPolicy at /refund', async () => {
    render(<App />)
    await screen.findByText('Welcome back')

    await router.navigate('/refund')
    expect(await screen.findByText('Refund Policy')).toBeInTheDocument()
    expect(screen.getByText('Monthly Subscriptions')).toBeInTheDocument()
  })

  it('shows 404 NotFound for an unknown route when authenticated', async () => {
    localStorage.setItem('token', 'tok123')
    render(<App />)

    expect(await screen.findByText('No data yet — waiting for first log')).toBeInTheDocument()

    await router.navigate('/zzz')
    expect(await screen.findByText('404')).toBeInTheDocument()
    expect(screen.getByText('Page not found')).toBeInTheDocument()
  })

  it('renders the dashboard shell for an authenticated user', async () => {
    localStorage.setItem('token', 'tok123')
    render(<App />)

    expect(await screen.findByText('No data yet — waiting for first log')).toBeInTheDocument()
    // topbar shows the authenticated user
    expect(await screen.findByText('v0lk')).toBeInTheDocument()
    // ProtectedRoute connects the websocket with the stored token
    expect(wsClient.connect).toHaveBeenCalledWith('tok123')
  })
})
