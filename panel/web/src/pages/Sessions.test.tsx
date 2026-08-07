import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
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

import { api } from '@/lib/api'
import Sessions from './Sessions'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })

function LocationProbe() {
  const loc = useLocation()
  return <div data-testid="loc">{loc.pathname}</div>
}

const renderPage = (initial = '/') =>
  render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter initialEntries={[initial]}>
        <I18nProvider>
          <Sessions />
          <LocationProbe />
        </I18nProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )

const sessionPage = {
  sessions: [
    {
      id: 's1',
      ip: '1.2.3.4',
      country_code: 'US',
      os: 'Windows 10',
      username: 'user1',
      hwid: 'hwid-1234567890',
      passwords_count: 5,
      cookies_count: 3,
      cards_count: 1,
      wallets_count: 0,
      created_at: '2026-01-01T00:00:00Z',
    },
  ],
  total: 42,
  page: 1,
  limit: 50,
  pages: 2,
}

const lastSessionsCall = () => {
  const calls = vi.mocked(api.get).mock.calls
  return calls.filter(c => c[0] === '/api/sessions').at(-1)
}

beforeEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
  vi.mocked(api.get).mockResolvedValue(sessionPage)
})

describe('Sessions', () => {
  it('shows a loading skeleton while fetching', () => {
    const { promise } = Promise.withResolvers<unknown>()
    vi.mocked(api.get).mockReturnValue(promise as Promise<never>)
    const { container } = renderPage()
    expect(screen.getByText('Sessions')).toBeInTheDocument()
    expect(container.querySelector('.h-96')).toBeTruthy()
  })

  it('renders session rows, showing text and pagination info', async () => {
    renderPage()
    expect(await screen.findByText('1.2.3.4')).toBeInTheDocument()
    expect(screen.getByText('user1')).toBeInTheDocument()
    expect(screen.getByText('Showing 1 of 42 sessions')).toBeInTheDocument()
    expect(screen.getByText('Page 1 of 2')).toBeInTheDocument()
  })

  it('shows the empty state when there are no sessions', async () => {
    vi.mocked(api.get).mockResolvedValue({ ...sessionPage, sessions: [], total: 0 })
    renderPage()
    expect(await screen.findByText('No sessions yet')).toBeInTheDocument()
  })

  it('does not crash when the request fails', async () => {
    vi.mocked(api.get).mockRejectedValue(new Error('boom'))
    renderPage()
    expect(await screen.findByText('No sessions yet')).toBeInTheDocument()
  })

  it('fetches the next page when clicking the next button', async () => {
    renderPage()
    await screen.findByText('1.2.3.4')
    const next = document.querySelector('.lucide-chevron-right')!.closest('button')!
    fireEvent.click(next)
    await waitFor(() => {
      expect(lastSessionsCall()?.[1]).toMatchObject({ page: 2 })
    })
  })

  it('applies date presets and sends date_from/date_to', async () => {
    renderPage()
    await screen.findByText('1.2.3.4')
    const dateSelect = screen.getAllByRole('combobox')[0]
    for (const preset of ['today', 'yesterday', '7d', '30d']) {
      fireEvent.change(dateSelect, { target: { value: preset } })
      await waitFor(() => {
        const params = lastSessionsCall()?.[1] as Record<string, unknown> | undefined
        expect(typeof params?.date_from).toBe('string')
      })
    }
  })

  it('filters by country', async () => {
    renderPage()
    await screen.findByText('1.2.3.4')
    const countrySelect = screen.getAllByRole('combobox')[1]
    fireEvent.change(countrySelect, { target: { value: 'RU' } })
    await waitFor(() => {
      expect(lastSessionsCall()?.[1]).toMatchObject({ country: 'RU' })
    })
  })

  it('searches after the debounce', async () => {
    renderPage()
    await screen.findByText('1.2.3.4')
    fireEvent.change(screen.getByPlaceholderText('Search IP, HWID, OS...'), {
      target: { value: 'user1' },
    })
    await waitFor(
      () => {
        expect(lastSessionsCall()?.[1]).toMatchObject({ q: 'user1' })
      },
      { timeout: 2000 },
    )
  })

  it('toggles the hide-empty filter', async () => {
    renderPage()
    await screen.findByText('1.2.3.4')
    fireEvent.click(screen.getByRole('button', { name: 'Hide empty' }))
    await waitFor(() => {
      expect(lastSessionsCall()?.[1]).toMatchObject({ empty_only: true })
    })
    fireEvent.click(screen.getByRole('button', { name: 'Show all' }))
    await waitFor(() => {
      expect((lastSessionsCall()?.[1] as Record<string, unknown>)?.empty_only).toBeUndefined()
    })
  })

  it('toggles blurred values', async () => {
    renderPage()
    await screen.findByText('1.2.3.4')
    const blurBtn = document.querySelector('.lucide-eye')!.closest('button')!
    fireEvent.click(blurBtn)
    await waitFor(() => {
      expect(document.querySelector('.blur-sm')).toBeTruthy()
    })
  })

  it('shows the coming-soon view for clippers', () => {
    renderPage('/clippers')
    expect(screen.getByText('This feature is coming soon')).toBeInTheDocument()
  })

  it('uses the category from the pathname for the api type', async () => {
    renderPage('/passwords')
    expect(await screen.findByText('1.2.3.4')).toBeInTheDocument()
    expect(lastSessionsCall()?.[1]).toMatchObject({ type: 'password' })
    expect(screen.getByRole('heading', { name: 'Passwords' })).toBeInTheDocument()
  })

  it('toggles column visibility from the settings menu', async () => {
    renderPage()
    await screen.findByText('1.2.3.4')
    const settingsBtn = document.querySelector('.lucide-settings-2')!.closest('button')!
    fireEvent.pointerDown(settingsBtn)
    const item = await screen.findByText('Hwid')
    fireEvent.click(item)
    const saved = JSON.parse(localStorage.getItem('session_columns')!)
    expect(saved.hwid).toBe(false)
  })

  it('sorts by a column header', async () => {
    renderPage()
    await screen.findByText('1.2.3.4')
    fireEvent.click(screen.getByText('IP Address'))
    await waitFor(() => {
      expect(lastSessionsCall()?.[1]).toMatchObject({ sort: 'ip' })
    })
  })

  it('navigates to the session detail on row click', async () => {
    renderPage()
    const cell = await screen.findByText('1.2.3.4')
    fireEvent.click(cell.closest('tr')!)
    await waitFor(() => {
      expect(screen.getByTestId('loc').textContent).toBe('/sessions/s1')
    })
  })
})
