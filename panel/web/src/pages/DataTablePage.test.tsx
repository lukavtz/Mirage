import { describe, it, expect, vi, beforeEach } from 'vitest'
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

import { api } from '@/lib/api'
import DataTablePage, { type DataType } from './DataTablePage'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })

const renderPage = (type: DataType = 'passwords') =>
  render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter>
        <I18nProvider>
          <DataTablePage type={type} />
        </I18nProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )

const passwordPage = {
  items: [
    {
      id: 'p1',
      session_id: 's1',
      url: 'https://example.com/login',
      username: 'alice',
      password_value: 'hunter2',
      browser: 'Chrome',
      country_code: 'US',
      ip: '1.2.3.4',
      created_at: '2026-01-01T00:00:00Z',
    },
  ],
  total: 42,
  page: 1,
  limit: 50,
  pages: 2,
}

const cardPage = {
  items: [
    {
      id: 'c1',
      session_id: 's1',
      number: '4111111111111234',
      exp_month: '12',
      exp_year: '28',
      holder: 'Alice Doe',
      cvc: '123',
      country_code: 'US',
      ip: '1.2.3.4',
      created_at: '2026-01-01T00:00:00Z',
    },
  ],
  total: 7,
  page: 1,
  limit: 50,
  pages: 1,
}

const lastDataCall = (path: string) => {
  const calls = vi.mocked(api.get).mock.calls
  return calls.filter(c => c[0] === path).at(-1)
}

beforeEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
  vi.mocked(api.get).mockResolvedValue(passwordPage)
})

describe('DataTablePage', () => {
  it('renders the passwords table with headers and row data', async () => {
    renderPage('passwords')
    expect(await screen.findByText('https://example.com/login')).toBeInTheDocument()
    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(screen.getByText('Chrome')).toBeInTheDocument()
    expect(screen.getByText('URL')).toBeInTheDocument()
    expect(screen.getByText('Password')).toBeInTheDocument()
    expect(screen.getByText('42 total')).toBeInTheDocument()
    // password is masked until revealed
    expect(screen.getByText('••••••••')).toBeInTheDocument()
    expect(screen.queryByText('hunter2')).not.toBeInTheDocument()
  })

  it('reveals the password on the per-row eye toggle', async () => {
    renderPage('passwords')
    await screen.findByText('alice')
    fireEvent.click(screen.getByRole('button', { name: 'Show password' }))
    expect(await screen.findByText('hunter2')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Hide password' })).toBeInTheDocument()
  })

  it('masks card numbers and reveals them on click', async () => {
    vi.mocked(api.get).mockResolvedValue(cardPage)
    renderPage('cards')
    expect(await screen.findByText('•••• •••• •••• 1234')).toBeInTheDocument()
    expect(screen.getByText('12/28')).toBeInTheDocument()
    expect(screen.queryByText('4111111111111234')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Reveal card number' }))
    expect(await screen.findByText('4111111111111234')).toBeInTheDocument()
  })

  it('shows the empty state when there are no items', async () => {
    vi.mocked(api.get).mockResolvedValue({ ...passwordPage, items: [], total: 0, pages: 1 })
    renderPage('passwords')
    expect(await screen.findByText('No data')).toBeInTheDocument()
  })

  it('includes a CSV export button for the current page', async () => {
    renderPage('passwords')
    await screen.findByText('alice')
    expect(screen.getByRole('button', { name: 'Export CSV' })).toBeInTheDocument()
  })

  it('fetches the next page when the next button is clicked', async () => {
    renderPage('passwords')
    await screen.findByText('alice')
    const next = document.querySelector('.lucide-chevron-right')!.closest('button')!
    fireEvent.click(next)
    await waitFor(() => {
      expect(lastDataCall('/api/data/passwords')?.[1]).toMatchObject({ page: 2 })
    })
  })

  it('searches after the debounce', async () => {
    renderPage('passwords')
    await screen.findByText('alice')
    fireEvent.change(screen.getByPlaceholderText('Search...'), {
      target: { value: 'example' },
    })
    await waitFor(
      () => {
        expect(lastDataCall('/api/data/passwords')?.[1]).toMatchObject({ q: 'example' })
      },
      { timeout: 2000 },
    )
  })
})
