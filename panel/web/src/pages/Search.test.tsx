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
import SearchPage from './Search'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const renderPage = () =>
  render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter>
        <I18nProvider>
          <SearchPage />
        </I18nProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )

const mockResults = {
  results: [
    { type: 'password', session_id: 's1', field1: 'example.com', field2: 'user1', field3: 'pass1', matched_field: 'field1' },
    { type: 'cookie', session_id: 's2', field1: 'test.org', field2: 'session', field3: 'tok', matched_field: 'field2' },
  ],
  total: 2,
  page: 1,
  limit: 50,
  pages: 1,
}

describe('SearchPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    ;(api.get as ReturnType<typeof vi.fn>).mockResolvedValue(mockResults)
  })

  it('renders search page with title and input', () => {
    renderPage()
    expect(screen.getByText('Search')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Search passwords, cookies, cards...')).toBeInTheDocument()
    expect(screen.getByDisplayValue('All')).toBeInTheDocument()
  })

  it('does not fetch when query is too short', async () => {
    renderPage()
    const input = screen.getByPlaceholderText('Search passwords, cookies, cards...')
    fireEvent.change(input, { target: { value: 'a' } })
    // Wait for debounce to expire
    await new Promise((r) => setTimeout(r, 400))
    expect(api.get).not.toHaveBeenCalled()
  })

  it('fetches search results after debounce when query >= 2 chars', async () => {
    renderPage()
    const input = screen.getByPlaceholderText('Search passwords, cookies, cards...')
    fireEvent.change(input, { target: { value: 'ex' } })
    await waitFor(() => {
      expect(api.get).toHaveBeenCalledWith('/api/search', {
        q: 'ex',
        type: undefined,
        page: 1,
        limit: 50,
      })
    })
  })

  it('renders loading skeletons while fetching', async () => {
    ;(api.get as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}))
    renderPage()
    const input = screen.getByPlaceholderText('Search passwords, cookies, cards...')
    fireEvent.change(input, { target: { value: 'ex' } })

    await waitFor(() => {
      expect(api.get).toHaveBeenCalled()
    })

    const skeletons = document.querySelectorAll('.animate-pulse')
    expect(skeletons.length).toBeGreaterThan(0)
  })

  it('renders search results in table', async () => {
    renderPage()
    const input = screen.getByPlaceholderText('Search passwords, cookies, cards...')
    fireEvent.change(input, { target: { value: 'ex' } })

    await waitFor(() => {
      expect(screen.getByText('Password')).toBeInTheDocument()
      expect(screen.getByText('Cookie')).toBeInTheDocument()
    })
  })

  it('shows no results message when empty', async () => {
    ;(api.get as ReturnType<typeof vi.fn>).mockResolvedValue({
      results: [],
      total: 0,
      page: 1,
      limit: 50,
      pages: 0,
    })

    renderPage()
    const input = screen.getByPlaceholderText('Search passwords, cookies, cards...')
    fireEvent.change(input, { target: { value: 'ex' } })

    await waitFor(() => {
      expect(screen.getByText('No results found')).toBeInTheDocument()
    })
  })

  it('shows pagination when multiple pages', async () => {
    const manyResults = Array.from({ length: 50 }, (_, i) => ({
      type: 'password',
      session_id: `s${i}`,
      field1: `example${i}.com`,
      field2: `user${i}`,
      field3: 'pass',
    }))
    ;(api.get as ReturnType<typeof vi.fn>).mockResolvedValue({
      results: manyResults,
      total: 150,
      page: 1,
      limit: 50,
      pages: 3,
    })

    renderPage()
    const input = screen.getByPlaceholderText('Search passwords, cookies, cards...')
    fireEvent.change(input, { target: { value: 'ex' } })

    await waitFor(() => {
      expect(screen.getByText('150 results')).toBeInTheDocument()
      expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Next'))
    await waitFor(() => {
      expect(api.get).toHaveBeenCalledWith('/api/search', expect.objectContaining({ page: 2 }))
    })
  })

  it('navigates to session on row click', async () => {
    renderPage()
    const input = screen.getByPlaceholderText('Search passwords, cookies, cards...')
    fireEvent.change(input, { target: { value: 'ex' } })

    await waitFor(() => {
      expect(screen.getByText('Password')).toBeInTheDocument()
    })

    const rows = screen.getAllByRole('row')
    fireEvent.click(rows[1])
  })

  it('filters by type', async () => {
    renderPage()
    const input = screen.getByPlaceholderText('Search passwords, cookies, cards...')
    fireEvent.change(input, { target: { value: 'ex' } })

    await waitFor(() => {
      expect(api.get).toHaveBeenCalled()
    })

    const select = screen.getByDisplayValue('All')
    fireEvent.change(select, { target: { value: 'passwords' } })
    await waitFor(() => {
      expect(api.get).toHaveBeenCalledWith('/api/search', expect.objectContaining({ type: 'passwords' }))
    })
  })
})
