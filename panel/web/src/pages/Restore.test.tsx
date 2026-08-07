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
import Restore from './Restore'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const renderPage = () =>
  render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter>
        <I18nProvider>
          <Restore />
        </I18nProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )

const mockResult = {
  session_id: 'abc123',
  proxy: 'socks5://user:pass@host:1080',
  count: 2,
  cookies: [
    { domain: 'example.com', name: 'session', value: 'tok', path: '/' },
    { domain: 'test.org', name: 'user', value: 'admin', path: '/' },
  ],
}

describe('Restore', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    ;(api.post as ReturnType<typeof vi.fn>).mockResolvedValue(mockResult)
  })

  it('renders title and form inputs', () => {
    renderPage()
    expect(screen.getByText('Cookie Restore')).toBeInTheDocument()
    expect(screen.getByText('Restore Configuration')).toBeInTheDocument()
    expect(screen.getByLabelText('Session ID')).toBeInTheDocument()
    expect(screen.getByLabelText('Proxy')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Start Restore' })).toBeInTheDocument()
  })

  it('button is disabled when inputs are empty', () => {
    renderPage()
    const btn = screen.getByRole('button', { name: 'Start Restore' })
    expect(btn).toBeDisabled()
  })

  it('button is enabled when both inputs are filled', () => {
    renderPage()
    fireEvent.change(screen.getByLabelText('Session ID'), { target: { value: 'abc123' } })
    fireEvent.change(screen.getByLabelText('Proxy'), { target: { value: 'socks5://host:1080' } })
    expect(screen.getByRole('button', { name: 'Start Restore' })).toBeEnabled()
  })

  it('calls api.post on restore and shows results', async () => {
    renderPage()
    fireEvent.change(screen.getByLabelText('Session ID'), { target: { value: 'abc123' } })
    fireEvent.change(screen.getByLabelText('Proxy'), { target: { value: 'socks5://host:1080' } })
    fireEvent.click(screen.getByRole('button', { name: 'Start Restore' }))

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/api/restore/cookies', {
        session_id: 'abc123',
        proxy: 'socks5://host:1080',
      })
    })

    await waitFor(() => {
      expect(screen.getByText('Progress: 2 cookie(s)')).toBeInTheDocument()
      expect(screen.getByText('example.com')).toBeInTheDocument()
      expect(screen.getByText('session')).toBeInTheDocument()
      expect(screen.getByText('test.org')).toBeInTheDocument()
      expect(screen.getByText('user')).toBeInTheDocument()
    })
  })

  it('shows loading spinner while restoring', async () => {
    let resolve: (v: unknown) => void
    ;(api.post as ReturnType<typeof vi.fn>).mockReturnValue(new Promise((r) => { resolve = r }))

    renderPage()
    fireEvent.change(screen.getByLabelText('Session ID'), { target: { value: 'abc123' } })
    fireEvent.change(screen.getByLabelText('Proxy'), { target: { value: 'socks5://host:1080' } })
    fireEvent.click(screen.getByRole('button', { name: 'Start Restore' }))

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Start Restore/ })).toBeDisabled()
    })

    resolve!(mockResult)
  })

  it('shows error card on failure', async () => {
    ;(api.post as ReturnType<typeof vi.fn>).mockRejectedValue({ error: 'Invalid session' })

    renderPage()
    fireEvent.change(screen.getByLabelText('Session ID'), { target: { value: 'abc123' } })
    fireEvent.change(screen.getByLabelText('Proxy'), { target: { value: 'socks5://host:1080' } })
    fireEvent.click(screen.getByRole('button', { name: 'Start Restore' }))

    await waitFor(() => {
      expect(screen.getByText('Invalid session')).toBeInTheDocument()
    })
  })

  it('shows generic error message when error has no message', async () => {
    ;(api.post as ReturnType<typeof vi.fn>).mockRejectedValue({})

    renderPage()
    fireEvent.change(screen.getByLabelText('Session ID'), { target: { value: 'abc123' } })
    fireEvent.change(screen.getByLabelText('Proxy'), { target: { value: 'socks5://host:1080' } })
    fireEvent.click(screen.getByRole('button', { name: 'Start Restore' }))

    await waitFor(() => {
      expect(screen.getByText('Restore failed')).toBeInTheDocument()
    })
  })

  it('shows no cookies message when result has zero cookies', async () => {
    ;(api.post as ReturnType<typeof vi.fn>).mockResolvedValue({
      session_id: 'abc',
      proxy: '',
      count: 0,
      cookies: [],
    })

    renderPage()
    fireEvent.change(screen.getByLabelText('Session ID'), { target: { value: 'abc123' } })
    fireEvent.change(screen.getByLabelText('Proxy'), { target: { value: 'socks5://host:1080' } })
    fireEvent.click(screen.getByRole('button', { name: 'Start Restore' }))

    await waitFor(() => {
      expect(screen.getByText('No cookies found for this session.')).toBeInTheDocument()
    })
  })
})