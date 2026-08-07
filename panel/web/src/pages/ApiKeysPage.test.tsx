import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { I18nProvider } from '@/lib/i18n'

vi.mock('@/lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), fetchCsrf: vi.fn().mockResolvedValue(null), clearCsrf: vi.fn() },
}))

import { api } from '@/lib/api'
import ApiKeysPage from './ApiKeysPage'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const renderPage = () =>
  render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter>
        <I18nProvider>
          <ApiKeysPage />
        </I18nProvider>
      </MemoryRouter>
    </QueryClientProvider>
  )

const keys = [
  { id: 'k1', name: 'ci-key', scope: 'read', rate_limit: 100, created_at: '2026-01-01' },
  { id: 'k2', name: 'admin-key', scope: 'admin', rate_limit: 500, created_at: '2026-02-01' },
]

beforeEach(() => {
  vi.mocked(api.get).mockResolvedValue({ keys })
  vi.mocked(api.post).mockResolvedValue({ id: 'new1', key: 'sk_live_abc123' })
  vi.mocked(api.del).mockResolvedValue({ ok: true })
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
    configurable: true,
  })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('ApiKeysPage', () => {
  it('shows a skeleton while keys load', () => {
    const { promise } = Promise.withResolvers<unknown>()
    vi.mocked(api.get).mockReturnValue(promise as never)
    renderPage()
    expect(screen.getByRole('heading', { name: 'API Keys' })).toBeInTheDocument()
    expect(document.querySelector('.h-48')).toBeInTheDocument()
  })

  it('renders the list of api keys', async () => {
    renderPage()
    const table = await screen.findByRole('table')
    expect(within(table).getByText('ci-key')).toBeInTheDocument()
    expect(within(table).getByText('admin-key')).toBeInTheDocument()
    expect(within(table).getByText('read')).toBeInTheDocument()
    expect(within(table).getByText('admin')).toBeInTheDocument()
    expect(within(table).getByText('500')).toBeInTheDocument()
    expect(vi.mocked(api.get)).toHaveBeenCalledWith('/api/keys')
  })

  it('shows the empty state when there are no keys', async () => {
    vi.mocked(api.get).mockResolvedValue({ keys: [] })
    renderPage()
    expect(await screen.findByText('No API keys yet')).toBeInTheDocument()
  })

  it('shows an error query state without crashing', async () => {
    vi.mocked(api.get).mockRejectedValue(new Error('boom'))
    renderPage()
    await waitFor(() => expect(vi.mocked(api.get)).toHaveBeenCalledWith('/api/keys'))
    expect(screen.getByRole('heading', { name: 'API Keys' })).toBeInTheDocument()
  })

  it('creates an api key and reveals/copies it', async () => {
    renderPage()
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'my key' } })
    fireEvent.change(screen.getByLabelText('Scope'), { target: { value: 'write' } })
    fireEvent.change(screen.getByLabelText('Rate Limit'), { target: { value: '250' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create API Key' }))
    await waitFor(() =>
      expect(vi.mocked(api.post)).toHaveBeenCalledWith('/api/keys', { name: 'my key', scope: 'write', rate_limit: 250 })
    )
    // created key shown masked
    const masked = await screen.findByText('•'.repeat(40))
    const box = masked.closest('div') as HTMLElement
    // toggle reveal (icon-only button)
    fireEvent.click(within(box).getAllByRole('button')[0])
    expect(screen.getByText('sk_live_abc123')).toBeInTheDocument()
    // copy (button with text)
    fireEvent.click(within(box).getByRole('button', { name: 'Copy' }))
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('sk_live_abc123')
  })

  it('does not create a key without a name', async () => {
    renderPage()
    await screen.findByText('ci-key')
    fireEvent.click(screen.getByRole('button', { name: 'Create API Key' }))
    expect(vi.mocked(api.post)).not.toHaveBeenCalled()
  })

  it('revokes a key via api.del', async () => {
    renderPage()
    const table = await screen.findByRole('table')
    fireEvent.click(within(table).getAllByRole('button')[0])
    await waitFor(() => expect(vi.mocked(api.del)).toHaveBeenCalledWith('/api/keys/k1'))
  })
})
