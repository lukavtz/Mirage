import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { I18nProvider } from '@/lib/i18n'

vi.mock('@/lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), fetchCsrf: vi.fn().mockResolvedValue(null), clearCsrf: vi.fn() },
}))

import { api } from '@/lib/api'
import UsersPage from './Users'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const renderPage = () =>
  render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter>
        <I18nProvider>
          <UsersPage />
        </I18nProvider>
      </MemoryRouter>
    </QueryClientProvider>
  )

const users = [
  { id: '1', username: 'alice', role: 'worker', tier: 'pro', created_at: '2026-01-01' },
  { id: '2', username: 'bob', role: 'viewer', tier: 'starter', created_at: '2026-02-02' },
]

beforeEach(() => {
  vi.mocked(api.get).mockResolvedValue(users)
  vi.mocked(api.post).mockResolvedValue({ code: 'INVITE-CODE-123' })
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
    configurable: true,
  })
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('UsersPage', () => {
  it('renders the user list from api.get', async () => {
    renderPage()
    await screen.findByText('alice')
    const table = screen.getByRole('table')
    expect(within(table).getByText('alice')).toBeInTheDocument()
    expect(within(table).getByText('bob')).toBeInTheDocument()
    expect(within(table).getByText('worker')).toBeInTheDocument()
    expect(within(table).getByText('pro')).toBeInTheDocument()
    expect(within(table).getByText('starter')).toBeInTheDocument()
    expect(vi.mocked(api.get)).toHaveBeenCalledWith('/api/users')
  })

  it('renders an empty table when there are no users', async () => {
    vi.mocked(api.get).mockResolvedValue([])
    renderPage()
    await waitFor(() => expect(vi.mocked(api.get)).toHaveBeenCalledWith('/api/users'))
    expect(screen.queryByText('alice')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Users' })).toBeInTheDocument()
  })

  it('shows an error query state without crashing', async () => {
    vi.mocked(api.get).mockRejectedValue(new Error('boom'))
    renderPage()
    await waitFor(() => expect(vi.mocked(api.get)).toHaveBeenCalledWith('/api/users'))
    expect(screen.getByRole('heading', { name: 'Users' })).toBeInTheDocument()
  })

  it('generates an invite code with current form values', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Generate' }))
    await screen.findByText('INVITE-CODE-123')
    expect(vi.mocked(api.post)).toHaveBeenCalledWith('/api/users/invite', { role: 'worker', tier: 'starter', max_uses: 5 })

    // change role, tier and max uses then generate again (labels are not associated, query by role)
    const [roleSelect, tierSelect] = screen.getAllByRole('combobox')
    fireEvent.change(roleSelect, { target: { value: 'viewer' } })
    fireEvent.change(tierSelect, { target: { value: 'team' } })
    fireEvent.change(screen.getByRole('spinbutton'), { target: { value: '12' } })
    fireEvent.click(screen.getByRole('button', { name: 'Generate' }))
    await waitFor(() =>
      expect(vi.mocked(api.post)).toHaveBeenLastCalledWith('/api/users/invite', { role: 'viewer', tier: 'team', max_uses: 12 })
    )
  })

  it('copies the invite code to the clipboard', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Generate' }))
    const code = await screen.findByText('INVITE-CODE-123')
    const inviteBox = code.closest('div') as HTMLElement
    fireEvent.click(within(inviteBox).getAllByRole('button')[0])
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('INVITE-CODE-123')
    // let the 2s copied->false timeout fire while mounted
    const { promise, resolve } = Promise.withResolvers<void>()
    setTimeout(resolve, 2100)
    await promise
  })
})
