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
import TeamPage from './TeamPage'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const renderPage = () =>
  render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter>
        <I18nProvider>
          <TeamPage />
        </I18nProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )

const mockMembers = [
  { id: '1', username: 'alice', role: 'admin', status: 'online', last_login: '2025-01-01T00:00:00Z', sessions: 5, created_at: '2024-01-01T00:00:00Z' },
  { id: '2', username: 'bob', role: 'worker', status: 'offline', last_login: null, sessions: 2, created_at: '2024-06-01T00:00:00Z' },
  { id: '3', username: 'charlie', role: 'viewer', status: 'online', last_login: '2025-02-01T00:00:00Z', sessions: 0, created_at: '2024-03-01T00:00:00Z' },
]

describe('TeamPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    ;(api.get as ReturnType<typeof vi.fn>).mockResolvedValue(mockMembers)
  })

  it('renders title and role filter', () => {
    renderPage()
    expect(screen.getByText('Team')).toBeInTheDocument()
    expect(screen.getByDisplayValue('All roles')).toBeInTheDocument()
  })

  it('shows loading skeleton initially', () => {
    ;(api.get as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}))
    renderPage()
    const skeleton = document.querySelector('.animate-pulse')
    expect(skeleton).toBeInTheDocument()
  })

  it('renders team members in table', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('alice')).toBeInTheDocument()
      expect(screen.getByText('bob')).toBeInTheDocument()
      expect(screen.getByText('charlie')).toBeInTheDocument()
    })

    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('worker')).toBeInTheDocument()
    expect(screen.getByText('viewer')).toBeInTheDocument()
    const onlineEls = screen.getAllByText('online')
    expect(onlineEls.length).toBe(2)
    expect(screen.getByText('offline')).toBeInTheDocument()
  })

  it('shows "never" for null last_login', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Never')).toBeInTheDocument()
    })
  })

  it('shows empty state when no members', async () => {
    ;(api.get as ReturnType<typeof vi.fn>).mockResolvedValue([])
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('No members')).toBeInTheDocument()
    })
  })

  it('filters by role', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('alice')).toBeInTheDocument()
    })

    const select = screen.getByDisplayValue('All roles')
    fireEvent.change(select, { target: { value: 'admin' } })

    await waitFor(() => {
      expect(api.get).toHaveBeenCalledWith('/api/team', { role: 'admin' })
    })
  })

  it('opens remove dialog and confirms removal', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('alice')).toBeInTheDocument()
    })

    const deleteButtons = screen.getAllByRole('button', { name: '' })
    const trashButton = deleteButtons.find(
      (btn) => btn.querySelector('svg')?.getAttribute('class')?.includes('text-destructive'),
    )
    fireEvent.click(trashButton!)

    await waitFor(() => {
      expect(screen.getByText('Remove member')).toBeInTheDocument()
    })

    const removeBtn = screen.getByText('Remove')
    fireEvent.click(removeBtn)

    await waitFor(() => {
      expect(api.del).toHaveBeenCalledWith('/api/team/1')
    })
  })

  it('opens role dialog and changes role', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('alice')).toBeInTheDocument()
    })

    // Find the shield button (Shield icon) for the first member
    const shieldButtons = screen.getAllByRole('button', { name: '' })
    const shieldBtn = shieldButtons.find(
      (btn) => btn.querySelector('svg.lucide-shield') !== null,
    )
    fireEvent.click(shieldBtn!)

    await waitFor(() => {
      expect(screen.getByText('Change role — alice')).toBeInTheDocument()
    })

    // Find the role select in the dialog and change it
    // Actually use the dialog role select - there should be exactly 2 selects
    // (role filter + dialog role select)
    const allSelects = document.querySelectorAll('select')
    const dialogSelect = allSelects[allSelects.length - 1] // Last one is the dialog
    fireEvent.change(dialogSelect, { target: { value: 'viewer' } })

    const saveBtn = screen.getByText('Save')
    fireEvent.click(saveBtn)

    await waitFor(() => {
      expect(api.put).toHaveBeenCalledWith('/api/team/1/role', { role: 'viewer' })
    })
  })
})
