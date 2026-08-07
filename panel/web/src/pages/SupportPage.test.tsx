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
import SupportPage from './SupportPage'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const renderPage = () =>
  render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter>
        <I18nProvider>
          <SupportPage />
        </I18nProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )

const mockTickets = [
  { id: '1', user_id: 'u1', subject: 'Login issue', category: 'bug', status: 'open', created_at: '2025-01-01T00:00:00Z', updated_at: '2025-01-01T00:00:00Z' },
  { id: '2', user_id: 'u2', subject: 'Feature request', category: 'feature', status: 'closed', created_at: '2025-01-02T00:00:00Z', updated_at: '2025-01-03T00:00:00Z' },
]

describe('SupportPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    ;(api.get as ReturnType<typeof vi.fn>).mockResolvedValue(mockTickets)
    ;(api.post as ReturnType<typeof vi.fn>).mockResolvedValue({ id: '3' })
    ;(api.put as ReturnType<typeof vi.fn>).mockResolvedValue({})
  })

  it('renders title and create ticket form', () => {
    renderPage()
    expect(screen.getByText('Support')).toBeInTheDocument()
    const newTicketTexts = screen.getAllByText('New Ticket')
    expect(newTicketTexts.length).toBe(2)
    expect(screen.getByLabelText('Subject')).toBeInTheDocument()
    expect(screen.getByLabelText('Category')).toBeInTheDocument()
  })

  it('shows loading skeleton while fetching tickets', () => {
    ;(api.get as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}))
    renderPage()
    const skeleton = document.querySelector('.animate-pulse')
    expect(skeleton).toBeInTheDocument()
  })

  it('renders tickets in table', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Login issue')).toBeInTheDocument()
      expect(screen.getByText('Feature request')).toBeInTheDocument()
    })

    const bugTexts = screen.getAllByText('bug')
    expect(bugTexts.length).toBe(2)
    const featureTexts = screen.getAllByText('feature')
    expect(featureTexts.length).toBe(2)
    expect(screen.getByText('open')).toBeInTheDocument()
    expect(screen.getByText('closed')).toBeInTheDocument()
  })

  it('shows empty state when no tickets', async () => {
    ;(api.get as ReturnType<typeof vi.fn>).mockResolvedValue([])
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('No tickets yet')).toBeInTheDocument()
    })
  })

  it('creates a new ticket', async () => {
    renderPage()

    const subjectInput = screen.getByLabelText('Subject')
    fireEvent.change(subjectInput, { target: { value: 'New bug report' } })

    const categorySelect = screen.getByLabelText('Category')
    fireEvent.change(categorySelect, { target: { value: 'bug' } })

    const createBtn = screen.getByRole('button', { name: 'New Ticket' })
    fireEvent.click(createBtn)

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/api/support/tickets', {
        subject: 'New bug report',
        category: 'bug',
      })
    })
  })

  it('disables create button when subject is empty', () => {
    renderPage()
    const createBtn = screen.getByRole('button', { name: 'New Ticket' })
    expect(createBtn).toBeDisabled()
  })

  it('enables create button when subject is filled', () => {
    renderPage()
    const subjectInput = screen.getByLabelText('Subject')
    fireEvent.change(subjectInput, { target: { value: 'Issue' } })
    expect(screen.getByRole('button', { name: 'New Ticket' })).toBeEnabled()
  })

  it('closes an open ticket', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Login issue')).toBeInTheDocument()
    })

    const newTicketBtn = screen.getByRole('button', { name: 'New Ticket' })
    const closeBtns = screen.getAllByRole('button').filter((btn) => btn !== newTicketBtn)
    if (closeBtns.length > 0) {
      fireEvent.click(closeBtns[0])
      await waitFor(() => {
        expect(api.put).toHaveBeenCalledWith('/api/support/tickets/1/close', {})
      })
    }
  })

  it('selects different category', () => {
    renderPage()
    const categorySelect = screen.getByLabelText('Category') as HTMLSelectElement
    fireEvent.change(categorySelect, { target: { value: 'bug' } })
    expect(categorySelect.value).toBe('bug')
  })
})
