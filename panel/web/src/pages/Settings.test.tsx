import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { I18nProvider } from '@/lib/i18n'

vi.mock('@/lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), fetchCsrf: vi.fn().mockResolvedValue(null), clearCsrf: vi.fn() },
}))

const { mockTheme } = vi.hoisted(() => ({
  mockTheme: { theme: 'light', toggle: vi.fn(), setTheme: vi.fn() },
}))

vi.mock('@/lib/theme-provider', () => ({ useTheme: () => mockTheme }))
vi.mock('@/components/totp-setup', () => ({ TotpSetupCard: () => null }))

import { api } from '@/lib/api'
import Settings from './Settings'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const renderPage = () =>
  render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter>
        <I18nProvider>
          <Settings />
        </I18nProvider>
      </MemoryRouter>
    </QueryClientProvider>
  )

const settingsData = {
  settings: { telegram_token: 'tok123', telegram_chat_id: 'chat-1', rate_limit: '250' },
  audit: [
    { id: 'a1', user_id: 'u1', action: 'login', details: 'from ip', created_at: '2026-01-01' },
    { id: 'a2', action: 'logout', ip: '1.2.3.4', created_at: '2026-01-02' },
  ],
}

beforeEach(() => {
  mockTheme.theme = 'light'
  vi.mocked(api.get).mockResolvedValue(settingsData)
  vi.mocked(api.put).mockResolvedValue({ ok: true })
  vi.mocked(api.post).mockResolvedValue({ ok: true })
  // window.location.reload is read-only in jsdom; swap the whole location object
  Object.defineProperty(window, 'location', {
    configurable: true,
    writable: true,
    value: { href: 'http://localhost/', reload: vi.fn() },
  })
  localStorage.clear()
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('Settings', () => {
  it('shows a loading spinner while settings load', () => {
    const { promise } = Promise.withResolvers<unknown>()
    vi.mocked(api.get).mockReturnValue(promise as never)
    renderPage()
    expect(document.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('renders current settings and audit entries from api.get', async () => {
    renderPage()
    expect(await screen.findByDisplayValue('tok123')).toBeInTheDocument()
    expect(screen.getByDisplayValue('chat-1')).toBeInTheDocument()
    expect(screen.getByDisplayValue('250')).toBeInTheDocument()
    expect(vi.mocked(api.get)).toHaveBeenCalledWith('/api/settings')
    const table = screen.getByRole('table')
    expect(within(table).getByText('login')).toBeInTheDocument()
    expect(within(table).getByText('u1')).toBeInTheDocument()
    expect(within(table).getByText('from ip')).toBeInTheDocument()
    expect(within(table).getByText('logout')).toBeInTheDocument()
    expect(within(table).getByText('1.2.3.4')).toBeInTheDocument()
  })

  it('does not render the audit card when there is no audit data', async () => {
    vi.mocked(api.get).mockResolvedValue({ settings: { telegram_token: '', telegram_chat_id: '', rate_limit: '100' }, audit: [] })
    renderPage()
    await waitFor(() => expect(screen.queryByText('login')).not.toBeInTheDocument())
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('saves edited settings via api.put and shows success', async () => {
    renderPage()
    const tokenInput = await screen.findByLabelText(/Telegram Bot Token/)
    fireEvent.change(tokenInput, { target: { value: 'newtoken' } })
    fireEvent.change(screen.getByLabelText(/Telegram Chat ID/), { target: { value: 'newchat' } })
    fireEvent.change(screen.getByLabelText('Rate Limit'), { target: { value: '500' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(vi.mocked(api.put)).toHaveBeenCalledWith('/api/settings', {
        telegram_token: 'newtoken',
        telegram_chat_id: 'newchat',
        rate_limit: '500',
      })
    )
    expect(await screen.findByText('Saved!')).toBeInTheDocument()
  })

  it('shows an error message when saving fails', async () => {
    vi.mocked(api.put).mockRejectedValue(new Error('nope'))
    renderPage()
    await screen.findByDisplayValue('tok123')
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Failed to save')).toBeInTheDocument()
  })

  it('sends a telegram test request', async () => {
    renderPage()
    await screen.findByDisplayValue('tok123')
    fireEvent.click(screen.getByRole('button', { name: 'Test' }))
    await waitFor(() =>
      expect(vi.mocked(api.post)).toHaveBeenCalledWith('/api/settings/telegram/test', { token: 'tok123', chat_id: 'chat-1' })
    )
  })

  it('toggles to dark theme from the appearance card', async () => {
    mockTheme.theme = 'light'
    renderPage()
    await screen.findByDisplayValue('tok123')
    fireEvent.click(screen.getByRole('button', { name: /Dark/ }))
    expect(mockTheme.toggle).toHaveBeenCalled()
  })

  it('toggles to light theme when already dark', async () => {
    mockTheme.theme = 'dark'
    renderPage()
    await screen.findByDisplayValue('tok123')
    fireEvent.click(screen.getByRole('button', { name: /Light/ }))
    expect(mockTheme.toggle).toHaveBeenCalled()
  })

  it('switches language and reloads the window', async () => {
    renderPage()
    await screen.findByDisplayValue('tok123')
    fireEvent.click(screen.getByRole('button', { name: 'Русский' }))
    expect(window.location.reload).toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'English' }))
    expect(window.location.reload).toHaveBeenCalledTimes(2)
  })
})
