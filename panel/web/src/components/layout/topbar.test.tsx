import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { I18nProvider } from '@/lib/i18n'
import { ThemeProvider } from '@/lib/theme-provider'
import { AuthProvider } from '@/hooks/use-auth'

vi.mock('@/lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), fetchCsrf: vi.fn().mockResolvedValue(null), clearCsrf: vi.fn() },
}))

import { api } from '@/lib/api'
import { Topbar } from './topbar'

const makeQC = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })

function renderTopbar(props: { onToggleMobileSidebar?: () => void } = {}) {
  return render(
    <MemoryRouter>
      <I18nProvider>
        <ThemeProvider>
          <AuthProvider>
            <QueryClientProvider client={makeQC()}>
              <Topbar {...props} />
            </QueryClientProvider>
          </AuthProvider>
        </ThemeProvider>
      </I18nProvider>
    </MemoryRouter>,
  )
}

function findButtonByIcon(iconClass: string): HTMLButtonElement {
  const btn = document.querySelector(`button svg.${iconClass}`)?.closest('button') as HTMLButtonElement
  expect(btn).toBeTruthy()
  return btn
}

describe('Topbar', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    vi.clearAllMocks()
    vi.mocked(api.get).mockResolvedValue(undefined)
    vi.mocked(api.fetchCsrf).mockResolvedValue(null)
  })

  it('renders the default admin user when the user query returns nothing', async () => {
    renderTopbar()
    await waitFor(() => {
      expect(screen.getAllByText('admin').length).toBeGreaterThanOrEqual(2)
    })
    // avatar letter derived from username, shown twice (desktop + mobile trigger)
    expect(screen.getAllByText('A').length).toBe(2)
  })

  it('renders the real username and role from api.get /api/auth/me', async () => {
    vi.mocked(api.get).mockResolvedValue({ user_id: 'u1', username: 'v0lk', role: 'operator' })
    renderTopbar()
    expect(await screen.findByText('v0lk')).toBeInTheDocument()
    expect(screen.getByText('operator')).toBeInTheDocument()
    expect(screen.getAllByText('V').length).toBe(2)
    expect(vi.mocked(api.get)).toHaveBeenCalledWith('/api/auth/me')
  })

  it('flips the language en -> ru -> en on the language button', () => {
    renderTopbar()
    expect(screen.getByText('EN')).toBeInTheDocument()
    fireEvent.click(screen.getByTitle('Switch to Russian'))
    expect(localStorage.getItem('lang')).toBe('ru')
    expect(screen.getByText('RU')).toBeInTheDocument()
    expect(screen.getByTitle('English')).toBeInTheDocument()
    fireEvent.click(screen.getByTitle('English'))
    expect(localStorage.getItem('lang')).toBe('en')
    expect(screen.getByText('EN')).toBeInTheDocument()
  })

  it('toggles the theme and updates data-theme on the document root', () => {
    renderTopbar()
    // default theme is dark -> sun icon shown
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    fireEvent.click(findButtonByIcon('lucide-sun'))
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(document.querySelector('svg.lucide-moon')).toBeTruthy()
    fireEvent.click(findButtonByIcon('lucide-moon'))
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('logs out from the dropdown menu and clears the stored token', async () => {
    localStorage.setItem('token', 'tok123')
    vi.mocked(api.get).mockResolvedValue({ user_id: 'u1', username: 'v0lk', role: 'admin' })
    renderTopbar()
    await screen.findByText('v0lk')

    fireEvent.pointerDown(screen.getByRole('button', { name: 'V' }), { button: 0 })
    const item = await screen.findByRole('menuitem', { name: 'Logout' })
    fireEvent.click(item)

    await waitFor(() => {
      expect(localStorage.getItem('token')).toBeNull()
    })
    expect(sessionStorage.getItem('token')).toBeNull()
    expect(vi.mocked(api.clearCsrf)).toHaveBeenCalled()
  })

  it('logs out via the desktop logout button', async () => {
    vi.mocked(api.get).mockResolvedValue({ user_id: 'u1', username: 'v0lk', role: 'admin' })
    renderTopbar()
    await screen.findByText('v0lk')
    fireEvent.click(findButtonByIcon('lucide-log-out'))
    expect(vi.mocked(api.clearCsrf)).toHaveBeenCalled()
  })

  it('fires onToggleMobileSidebar when the mobile menu button is clicked', () => {
    const onToggle = vi.fn()
    renderTopbar({ onToggleMobileSidebar: onToggle })
    fireEvent.click(findButtonByIcon('lucide-menu'))
    expect(onToggle).toHaveBeenCalledTimes(1)
  })

  it('does not render the mobile menu button without the callback', () => {
    renderTopbar()
    expect(document.querySelector('svg.lucide-menu')).toBeNull()
  })
})
