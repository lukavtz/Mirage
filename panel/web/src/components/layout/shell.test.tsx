import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { I18nProvider } from '@/lib/i18n'
import { ThemeProvider } from '@/lib/theme-provider'
import { AuthProvider } from '@/hooks/use-auth'
import { Shell } from './shell'

vi.mock('@/lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), fetchCsrf: vi.fn().mockResolvedValue(null), clearCsrf: vi.fn() },
}))

import { api } from '@/lib/api'

function renderShell() {
  return render(
    <MemoryRouter initialEntries={['/']}>
      <I18nProvider>
        <ThemeProvider>
          <AuthProvider>
            <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
              <Routes>
                <Route path="/" element={<Shell />}>
                  <Route index element={<div>content</div>} />
                </Route>
              </Routes>
            </QueryClientProvider>
          </AuthProvider>
        </ThemeProvider>
      </I18nProvider>
    </MemoryRouter>,
  )
}

describe('Shell', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
    vi.mocked(api.get).mockResolvedValue(undefined)
  })

  it('renders the outlet content, the sidebar and the topbar', () => {
    renderShell()
    expect(screen.getByText('content')).toBeInTheDocument()
    // Sidebar nav
    expect(screen.getByRole('link', { name: 'Dashboard' })).toBeInTheDocument()
    // Topbar language button
    expect(screen.getByTitle('Switch to Russian')).toBeInTheDocument()
    // Topbar default user
    expect(screen.getAllByText('admin').length).toBeGreaterThanOrEqual(2)
  })

  it('opens and closes the mobile sidebar via the topbar toggle', async () => {
    renderShell()
    const menuBtn = document.querySelector('button svg.lucide-menu')?.closest('button') as HTMLButtonElement
    expect(menuBtn).toBeTruthy()

    // open
    fireEvent.click(menuBtn)
    expect(await screen.findByLabelText('Close')).toBeInTheDocument()

    // close via the backdrop
    fireEvent.click(screen.getByLabelText('Close'))
    await waitFor(() => {
      expect(screen.queryByLabelText('Close')).not.toBeInTheDocument()
    })

    // toggle again reopens the overlay
    fireEvent.click(menuBtn)
    expect(await screen.findByLabelText('Close')).toBeInTheDocument()
  })
})
