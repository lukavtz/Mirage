import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { I18nProvider } from '@/lib/i18n'
import { Sidebar } from './sidebar'

const NAV_LABELS = [
  'Dashboard', 'Logs', 'Infections', 'Cookies', 'Passwords',
  'Cards', 'Wallets', 'Files', 'Clippers', 'Support',
]

function renderSidebar(opts: { initialEntries?: string[]; open?: boolean; onClose?: () => void } = {}) {
  return render(
    <MemoryRouter initialEntries={opts.initialEntries ?? ['/']}>
      <I18nProvider>
        <Sidebar open={opts.open} onClose={opts.onClose} />
      </I18nProvider>
    </MemoryRouter>
  )
}

describe('Sidebar', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('renders the logo and every nav item label', () => {
    renderSidebar()
    expect(screen.getByAltText('Mirage')).toBeInTheDocument()
    expect(screen.getByText('Mirage')).toBeInTheDocument()
    for (const label of NAV_LABELS) {
      expect(screen.getByRole('link', { name: label })).toBeInTheDocument()
    }
  })

  it('marks the active route with aria-current on exact matches', () => {
    renderSidebar({ initialEntries: ['/sessions'] })
    expect(screen.getByRole('link', { name: 'Logs' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('link', { name: 'Dashboard' })).not.toHaveAttribute('aria-current')
  })

  it('marks a parent route active for nested paths', () => {
    renderSidebar({ initialEntries: ['/sessions/abc-123'] })
    expect(screen.getByRole('link', { name: 'Logs' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('link', { name: 'Dashboard' })).not.toHaveAttribute('aria-current')
  })

  it('marks the dashboard active on the root path', () => {
    renderSidebar({ initialEntries: ['/'] })
    expect(screen.getByRole('link', { name: 'Dashboard' })).toHaveAttribute('aria-current', 'page')
  })

  it('collapses on toggle, persists to localStorage, and hides labels', () => {
    renderSidebar()
    fireEvent.click(screen.getByRole('button', { name: 'Collapse sidebar' }))
    expect(localStorage.getItem('sidebar_collapsed')).toBe('true')
    expect(screen.getByRole('button', { name: 'Expand sidebar' })).toBeInTheDocument()
    expect(screen.queryByText('Mirage')).not.toBeInTheDocument()
    expect(screen.queryByText('Logs')).not.toBeInTheDocument()
    // collapsed links keep the label as a title attribute
    expect(screen.getByRole('link', { name: 'Dashboard' })).toHaveAttribute('title', 'Dashboard')
  })

  it('reads the collapsed state from localStorage on mount', () => {
    localStorage.setItem('sidebar_collapsed', 'true')
    renderSidebar()
    expect(screen.getByRole('button', { name: 'Expand sidebar' })).toBeInTheDocument()
    expect(screen.queryByText('Logs')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Dashboard' })).toHaveAttribute('title', 'Dashboard')
  })

  it('re-expands when the toggle is clicked again', () => {
    localStorage.setItem('sidebar_collapsed', 'true')
    renderSidebar()
    fireEvent.click(screen.getByRole('button', { name: 'Expand sidebar' }))
    expect(localStorage.getItem('sidebar_collapsed')).toBe('false')
    expect(screen.getByRole('button', { name: 'Collapse sidebar' })).toBeInTheDocument()
    expect(screen.getByText('Logs')).toBeInTheDocument()
  })

  it('renders a clickable mobile backdrop when open and none when closed', () => {
    const onClose = vi.fn()
    const { unmount } = renderSidebar({ open: true, onClose })
    const backdrop = screen.getByLabelText('Close')
    expect(backdrop).toBeInTheDocument()
    fireEvent.click(backdrop)
    expect(onClose).toHaveBeenCalledTimes(1)
    unmount()

    renderSidebar()
    expect(screen.queryByLabelText('Close')).not.toBeInTheDocument()
  })

  it('closes on Escape while open and cleans up the listener', () => {
    const onClose = vi.fn()
    const { rerender } = renderSidebar({ open: true, onClose })
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)

    // switching to closed re-runs the effect, detaching the listener
    rerender(
      <MemoryRouter initialEntries={['/']}>
        <I18nProvider>
          <Sidebar open={false} onClose={onClose} />
        </I18nProvider>
      </MemoryRouter>,
    )
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('closes the mobile sidebar when a nav link is clicked', () => {
    const onClose = vi.fn()
    renderSidebar({ open: true, onClose })
    fireEvent.click(screen.getByRole('link', { name: 'Logs' }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
