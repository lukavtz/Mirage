import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { I18nProvider } from '@/lib/i18n'
import { LatestLogs } from '@/components/charts/latest-logs'
import type { SessionListItem } from '@/types'

const renderWith = (ui: React.ReactNode, routes?: React.ReactNode) =>
  render(
    <MemoryRouter initialEntries={['/']}>
      <I18nProvider>{ui}</I18nProvider>
      {routes}
    </MemoryRouter>,
  )

const session = (over: Partial<SessionListItem> = {}): SessionListItem => ({
  id: 'abc123def456',
  ip: '1.2.3.4',
  country_code: 'US',
  os: 'Windows 10',
  browser: 'Chrome',
  created_at: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(),
  ...over,
})

describe('LatestLogs', () => {
  it('renders skeletons while loading', () => {
    const { container } = renderWith(<LatestLogs data={[]} isLoading />)
    expect(container.querySelectorAll('.animate-pulse').length).toBe(5)
  })

  it('shows the empty message when there is no data', () => {
    renderWith(<LatestLogs data={[]} isLoading={false} />)
    expect(screen.getByText(/No logs yet/)).toBeInTheDocument()
  })

  it('renders table headers and session rows', () => {
    renderWith(
      <LatestLogs
        data={[session(), session({ id: 'xyz', ip: '5.6.7.8', country_code: 'DE', os: 'Ubuntu', browser: 'Firefox' })]}
        isLoading={false}
      />,
    )
    expect(screen.getByText('IP Address')).toBeInTheDocument()
    expect(screen.getByText('Country')).toBeInTheDocument()
    expect(screen.getByText('OS')).toBeInTheDocument()
    expect(screen.getByText('Browser')).toBeInTheDocument()
    expect(screen.getByText('Logs')).toBeInTheDocument()
    expect(screen.getByText('Date')).toBeInTheDocument()
    expect(screen.getByText('1.2.3.4')).toBeInTheDocument()
    expect(screen.getByText('5.6.7.8')).toBeInTheDocument()
    expect(screen.getByText('Windows 10')).toBeInTheDocument()
    expect(screen.getByText('abc123de')).toBeInTheDocument()
    expect(screen.getAllByText(/ago/).length).toBe(2)
  })

  it('renders log count badges only when counts are positive', () => {
    renderWith(
      <LatestLogs
        data={[
          session({ passwords_count: 3, cookies_count: 5, cards_count: 2 }),
          session({ id: 'nobadges', passwords_count: 0, cookies_count: 0, cards_count: 0 }),
        ]}
        isLoading={false}
      />,
    )
    expect(screen.getByText('P 3')).toBeInTheDocument()
    expect(screen.getByText('C 5')).toBeInTheDocument()
    expect(screen.getByText('CC 2')).toBeInTheDocument()
    expect(screen.queryByText('P 0')).not.toBeInTheDocument()
  })

  it('renders placeholders for missing fields', () => {
    renderWith(<LatestLogs data={[session({ ip: '', country_code: '', os: '', browser: '', created_at: '' })]} isLoading={false} />)
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(4)
  })

  it('limits rows to the first 5 sessions', () => {
    const data = Array.from({ length: 7 }, (_, i) => session({ id: `id-${i}`, ip: `10.0.0.${i}` }))
    renderWith(<LatestLogs data={data} isLoading={false} />)
    expect(screen.getByText('10.0.0.0')).toBeInTheDocument()
    expect(screen.queryByText('10.0.0.6')).not.toBeInTheDocument()
  })

  it('navigates to the session page when a row is clicked', () => {
    renderWith(
      <LatestLogs data={[session()]} isLoading={false} />,
      <Routes>
        <Route path="/sessions/:id" element={<div>session detail page</div>} />
      </Routes>,
    )
    fireEvent.click(screen.getByText('1.2.3.4'))
    expect(screen.getByText('session detail page')).toBeInTheDocument()
  })
})
