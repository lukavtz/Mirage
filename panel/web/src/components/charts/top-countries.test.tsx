import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { I18nProvider } from '@/lib/i18n'
import { TopCountries } from '@/components/charts/top-countries'

const renderWith = (ui: React.ReactNode) => render(
  <MemoryRouter>
    <I18nProvider>{ui}</I18nProvider>
  </MemoryRouter>
)

describe('TopCountries', () => {
  it('renders flag, full country name, count, percent for each entry', () => {
    renderWith(
      <TopCountries
        data={[
          { country_code: 'US', count: 50 },
          { country_code: 'DE', count: 30 },
        ]}
        isLoading={false}
      />,
    )
    expect(screen.getByText('United States')).toBeInTheDocument()
    expect(screen.getByText('Germany')).toBeInTheDocument()
    expect(screen.getByText('50')).toBeInTheDocument()
    expect(screen.getByText('30')).toBeInTheDocument()
    expect(screen.getByText('62.5%')).toBeInTheDocument()
    expect(screen.getByText('37.5%')).toBeInTheDocument()
  })

  it('shows "no data" message when empty', () => {
    renderWith(<TopCountries data={[]} isLoading={false} />)
    expect(screen.getByText(/no geo/i)).toBeInTheDocument()
  })

  it('shows skeletons while loading', () => {
    const { container } = renderWith(<TopCountries data={[]} isLoading={true} />)
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
  })

  it('navigates to the country filter when a row is clicked', () => {
    renderWith(
      <>
        <TopCountries
          data={[
            { country_code: 'US', count: 50 },
            { country_code: 'DE', count: 30 },
          ]}
          isLoading={false}
        />
        <Routes>
          <Route path="/sessions" element={<div>sessions page</div>} />
        </Routes>
      </>,
    )
    fireEvent.click(screen.getByText('United States'))
    expect(screen.getByText('sessions page')).toBeInTheDocument()
  })

  it('shows a view-all button and calls onViewAll when more than 7 entries', () => {
    const onViewAll = vi.fn()
    const data = Array.from({ length: 9 }, (_, i) => ({ country_code: `C${i}`, count: 10 - i }))
    const { container } = renderWith(<TopCountries data={data} isLoading={false} onViewAll={onViewAll} />)
    expect(screen.getByText('View all')).toBeInTheDocument()
    expect(screen.getAllByRole('button').length).toBe(8)
    fireEvent.click(screen.getByText('View all'))
    expect(onViewAll).toHaveBeenCalledTimes(1)
    expect(container).toBeInTheDocument()
  })

  it('navigates to sessions when clicking view-all without a handler', () => {
    const data = Array.from({ length: 8 }, (_, i) => ({ country_code: `C${i}`, count: 10 - i }))
    renderWith(
      <>
        <TopCountries data={data} isLoading={false} />
        <Routes>
          <Route path="/sessions" element={<div>sessions page</div>} />
        </Routes>
      </>,
    )
    fireEvent.click(screen.getByText('View all'))
    expect(screen.getByText('sessions page')).toBeInTheDocument()
  })

  it('renders at most 7 rows', () => {
    const data = Array.from({ length: 9 }, (_, i) => ({ country_code: `C${i}`, count: 10 - i }))
    renderWith(<TopCountries data={data} isLoading={false} />)
    expect(screen.getAllByRole('button').length).toBe(8) // 7 rows + view-all
    expect(screen.queryByText('C7')).not.toBeInTheDocument()
  })
})
