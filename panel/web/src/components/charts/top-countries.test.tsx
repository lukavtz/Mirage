import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
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
})
