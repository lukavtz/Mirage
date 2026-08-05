import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { I18nProvider } from '@/lib/i18n'
import { WorldMap } from '@/components/charts/world-map'

const renderMap = (ui: React.ReactNode, routes?: React.ReactNode) =>
  render(
    <MemoryRouter initialEntries={['/']}>
      <I18nProvider>{ui}</I18nProvider>
      {routes}
    </MemoryRouter>,
  )

const pathForCountry = (container: HTMLElement, name: string) => {
  const title = Array.from(container.querySelectorAll('svg title')).find(t => t.textContent === name)
  return title?.closest('path') ?? null
}

describe('WorldMap', () => {
  it('renders a skeleton while loading', () => {
    const { container } = renderMap(<WorldMap data={[]} isLoading />)
    expect(container.querySelector('.animate-pulse')).not.toBeNull()
  })

  it('shows the empty message when there is no data', () => {
    renderMap(<WorldMap data={[]} isLoading={false} />)
    expect(screen.getByText(/No geo data yet/)).toBeInTheDocument()
  })

  it('renders an svg with a path per country', () => {
    const { container } = renderMap(<WorldMap data={[{ country_code: 'US', count: 50 }]} isLoading={false} />)
    const svg = container.querySelector('svg')
    expect(svg).not.toBeNull()
    expect(container.querySelectorAll('svg path').length).toBeGreaterThan(100)
  })

  it('names data countries in path titles and legend count', () => {
    const { container } = renderMap(
      <WorldMap
        data={[
          { country_code: 'US', count: 50 },
          { country_code: 'DE', count: 30 },
        ]}
        isLoading={false}
      />,
    )
    expect(pathForCountry(container, 'United States')).not.toBeNull()
    expect(pathForCountry(container, 'Germany')).not.toBeNull()
    expect(screen.getByText(/2 Countries/)).toBeInTheDocument()
    expect(screen.getByText('Low')).toBeInTheDocument()
    expect(screen.getByText('Medium')).toBeInTheDocument()
    expect(screen.getByText('High')).toBeInTheDocument()
  })

  it('shows a tooltip on hover and hides it on leave', () => {
    const { container } = renderMap(<WorldMap data={[{ country_code: 'US', count: 50 }]} isLoading={false} />)
    const usPath = pathForCountry(container, 'United States')!
    fireEvent.mouseEnter(usPath)
    const tooltip = container.querySelector('.bg-popover')
    expect(tooltip).not.toBeNull()
    expect(tooltip!.textContent).toContain('United States')
    expect(tooltip!.textContent).toContain('50')
    fireEvent.mouseLeave(usPath)
    expect(container.querySelector('.bg-popover')).toBeNull()
  })

  it('navigates to the country session filter on click', () => {
    const { container } = renderMap(
      <WorldMap data={[{ country_code: 'US', count: 50 }]} isLoading={false} />,
      <Routes>
        <Route path="/sessions" element={<div>sessions page</div>} />
      </Routes>,
    )
    const usPath = pathForCountry(container, 'United States')!
    fireEvent.click(usPath)
    expect(screen.getByText('sessions page')).toBeInTheDocument()
  })

  it('clears the active country while loading after a hover', () => {
    const { container, rerender } = renderMap(<WorldMap data={[{ country_code: 'US', count: 50 }]} isLoading={false} />)
    const usPath = pathForCountry(container, 'United States')!
    fireEvent.mouseEnter(usPath)
    expect(container.querySelector('.bg-popover')).not.toBeNull()
    rerender(
      <MemoryRouter initialEntries={['/']}>
        <I18nProvider>
          <WorldMap data={[{ country_code: 'US', count: 50 }]} isLoading />
        </I18nProvider>
      </MemoryRouter>,
    )
    expect(container.querySelector('.bg-popover')).toBeNull()
  })
})
