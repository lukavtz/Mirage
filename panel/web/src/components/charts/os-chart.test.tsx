import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { I18nProvider } from '@/lib/i18n'
import { OSChart } from '@/components/charts/os-chart'

const renderWith = (ui: React.ReactNode) => render(<I18nProvider>{ui}</I18nProvider>)

describe('OSChart', () => {
  it('renders skeletons while loading', () => {
    const { container } = renderWith(<OSChart data={[]} isLoading />)
    expect(container.querySelectorAll('.animate-pulse').length).toBe(7)
  })

  it('shows the empty message when there is no data', () => {
    renderWith(<OSChart data={[]} isLoading={false} />)
    expect(screen.getByText(/No OS data yet/)).toBeInTheDocument()
  })

  it('renders os rows with labels, counts and percentages', () => {
    renderWith(
      <OSChart
        data={[
          { os: 'Windows 10', count: 60 },
          { os: 'Ubuntu 22.04', count: 40 },
        ]}
        isLoading={false}
      />,
    )
    expect(screen.getByText('Windows')).toBeInTheDocument()
    expect(screen.getByText('Ubuntu')).toBeInTheDocument()
    expect(screen.getByText('60')).toBeInTheDocument()
    expect(screen.getByText('40')).toBeInTheDocument()
    expect(screen.getByText('60.0%')).toBeInTheDocument()
    expect(screen.getByText('40.0%')).toBeInTheDocument()
  })

  it('calls onSelect with the os when a row is clicked', () => {
    const onSelect = vi.fn()
    renderWith(
      <OSChart
        data={[{ os: 'Windows', count: 10 }]}
        isLoading={false}
        onSelect={onSelect}
      />,
    )
    fireEvent.click(screen.getByText('Windows'))
    expect(onSelect).toHaveBeenCalledWith('Windows')
  })

  it('clears selection when clicking the already-selected os', () => {
    const onSelect = vi.fn()
    renderWith(
      <OSChart
        data={[{ os: 'Windows', count: 10 }]}
        isLoading={false}
        onSelect={onSelect}
        selectedOs="Windows"
      />,
    )
    fireEvent.click(screen.getByText('Windows'))
    expect(onSelect).toHaveBeenCalledWith('')
  })

  it('marks the selected os row as active', () => {
    renderWith(
      <OSChart
        data={[
          { os: 'Windows', count: 10 },
          { os: 'Linux', count: 5 },
        ]}
        isLoading={false}
        selectedOs="Linux"
      />,
    )
    const rows = screen.getAllByRole('button')
    expect(rows[1].classList.contains('bg-accent')).toBe(true)
    expect(rows[0].classList.contains('bg-accent')).toBe(false)
  })

  it('limits rendering to the first 7 entries', () => {
    const data = Array.from({ length: 10 }, (_, i) => ({ os: `OS ${i}`, count: i + 1 }))
    renderWith(<OSChart data={data} isLoading={false} />)
    expect(screen.getAllByRole('button').length).toBe(7)
  })
})
