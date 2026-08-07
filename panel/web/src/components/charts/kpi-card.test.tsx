import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Users } from 'lucide-react'
import { KpiCard } from '@/components/charts/kpi-card'

const baseProps = {
  title: 'Sessions',
  value: 100,
  change: 0,
  icon: Users,
  color: '#22c55e',
  isLoading: false,
}

describe('KpiCard', () => {
  it('renders skeletons while loading', () => {
    const { container } = render(<KpiCard {...baseProps} isLoading />)
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
    expect(screen.queryByText('Sessions')).not.toBeInTheDocument()
  })

  it('renders title, formatted value and change', () => {
    render(<KpiCard {...baseProps} change={1.5} />)
    expect(screen.getByText('Sessions')).toBeInTheDocument()
    expect(screen.getByText('100')).toBeInTheDocument()
    expect(screen.getByText('+1.5%')).toBeInTheDocument()
    expect(document.querySelector('.lucide-trending-up')).not.toBeNull()
    expect(screen.getByText('+1.5%').parentElement!.className).toContain('text-green-500')
  })

  it('renders negative change in red with trending-down icon', () => {
    render(<KpiCard {...baseProps} change={-2.3} />)
    expect(screen.getByText('-2.3%')).toBeInTheDocument()
    expect(document.querySelector('.lucide-trending-down')).not.toBeNull()
    expect(screen.getByText('-2.3%').parentElement!.className).toContain('text-red-500')
  })

  it('shows a custom vsLabel instead of the computed change', () => {
    render(<KpiCard {...baseProps} change={9} vsLabel="vs last week" />)
    expect(screen.getByText('vs last week')).toBeInTheDocument()
    expect(screen.queryByText('+9.0%')).not.toBeInTheDocument()
  })

  it('renders a sparkline polyline when sparkline is provided', () => {
    const { container } = render(<KpiCard {...baseProps} sparkline={[10, 20, 15, 30]} />)
    const polyline = container.querySelector('polyline')
    expect(polyline).not.toBeNull()
    expect(polyline!.getAttribute('points')!.split(' ').length).toBe(4)
  })

  it('handles a flat sparkline without dividing by zero', () => {
    const { container } = render(<KpiCard {...baseProps} sparkline={[5, 5, 5]} />)
    const polyline = container.querySelector('polyline')!
    expect(polyline.getAttribute('points')).toContain(',')
  })

  it('omits the sparkline when not provided', () => {
    const { container } = render(<KpiCard {...baseProps} />)
    expect(container.querySelector('polyline')).toBeNull()
  })
})
