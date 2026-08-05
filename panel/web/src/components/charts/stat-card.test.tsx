import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Users } from 'lucide-react'
import { StatCard } from '@/components/charts/stat-card'

describe('StatCard', () => {
  it('renders skeletons while loading', () => {
    const { container } = render(<StatCard title="Sessions" value={0} icon={Users} isLoading />)
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
    expect(screen.queryByText('Sessions')).not.toBeInTheDocument()
  })

  it('renders title, formatted value and icon', () => {
    render(<StatCard title="Sessions" value={1234} icon={Users} isLoading={false} />)
    expect(screen.getByText('Sessions')).toBeInTheDocument()
    expect(screen.getByText((t) => t.replace(/\s/g, '') === '1234')).toBeInTheDocument()
    expect(document.querySelector('.lucide-users')).not.toBeNull()
  })

  it('renders the subtitle when provided and omits it otherwise', () => {
    const { container, rerender } = render(
      <StatCard title="Sessions" value={1} subtitle="since yesterday" icon={Users} isLoading={false} />,
    )
    expect(screen.getByText('since yesterday')).toBeInTheDocument()
    rerender(<StatCard title="Sessions" value={1} icon={Users} isLoading={false} />)
    expect(screen.queryByText('since yesterday')).not.toBeInTheDocument()
    expect(container).toBeInTheDocument()
  })

  it('applies the warning accent class to the value', () => {
    render(<StatCard title="Stealer" value={5} icon={Users} isLoading={false} accent="warning" />)
    expect(screen.getByText('5').className).toContain('text-warning')
  })

  it('uses the foreground accent by default', () => {
    render(<StatCard title="Stealer" value={7} icon={Users} isLoading={false} />)
    expect(screen.getByText('7').className).toContain('text-foreground')
  })
})
