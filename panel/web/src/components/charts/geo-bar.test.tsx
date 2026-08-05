import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('recharts', async (importOriginal) => {
  const actual = await importOriginal<typeof import('recharts')>()
  // Real ResponsiveContainer skips DOM measurement when given numeric
  // width/height, so delegate with fixed dimensions to render the chart.
  const ResponsiveContainer = ({ children }: { children?: React.ReactNode }) => (
    <actual.ResponsiveContainer width={400} height={300}>{children}</actual.ResponsiveContainer>
  )
  return { ...actual, ResponsiveContainer }
})

import { GeoBar } from '@/components/charts/geo-bar'

describe('GeoBar', () => {
  it('renders a skeleton while loading', () => {
    const { container } = render(<GeoBar data={[]} isLoading />)
    expect(container.querySelector('.animate-pulse')).not.toBeNull()
  })

  it('shows the empty message when there is no data', () => {
    render(<GeoBar data={[]} isLoading={false} />)
    expect(screen.getByText('No geo data yet')).toBeInTheDocument()
  })

  it('renders the bar chart with flags and country data', () => {
    const { container } = render(
      <GeoBar
        data={[
          { country: 'US', count: 120 },
          { country: 'DE', count: 80 },
        ]}
        isLoading={false}
      />,
    )
    const svg = container.querySelector('svg')
    expect(svg).not.toBeNull()
    expect(container.querySelector('linearGradient')).not.toBeNull()
    expect(container.querySelectorAll('foreignObject').length).toBeGreaterThan(0)
    expect(container.querySelectorAll('svg title').length).toBeGreaterThan(0)
  })
})
