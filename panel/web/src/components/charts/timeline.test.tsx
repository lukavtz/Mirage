import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('recharts', async (importOriginal) => {
  const actual = await importOriginal<typeof import('recharts')>()
  // Real ResponsiveContainer skips DOM measurement when given numeric
  // width/height, so delegate with fixed dimensions to render the chart.
  const ResponsiveContainer = ({ children }: { children?: React.ReactNode }) => (
    <actual.ResponsiveContainer width={400} height={300}>{children}</actual.ResponsiveContainer>
  )
  // jsdom never fires the chart mouse events that populate the real
  // tooltip, so exercise the label/value formatters directly.
  const Tooltip = ({ labelFormatter, formatter }: { labelFormatter?: (l: unknown) => unknown; formatter?: (v: unknown) => unknown }) => (
    <div data-testid="test-tooltip">
      {typeof labelFormatter === 'function' ? String(labelFormatter('2026-08-01')) : ''}:
      {typeof formatter === 'function' ? String(formatter(20)) : ''}
    </div>
  )
  return { ...actual, ResponsiveContainer, Tooltip }
})

import { I18nProvider } from '@/lib/i18n'
import { Timeline } from '@/components/charts/timeline'

const renderWith = (ui: React.ReactNode) => render(<I18nProvider>{ui}</I18nProvider>)

describe('Timeline', () => {
  it('renders a skeleton while loading', () => {
    const { container } = renderWith(<Timeline data={[]} isLoading />)
    expect(container.querySelector('.animate-pulse')).not.toBeNull()
  })

  it('shows the empty message when there is no data', () => {
    renderWith(<Timeline data={[]} isLoading={false} />)
    expect(screen.getByText(/No data yet/)).toBeInTheDocument()
  })

  it('renders the area chart with dates and counts', () => {
    const { container } = renderWith(
      <Timeline
        data={[
          { date: '2026-08-01', count: 10 },
          { date: '2026-08-02', count: 20 },
          { date: '2026-08-03', count: 15 },
          { date: '2026-08-04', count: 30 },
        ]}
        isLoading={false}
      />,
    )
    const svg = container.querySelector('svg')
    expect(svg).not.toBeNull()
    expect(container.querySelector('linearGradient')).not.toBeNull()
    expect(container.querySelector('.recharts-area')).not.toBeNull()
    expect(screen.getByText('2026-08-01')).toBeInTheDocument()
  })

  it('formats the tooltip label and value via the chart formatters', () => {
    renderWith(<Timeline data={[{ date: '2026-08-01', count: 20 }]} isLoading={false} />)
    const tooltip = screen.getByTestId('test-tooltip')
    expect(tooltip.textContent).toContain('2026-08-01')
    expect(tooltip.textContent).toContain((20).toLocaleString())
  })
})
