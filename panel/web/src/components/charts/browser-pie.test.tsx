import { describe, it, expect, vi } from 'vitest'
import { render, screen, act } from '@testing-library/react'

vi.mock('recharts', async (importOriginal) => {
  const actual = await importOriginal<typeof import('recharts')>()
  // Real ResponsiveContainer skips DOM measurement when given numeric
  // width/height, so delegate with fixed dimensions to render the chart.
  const ResponsiveContainer = ({ children }: { children?: React.ReactNode }) => (
    <actual.ResponsiveContainer width={400} height={300}>{children}</actual.ResponsiveContainer>
  )
  return { ...actual, ResponsiveContainer }
})

import { BrowserPie } from '@/components/charts/browser-pie'

describe('BrowserPie', () => {
  it('renders a skeleton while loading', () => {
    const { container } = render(<BrowserPie data={[]} isLoading />)
    expect(container.querySelector('.animate-pulse')).not.toBeNull()
  })

  it('shows the empty message when there is no data', () => {
    render(<BrowserPie data={[]} isLoading={false} />)
    expect(screen.getByText('No browser data yet')).toBeInTheDocument()
  })

  it('renders browser names, counts and percentages from data', () => {
    vi.useFakeTimers()
    render(
      <BrowserPie
        data={[
          { name: 'Chrome', count: 75 },
          { name: 'Firefox', count: 25 },
        ]}
        isLoading={false}
      />,
    )
    expect(screen.getByText('Chrome')).toBeInTheDocument()
    expect(screen.getByText('Firefox')).toBeInTheDocument()
    expect(screen.getByText('75')).toBeInTheDocument()
    expect(screen.getByText('25')).toBeInTheDocument()
    act(() => { vi.advanceTimersByTime(2000) })
    expect(screen.getByText(/75%/)).toBeInTheDocument()
    expect(screen.getByText(/25%/)).toBeInTheDocument()
    expect(document.querySelector('svg')).not.toBeNull()
    vi.useRealTimers()
  })

  it('clamps pie colors beyond the palette length', () => {
    const data = Array.from({ length: 8 }, (_, i) => ({ name: `Browser ${i}`, count: 10 + i }))
    vi.useFakeTimers()
    const { container } = render(<BrowserPie data={data} isLoading={false} />)
    act(() => { vi.advanceTimersByTime(2000) })
    expect(screen.getByText('Browser 7')).toBeInTheDocument()
    expect(container.querySelector('svg')).not.toBeNull()
    vi.useRealTimers()
  })
})
