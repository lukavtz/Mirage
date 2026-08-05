import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { Skeleton } from '@/components/ui/skeleton'

describe('Skeleton', () => {
  it('renders a div with default skeleton classes', () => {
    const { container } = render(<Skeleton data-testid="sk" />)
    const el = container.querySelector('[data-testid="sk"]')
    expect(el).toBeInTheDocument()
    expect(el).toHaveClass('animate-pulse', 'rounded-md', 'bg-muted')
  })

  it('merges custom className', () => {
    const { container } = render(<Skeleton className="my-skeleton h-8" data-testid="sk2" />)
    const el = container.querySelector('[data-testid="sk2"]')
    expect(el).toHaveClass('my-skeleton', 'h-8', 'animate-pulse')
  })

  it('forwards native props', () => {
    const { container } = render(<Skeleton aria-label="loading" data-testid="sk3" />)
    expect(container.querySelector('[data-testid="sk3"]')).toHaveAttribute('aria-label', 'loading')
  })
})
