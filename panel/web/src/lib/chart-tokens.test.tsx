import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { PIE_COLORS, useChartGradientId } from './chart-tokens'

function GradientProbe({ prefix }: { prefix: string }) {
  const id = useChartGradientId(prefix)
  return <span data-testid="gradient-id">{id}</span>
}

describe('chart tokens', () => {
  it('exposes five pie colors backed by chart CSS vars', () => {
    expect(PIE_COLORS).toHaveLength(5)
    expect(PIE_COLORS[0]).toBe('var(--chart-1)')
  })

  it('generates a prefixed gradient id', () => {
    render(<GradientProbe prefix="grad" />)
    expect(screen.getByTestId('gradient-id').textContent).toMatch(/^grad-/)
  })

  it('generates a unique id per component instance', () => {
    render(<GradientProbe prefix="grad" />)
    render(<GradientProbe prefix="grad" />)
    const [a, b] = screen.getAllByTestId('gradient-id').map(el => el.textContent)
    expect(a).not.toBe(b)
  })
})
