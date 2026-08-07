// Centralized chart tokens — consumed by charts/* and PublicStatsPage.
// PIE_COLORS uses the same --chart-N vars so a palette swap re-themes every chart.
import { useId } from 'react'

export const PIE_COLORS = [
  'var(--chart-1)',
  'var(--chart-2)',
  'var(--chart-3)',
  'var(--chart-4)',
  'var(--chart-5)',
] as const

/**
 * Returns a unique SVG gradient id per component instance.
 * Prevents collisions when the same chart type renders multiple times on one page
 * (e.g. Dashboard Timeline + PublicStatsPage Timeline).
 */
export function useChartGradientId(prefix: string): string {
  const id = useId()
  return `${prefix}-${id.replace(/:/g, '')}`
}
