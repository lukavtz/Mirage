import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { FlagIcon } from '@/components/charts/flag-icon'

describe('FlagIcon', () => {
  it('renders an svg with a title element for a known country code', () => {
    const { container } = render(<FlagIcon country="US" />)
    const svg = container.querySelector('svg')
    expect(svg).not.toBeNull()
    expect(svg!).toHaveAttribute('width', '20')
    expect(svg!).toHaveAttribute('height', '15')
    expect(svg!.querySelector('title')?.textContent).toBe('US')
  })

  it('renders several known country codes', () => {
    for (const code of ['US', 'DE', 'RU', 'GB', 'BR', 'JP', 'UA']) {
      const { container, unmount } = render(<FlagIcon country={code} />)
      const svg = container.querySelector('svg')
      expect(svg).not.toBeNull()
      expect(svg!.querySelector('title')?.textContent).toBe(code)
      unmount()
    }
  })

  it('normalizes lowercase country codes to uppercase', () => {
    const { container } = render(<FlagIcon country="de" />)
    expect(container.querySelector('svg')!.querySelector('title')?.textContent).toBe('DE')
  })

  it('renders nothing for an unknown country code', () => {
    const { container } = render(<FlagIcon country="ZZ" />)
    expect(container.querySelector('svg')).toBeNull()
  })

  it('renders nothing for an empty country', () => {
    const { container } = render(<FlagIcon country="" />)
    expect(container.querySelector('svg')).toBeNull()
  })

  it('applies width, height and className props', () => {
    const { container } = render(<FlagIcon country="US" width={32} height={24} className="rounded-full" />)
    const svg = container.querySelector('svg')!
    expect(svg).toHaveAttribute('width', '32')
    expect(svg).toHaveAttribute('height', '24')
    expect(svg.getAttribute('class')).toContain('rounded-full')
  })
})
