import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { OsIcon, normalizeOsLabel } from '@/components/charts/os-icon'

describe('OsIcon', () => {
  it('renders the windows brand icon', () => {
    const { container } = render(<OsIcon os="Windows 10" />)
    const svg = container.querySelector('svg')!
    expect(svg.getAttribute('aria-label')).toBe('Windows 10')
    expect(svg.getAttribute('fill')).toBe('#0078D4')
  })

  it('renders macOS, iOS and Android with theme colors', () => {
    const { container, unmount } = render(<OsIcon os="macOS" />)
    let svg = container.querySelector('svg')!
    expect(svg.getAttribute('fill')).toBe('currentColor')
    expect(svg.style.color).toBe('var(--foreground)')
    unmount()

    render(<OsIcon os="iOS 17" />)
    svg = document.body.querySelector('svg')!
    expect(svg.getAttribute('fill')).toBe('currentColor')
    expect(svg.style.color).toBe('var(--foreground)')
    document.body.innerHTML = ''

    render(<OsIcon os="Android" />)
    svg = document.body.querySelector('svg')!
    expect(svg.getAttribute('fill')).toBe('currentColor')
    expect(svg.style.color).toBe('rgb(61, 220, 132)')
  })

  it('renders generic linux with the muted foreground token', () => {
    const { container } = render(<OsIcon os="Linux" />)
    const svg = container.querySelector('svg')!
    expect(svg.getAttribute('fill')).toBe('currentColor')
    expect(svg.style.color).toBe('var(--muted-foreground)')
  })

  it('renders distro brand colors for ubuntu, debian, fedora, arch, mint, kali, freebsd', () => {
    const cases: Array<[string, string]> = [
      ['Ubuntu 22.04', '#E95420'],
      ['Debian', '#A81D33'],
      ['Fedora 39', '#294172'],
      ['Arch Linux', '#1793D1'],
      ['Linux Mint', '#86BE43'],
      ['Kali Linux', '#557C94'],
      ['FreeBSD', '#AB2B28'],
    ]
    for (const [os, color] of cases) {
      const { container, unmount } = render(<OsIcon os={os} />)
      const svg = container.querySelector('svg')!
      expect(svg.getAttribute('fill')).toBe(color)
      unmount()
    }
  })

  it('renders the unknown fallback for unrecognized OS strings', () => {
    const { container } = render(<OsIcon os="ChromeOS" />)
    const svg = container.querySelector('svg')!
    expect(svg.getAttribute('fill')).toBe('var(--muted-foreground)')
    expect(svg.getAttribute('aria-label')).toBe('ChromeOS')
  })

  it('renders unknown fallback for empty os and applies size/className', () => {
    const { container } = render(<OsIcon os="" size={24} className="mr-1" />)
    const svg = container.querySelector('svg')!
    expect(svg.getAttribute('aria-label')).toBe('unknown')
    expect(svg.getAttribute('width')).toBe('24')
    expect(svg.getAttribute('height')).toBe('24')
    expect(svg.getAttribute('class')).toContain('mr-1')
  })
})

describe('normalizeOsLabel', () => {
  it('maps OS strings to canonical labels', () => {
    expect(normalizeOsLabel('Ubuntu 22.04')).toBe('Ubuntu')
    expect(normalizeOsLabel('debian 12')).toBe('Debian')
    expect(normalizeOsLabel('Fedora 39')).toBe('Fedora')
    expect(normalizeOsLabel('Arch Linux')).toBe('Arch')
    expect(normalizeOsLabel('Linux Mint')).toBe('Linux Mint')
    expect(normalizeOsLabel('Kali')).toBe('Kali')
    expect(normalizeOsLabel('Windows 11')).toBe('Windows')
    expect(normalizeOsLabel('macOS')).toBe('macOS')
    expect(normalizeOsLabel('Darwin')).toBe('macOS')
    expect(normalizeOsLabel('iOS')).toBe('iOS')
    expect(normalizeOsLabel('Android 14')).toBe('Android')
    expect(normalizeOsLabel('Linux')).toBe('Linux')
    expect(normalizeOsLabel('FreeBSD')).toBe('FreeBSD')
    expect(normalizeOsLabel('Some OS')).toBe('Some OS')
    expect(normalizeOsLabel('')).toBe('Unknown')
  })
})
