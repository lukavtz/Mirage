import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { Button, buttonVariants } from '@/components/ui/button'

const variants = ['default', 'destructive', 'outline', 'secondary', 'ghost', 'link'] as const

const expectTokens = (el: HTMLElement, expected: string) => {
  const tokens = el.className.split(/\s+/)
  expected.split(/\s+/).forEach((t) => {
    expect(tokens).toContain(t)
  })
}

describe('Button', () => {
  it('renders a default button with children', () => {
    render(<Button>Click me</Button>)
    const btn = screen.getByRole('button', { name: 'Click me' })
    expect(btn).toBeInTheDocument()
    expect(btn.tagName).toBe('BUTTON')
    expectTokens(btn, buttonVariants())
  })

  it.each(variants)('applies %s variant classes', (variant) => {
    render(<Button variant={variant}>V</Button>)
    expectTokens(screen.getByRole('button'), buttonVariants({ variant }))
  })

  it.each([
    ['default', ['h-9', 'px-4', 'py-2']],
    ['sm', ['h-8', 'px-3', 'text-[12px]']],
    ['lg', ['h-10', 'px-6']],
    ['icon', ['h-9', 'w-9']],
  ] as const)('applies %s size classes', (size, expected) => {
    render(<Button size={size}>S</Button>)
    const tokens = screen.getByRole('button').className.split(/\s+/)
    expected.forEach((t) => expect(tokens).toContain(t))
  })

  it('renders disabled button', () => {
    render(<Button disabled>D</Button>)
    expect(screen.getByRole('button')).toBeDisabled()
  })

  it('fires onClick', () => {
    const onClick = vi.fn()
    render(<Button onClick={onClick}>Go</Button>)
    fireEvent.click(screen.getByRole('button'))
    expect(onClick).toHaveBeenCalledTimes(1)
  })

  it('renders child element instead of button when asChild (anchor)', () => {
    render(
      <Button asChild>
        <a href="/next">Next</a>
      </Button>,
    )
    const link = screen.getByRole('link', { name: 'Next' })
    expect(link.tagName).toBe('A')
    expectTokens(link, buttonVariants())
    expect(link.getAttribute('href')).toBe('/next')
  })

  it('renders child element instead of button when asChild (span)', () => {
    const { container } = render(
      <Button asChild>
        <span>Plain</span>
      </Button>,
    )
    const span = container.querySelector('span')
    expect(span).toBeInTheDocument()
    expect(container.querySelector('button')).not.toBeInTheDocument()
    expectTokens(span as HTMLElement, buttonVariants())
  })

  it('merges className', () => {
    render(<Button className="my-custom-class">M</Button>)
    expect(screen.getByRole('button').className).toContain('my-custom-class')
  })

  it('forwards native props', () => {
    render(<Button type="submit" aria-label="submit me">S</Button>)
    expect(screen.getByRole('button', { name: 'submit me' })).toHaveAttribute('type', 'submit')
  })
})

describe('buttonVariants', () => {
  it('returns default classes when no args', () => {
    expect(buttonVariants()).toContain('bg-foreground')
    expect(buttonVariants()).toContain('h-9')
  })

  it('returns variant + size classes when specified', () => {
    const cls = buttonVariants({ variant: 'link', size: 'icon' })
    expect(cls).toContain('underline-offset-4')
    expect(cls).toContain('w-9')
  })
})
