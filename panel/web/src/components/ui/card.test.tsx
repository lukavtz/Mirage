import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  Card,
  CardHeader,
  CardFooter,
  CardTitle,
  CardDescription,
  CardContent,
} from '@/components/ui/card'

describe('Card', () => {
  it('renders all subcomponents with children and merged className', () => {
    render(
      <Card className="my-card">
        <CardHeader className="my-header">
          <CardTitle className="my-title">Title here</CardTitle>
          <CardDescription className="my-desc">Description here</CardDescription>
        </CardHeader>
        <CardContent className="my-content">Content here</CardContent>
        <CardFooter className="my-footer">Footer here</CardFooter>
      </Card>,
    )
    expect(screen.getByText('Title here')).toBeInTheDocument()
    expect(screen.getByText('Description here')).toBeInTheDocument()
    expect(screen.getByText('Content here')).toBeInTheDocument()
    expect(screen.getByText('Footer here')).toBeInTheDocument()
  })

  it('applies custom className to Card', () => {
    const { container } = render(<Card className="custom-card">C</Card>)
    expect(container.firstChild).toHaveClass('custom-card', 'rounded-lg')
  })

  it('applies custom className to each subcomponent', () => {
    const { container } = render(
      <Card>
        <CardHeader className="c-hdr">
          <CardTitle className="c-title">T</CardTitle>
          <CardDescription className="c-desc">D</CardDescription>
          <CardContent className="c-content">B</CardContent>
          <CardFooter className="c-footer">F</CardFooter>
        </CardHeader>
      </Card>,
    )
    const classes = Array.from(container.querySelectorAll('div')).map((d) => d.className)
    expect(classes.join(' ')).toContain('c-hdr')
    expect(classes.join(' ')).toContain('c-title')
    expect(classes.join(' ')).toContain('c-desc')
    expect(classes.join(' ')).toContain('c-content')
    expect(classes.join(' ')).toContain('c-footer')
  })

  it('forwards native props to Card', () => {
    const { container } = render(<Card data-testid="card">C</Card>)
    expect(container.querySelector('[data-testid="card"]')).toBeInTheDocument()
  })
})
