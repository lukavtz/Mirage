import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Label } from '@/components/ui/label'

describe('Label', () => {
  it('renders a label element with htmlFor', () => {
    render(<Label htmlFor="email">Email address</Label>)
    const label = screen.getByText('Email address')
    expect(label).toBeInTheDocument()
    expect(label.tagName).toBe('LABEL')
    expect(label).toHaveAttribute('for', 'email')
  })

  it('merges className', () => {
    render(<Label htmlFor="x" className="my-label">Name</Label>)
    expect(screen.getByText('Name')).toHaveClass('my-label', 'text-sm')
  })

  it('forwards native props', () => {
    render(<Label htmlFor="y" data-testid="lbl">Label</Label>)
    expect(screen.getByTestId('lbl')).toBeInTheDocument()
  })
})
