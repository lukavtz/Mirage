import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { Input } from '@/components/ui/input'

describe('Input', () => {
  it('renders an input with merged className', () => {
    render(<Input className="my-input" placeholder="Type here" />)
    const input = screen.getByPlaceholderText('Type here')
    expect(input).toBeInTheDocument()
    expect(input).toHaveClass('my-input', 'h-10', 'w-full')
  })

  it('reflects value and fires onChange', () => {
    const onChange = vi.fn()
    render(<Input value="abc" onChange={onChange} aria-label="field" />)
    const input = screen.getByRole('textbox', { name: 'field' })
    expect(input).toHaveValue('abc')
    fireEvent.change(input, { target: { value: 'xyz' } })
    expect(onChange).toHaveBeenCalledTimes(1)
  })

  it('renders disabled input', () => {
    render(<Input disabled aria-label="field" />)
    expect(screen.getByRole('textbox', { name: 'field' })).toBeDisabled()
  })

  it('supports type and other native attributes', () => {
    render(<Input type="password" aria-label="pw" />)
    expect(screen.getByLabelText('pw')).toHaveAttribute('type', 'password')
  })
})
