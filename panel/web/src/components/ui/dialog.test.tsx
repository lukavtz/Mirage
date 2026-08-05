import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import {
  Dialog,
  DialogTrigger,
  DialogContent,
  DialogHeader,
  DialogFooter,
  DialogTitle,
  DialogDescription,
  DialogClose,
  DialogOverlay,
} from '@/components/ui/dialog'

describe('Dialog', () => {
  it('opens on trigger click and renders content', async () => {
    render(
      <Dialog>
        <DialogTrigger>Open dialog</DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Dialog title</DialogTitle>
            <DialogDescription>Dialog description</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose>Close me</DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>,
    )
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Open dialog' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toBeInTheDocument()
    expect(screen.getByText('Dialog title')).toBeInTheDocument()
    expect(screen.getByText('Dialog description')).toBeInTheDocument()
    expect(screen.getByText('Close me')).toBeInTheDocument()
  })

  it('closes when the close button is clicked', async () => {
    render(
      <Dialog>
        <DialogTrigger>Open</DialogTrigger>
        <DialogContent>
          <DialogTitle>Title</DialogTitle>
          <DialogClose>X</DialogClose>
        </DialogContent>
      </Dialog>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Open' }))
    await screen.findByRole('dialog')
    fireEvent.click(screen.getByRole('button', { name: 'X' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('calls onOpenChange when opened and closed', async () => {
    const onOpenChange = vi.fn()
    render(
      <Dialog onOpenChange={onOpenChange}>
        <DialogTrigger>Toggle</DialogTrigger>
        <DialogContent>
          <DialogTitle>Title</DialogTitle>
        </DialogContent>
      </Dialog>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Toggle' }))
    await screen.findByRole('dialog')
    expect(onOpenChange).toHaveBeenCalledWith(true)
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('renders content when controlled open', () => {
    render(
      <Dialog open>
        <DialogContent>
          <DialogTitle>Always visible</DialogTitle>
        </DialogContent>
      </Dialog>,
    )
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByText('Always visible')).toBeInTheDocument()
  })

  it('renders overlay with custom className and forwards props', () => {
    render(
      <Dialog open>
        <DialogOverlay className="my-overlay" data-testid="overlay" />
        <DialogContent className="my-content">
          <DialogHeader className="my-header">
            <DialogTitle className="my-title">T</DialogTitle>
            <DialogDescription className="my-desc">D</DialogDescription>
          </DialogHeader>
          <DialogFooter className="my-footer">F</DialogFooter>
        </DialogContent>
      </Dialog>,
    )
    expect(screen.getByTestId('overlay')).toHaveClass('my-overlay')
    expect(screen.getByRole('dialog')).toHaveClass('my-content')
    expect(screen.getByText('T')).toHaveClass('my-title')
    expect(screen.getByText('D')).toHaveClass('my-desc')
    expect(screen.getByText('F')).toHaveClass('my-footer')
  })
})
