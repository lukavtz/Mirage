import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import {
  AlertDialog,
  AlertDialogTrigger,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogFooter,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogOverlay,
} from '@/components/ui/alert-dialog'

const renderDialog = (onConfirm = vi.fn(), onCancel = vi.fn()) =>
  render(
    <AlertDialog>
      <AlertDialogTrigger>Delete item</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Are you sure?</AlertDialogTitle>
          <AlertDialogDescription>This cannot be undone.</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={onCancel}>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={onConfirm}>Confirm</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>,
  )

describe('AlertDialog', () => {
  it('opens on trigger click and shows content', async () => {
    renderDialog()
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Delete item' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toBeInTheDocument()
    expect(screen.getByText('Are you sure?')).toBeInTheDocument()
    expect(screen.getByText('This cannot be undone.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument()
  })

  it('fires confirm callback and closes on confirm', async () => {
    const onConfirm = vi.fn()
    const onCancel = vi.fn()
    renderDialog(onConfirm, onCancel)
    fireEvent.click(screen.getByRole('button', { name: 'Delete item' }))
    await screen.findByRole('alertdialog')
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(onConfirm).toHaveBeenCalledTimes(1)
    expect(onCancel).not.toHaveBeenCalled()
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument())
  })

  it('fires cancel callback and closes on cancel', async () => {
    const onConfirm = vi.fn()
    const onCancel = vi.fn()
    renderDialog(onConfirm, onCancel)
    fireEvent.click(screen.getByRole('button', { name: 'Delete item' }))
    await screen.findByRole('alertdialog')
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onCancel).toHaveBeenCalledTimes(1)
    expect(onConfirm).not.toHaveBeenCalled()
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument())
  })

  it('renders controlled open with overlay and custom classes', () => {
    render(
      <AlertDialog open>
        <AlertDialogOverlay className="my-overlay" data-testid="overlay" />
        <AlertDialogContent className="my-content">
          <AlertDialogHeader className="my-header">
            <AlertDialogTitle className="my-title">T</AlertDialogTitle>
            <AlertDialogDescription className="my-desc">D</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="my-footer">F</AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>,
    )
    expect(screen.getByTestId('overlay')).toHaveClass('my-overlay')
    expect(screen.getByRole('alertdialog')).toHaveClass('my-content')
    expect(screen.getByText('T')).toHaveClass('my-title')
    expect(screen.getByText('D')).toHaveClass('my-desc')
    expect(screen.getByText('F')).toHaveClass('my-footer')
  })
})
