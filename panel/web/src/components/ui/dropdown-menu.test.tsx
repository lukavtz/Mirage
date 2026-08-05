import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuGroup,
  DropdownMenuPortal,
  DropdownMenuRadioGroup,
  DropdownMenuSub,
} from '@/components/ui/dropdown-menu'

describe('DropdownMenu', () => {
  it('opens on trigger click and shows items', async () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open menu</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuLabel>Menu label</DropdownMenuLabel>
          <DropdownMenuItem>Item One</DropdownMenuItem>
          <DropdownMenuItem inset>Item Two</DropdownMenuItem>
          <DropdownMenuSeparator />
        </DropdownMenuContent>
      </DropdownMenu>,
    )
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
    fireEvent.pointerDown(screen.getByRole('button', { name: 'Open menu' }), { button: 0 })
    const menu = await screen.findByRole('menu')
    expect(menu).toBeInTheDocument()
    expect(screen.getByText('Menu label')).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: 'Item One' })).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: 'Item Two' })).toBeInTheDocument()
  })

  it('fires onSelect when an item is clicked', async () => {
    const onSelect = vi.fn()
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem onSelect={onSelect}>Pick me</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>,
    )
    fireEvent.pointerDown(screen.getByRole('button', { name: 'Open' }), { button: 0 })
    const item = await screen.findByRole('menuitem', { name: 'Pick me' })
    fireEvent.click(item)
    expect(onSelect).toHaveBeenCalledTimes(1)
  })

  it('does not fire onSelect for disabled items', async () => {
    const onSelect = vi.fn()
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem disabled onSelect={onSelect}>Nope</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>,
    )
    fireEvent.pointerDown(screen.getByRole('button', { name: 'Open' }), { button: 0 })
    const item = await screen.findByRole('menuitem', { name: 'Nope' })
    expect(item).toHaveAttribute('data-disabled')
    fireEvent.click(item)
    expect(onSelect).not.toHaveBeenCalled()
  })

  it('applies custom classes and renders group/portal/radio/sub passthroughs', async () => {
    render(
      <DropdownMenu>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuPortal>
          <DropdownMenuContent className="my-menu">
            <DropdownMenuGroup>
              <DropdownMenuLabel inset className="my-label">Group label</DropdownMenuLabel>
              <DropdownMenuRadioGroup>
                <DropdownMenuItem className="my-item">Radio-ish</DropdownMenuItem>
              </DropdownMenuRadioGroup>
              <DropdownMenuSub>
                <DropdownMenuItem>Sub child</DropdownMenuItem>
              </DropdownMenuSub>
            </DropdownMenuGroup>
          </DropdownMenuContent>
        </DropdownMenuPortal>
      </DropdownMenu>,
    )
    fireEvent.pointerDown(screen.getByRole('button', { name: 'Open' }), { button: 0 })
    const menu = await screen.findByRole('menu')
    expect(menu).toHaveClass('my-menu')
    expect(screen.getByText('Group label')).toHaveClass('my-label')
    expect(screen.getByRole('menuitem', { name: 'Radio-ish' })).toHaveClass('my-item')
    expect(screen.getByRole('menuitem', { name: 'Sub child' })).toBeInTheDocument()
  })
})
