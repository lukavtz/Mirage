import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'

describe('Tabs', () => {
  it('renders the default tab content only', () => {
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab One</TabsTrigger>
          <TabsTrigger value="tab2">Tab Two</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content One</TabsContent>
        <TabsContent value="tab2">Content Two</TabsContent>
      </Tabs>,
    )
    expect(screen.getByRole('tab', { name: 'Tab One' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Tab Two' })).toBeInTheDocument()
    expect(screen.getByText('Content One')).toBeInTheDocument()
    expect(screen.queryByText('Content Two')).not.toBeInTheDocument()
  })

  it('switches content when a trigger is clicked', () => {
    render(
      <Tabs defaultValue="tab1">
        <TabsList>
          <TabsTrigger value="tab1">Tab One</TabsTrigger>
          <TabsTrigger value="tab2">Tab Two</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">Content One</TabsContent>
        <TabsContent value="tab2">Content Two</TabsContent>
      </Tabs>,
    )
    fireEvent.mouseDown(screen.getByRole('tab', { name: 'Tab Two' }), { button: 0 })
    expect(screen.getByText('Content Two')).toBeInTheDocument()
    expect(screen.queryByText('Content One')).not.toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Tab Two' })).toHaveAttribute('data-state', 'active')
  })

  it('fires onValueChange when switching', () => {
    const onValueChange = vi.fn()
    render(
      <Tabs defaultValue="a" onValueChange={onValueChange}>
        <TabsList>
          <TabsTrigger value="a">A</TabsTrigger>
          <TabsTrigger value="b">B</TabsTrigger>
        </TabsList>
        <TabsContent value="a">A content</TabsContent>
        <TabsContent value="b">B content</TabsContent>
      </Tabs>,
    )
    fireEvent.mouseDown(screen.getByRole('tab', { name: 'B' }), { button: 0 })
    expect(onValueChange).toHaveBeenCalledWith('b')
  })

  it('supports controlled value, disabled trigger and custom classes', () => {
    render(
      <Tabs value="x">
        <TabsList className="my-list">
          <TabsTrigger value="x" className="my-trigger">X</TabsTrigger>
          <TabsTrigger value="y" disabled>Y</TabsTrigger>
        </TabsList>
        <TabsContent value="x" className="my-content">X content</TabsContent>
      </Tabs>,
    )
    expect(screen.getByRole('tab', { name: 'X' })).toHaveClass('my-trigger')
    expect(screen.getByRole('tab', { name: 'Y' })).toBeDisabled()
    expect(screen.getByText('X content')).toHaveClass('my-content')
    expect(screen.getByRole('tablist')).toHaveClass('my-list')
  })
})
