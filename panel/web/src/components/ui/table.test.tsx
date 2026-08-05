import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableHead,
  TableRow,
  TableCell,
  TableCaption,
} from '@/components/ui/table'

const renderTable = (extra?: React.ReactNode) =>
  render(
    <Table className="my-table">
      <TableCaption className="my-caption">Table caption</TableCaption>
      <TableHeader className="my-header">
        <TableRow className="my-row">
          <TableHead className="my-head">Name</TableHead>
          <TableHead>Status</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody className="my-body">
        <TableRow>
          <TableCell className="my-cell">Alice</TableCell>
          <TableCell>Active</TableCell>
        </TableRow>
      </TableBody>
      <TableFooter className="my-footer">
        <TableRow>
          <TableCell>Total</TableCell>
          <TableCell>1</TableCell>
        </TableRow>
      </TableFooter>
      {extra}
    </Table>,
  )

describe('Table', () => {
  it('renders all table sections with content', () => {
    renderTable()
    expect(screen.getByText('Table caption')).toBeInTheDocument()
    expect(screen.getByText('Name')).toBeInTheDocument()
    expect(screen.getByText('Status')).toBeInTheDocument()
    expect(screen.getByText('Alice')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Total')).toBeInTheDocument()
    expect(screen.getByRole('table')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Name' })).toBeInTheDocument()
  })

  it('applies custom classes', () => {
    const { container } = renderTable()
    expect(container.querySelector('table')).toHaveClass('my-table', 'w-full')
    expect(container.querySelector('caption')).toHaveClass('my-caption')
    expect(container.querySelector('thead')).toHaveClass('my-header')
    expect(container.querySelector('tbody')).toHaveClass('my-body')
    expect(container.querySelector('tfoot')).toHaveClass('my-footer')
    expect(container.querySelector('tr')).toHaveClass('my-row')
    expect(container.querySelector('th')).toHaveClass('my-head')
    expect(container.querySelectorAll('td')[0]).toHaveClass('my-cell')
  })

  it('forwards native props to cells and rows', () => {
    render(
      <Table>
        <TableBody>
          <TableRow data-testid="row">
            <TableCell data-testid="cell">X</TableCell>
          </TableRow>
        </TableBody>
      </Table>,
    )
    expect(screen.getByTestId('row')).toBeInTheDocument()
    expect(screen.getByTestId('cell')).toBeInTheDocument()
  })
})
