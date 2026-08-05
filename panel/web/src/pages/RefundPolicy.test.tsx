import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { I18nProvider } from '@/lib/i18n'
import RefundPolicy from './RefundPolicy'

describe('RefundPolicy', () => {
  it('renders the header and all refund sections', () => {
    render(
      <I18nProvider>
        <RefundPolicy />
      </I18nProvider>,
    )

    expect(screen.getByText('Refund Policy')).toBeInTheDocument()
    expect(screen.getByText('Last updated: July 2026')).toBeInTheDocument()

    expect(screen.getByText('Monthly Subscriptions')).toBeInTheDocument()
    expect(screen.getByText(/Refunds are processed within 5–7 business days/)).toBeInTheDocument()
    expect(screen.getByText(/full refund within 14 days/)).toBeInTheDocument()

    expect(screen.getByText('Lifetime Licenses')).toBeInTheDocument()
    expect(screen.getByText(/one-time nature/)).toBeInTheDocument()

    expect(screen.getByText('How to Request a Refund')).toBeInTheDocument()
    expect(screen.getByText(/submitted within 14 days/)).toBeInTheDocument()

    expect(screen.getByText('Exceptions')).toBeInTheDocument()
    expect(screen.getByText(/refuse refunds at our discretion/)).toBeInTheDocument()
  })
})
