import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { I18nProvider } from '@/lib/i18n'

vi.mock('@/lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn(), fetchCsrf: vi.fn().mockResolvedValue(null), clearCsrf: vi.fn() },
}))

import { api } from '@/lib/api'
import { TotpSetupCard } from './totp-setup'

const makeQC = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })

const SETUP_RESPONSE = { secret: 'JBSWY3DPEHPK3PXP', qr_base64: 'aGVsbG8=' }

function renderCard() {
  return render(
    <I18nProvider>
      <QueryClientProvider client={makeQC()}>
        <TotpSetupCard />
      </QueryClientProvider>
    </I18nProvider>,
  )
}

describe('TotpSetupCard', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
    vi.mocked(api.get).mockResolvedValue({ totp_enabled: false })
    vi.mocked(api.post).mockResolvedValue({})
  })

  it('shows the setup button when 2FA is disabled', async () => {
    renderCard()
    expect(screen.getByText('Two-Factor Authentication')).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: 'Set up 2FA' })).toBeInTheDocument()
    expect(vi.mocked(api.get)).toHaveBeenCalledWith('/api/auth/me')
  })

  it('runs the full setup + verify flow', async () => {
    vi.mocked(api.post)
      .mockResolvedValueOnce(SETUP_RESPONSE)
      .mockResolvedValueOnce({})

    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Set up 2FA' }))

    // QR code and manual secret appear
    expect(await screen.findByAltText('TOTP QR Code')).toHaveAttribute('src', 'data:image/png;base64,aGVsbG8=')
    expect(screen.getByText('JBSWY3DPEHPK3PXP')).toBeInTheDocument()
    expect(vi.mocked(api.post)).toHaveBeenCalledWith('/api/auth/2fa/setup')

    // verify button disabled until 6 digits; non-digits stripped
    const enableBtn = screen.getByRole('button', { name: 'Enable 2FA' })
    expect(enableBtn).toBeDisabled()
    const input = screen.getByLabelText('Verification Code')
    fireEvent.change(input, { target: { value: '12x3456' } })
    expect(input).toHaveValue('123456')
    expect(enableBtn).toBeEnabled()

    fireEvent.click(enableBtn)
    await waitFor(() => {
      expect(vi.mocked(api.post)).toHaveBeenCalledWith('/api/auth/2fa/verify', { passcode: '123456' })
    })

    // success resets the flow back to the setup button
    expect(await screen.findByRole('button', { name: 'Set up 2FA' })).toBeInTheDocument()
  })

  it('cancels the setup flow and returns to the setup button', async () => {
    vi.mocked(api.post).mockResolvedValueOnce(SETUP_RESPONSE)

    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Set up 2FA' }))
    expect(await screen.findByAltText('TOTP QR Code')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(await screen.findByRole('button', { name: 'Set up 2FA' })).toBeInTheDocument()
  })

  it('shows an error message when the setup request fails', async () => {
    vi.mocked(api.post).mockRejectedValueOnce(new Error('boom'))

    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Set up 2FA' }))
    expect(await screen.findByText('Failed to initialize 2FA setup')).toBeInTheDocument()
  })

  it('shows an error message when the verification code is invalid', async () => {
    vi.mocked(api.post)
      .mockResolvedValueOnce(SETUP_RESPONSE)
      .mockRejectedValueOnce(new Error('bad code'))

    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Set up 2FA' }))
    await screen.findByAltText('TOTP QR Code')

    fireEvent.change(screen.getByLabelText('Verification Code'), { target: { value: '999999' } })
    fireEvent.click(screen.getByRole('button', { name: 'Enable 2FA' }))
    expect(await screen.findByText('Invalid code, try again')).toBeInTheDocument()
  })

  it('shows the enabled state and disables 2FA', async () => {
    vi.mocked(api.get).mockResolvedValue({ totp_enabled: true })

    renderCard()
    expect(await screen.findByText('2FA is enabled')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Disable 2FA' }))
    await waitFor(() => {
      expect(vi.mocked(api.post)).toHaveBeenCalledWith('/api/auth/2fa/disable')
    })
    expect(await screen.findByText('2FA disabled')).toBeInTheDocument()
  })

  it('shows an error message when disabling 2FA fails', async () => {
    vi.mocked(api.get).mockResolvedValue({ totp_enabled: true })
    vi.mocked(api.post).mockRejectedValue(new Error('nope'))

    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Disable 2FA' }))
    expect(await screen.findByText('Failed to disable 2FA')).toBeInTheDocument()
  })

  it('shows a spinner while the setup request is pending', async () => {
    let resolveFn: (v: unknown) => void = () => {}
    vi.mocked(api.post).mockReturnValueOnce(
      new Promise((resolve) => { resolveFn = resolve }) as never,
    )

    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Set up 2FA' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Set up 2FA' })).toBeDisabled()
    })
    expect(document.querySelector('.animate-spin')).toBeInTheDocument()

    resolveFn(SETUP_RESPONSE)
    expect(await screen.findByAltText('TOTP QR Code')).toBeInTheDocument()
  })
})
