import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider } from '@/hooks/use-auth'
import { I18nProvider } from '@/lib/i18n'
import { ThemeProvider } from '@/lib/theme-provider'

vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    del: vi.fn(),
    fetchCsrf: vi.fn().mockResolvedValue(null),
    clearCsrf: vi.fn(),
  },
}))

import { api } from '@/lib/api'
import Login from './Login'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const renderPage = () =>
  render(
    <QueryClientProvider client={qc()}>
      <MemoryRouter>
        <I18nProvider>
          <ThemeProvider>
            <AuthProvider>
              <Login />
            </AuthProvider>
          </ThemeProvider>
        </I18nProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )

// fetch() response shim for the forgot-password/reset-password flows.
const fetchRes = (ok: boolean, body: unknown) => ({
  ok,
  status: ok ? 200 : 400,
  json: async () => body,
})

beforeEach(() => {
  localStorage.clear()
  sessionStorage.clear()
  vi.clearAllMocks()
  vi.mocked(api.post).mockResolvedValue({ token: 'tok123' })
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('Login', () => {
  it('renders username, password and sign-in button', () => {
    renderPage()
    expect(screen.getByLabelText('Username')).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeInTheDocument()
    expect(screen.getByLabelText('Remember me')).toBeChecked()
  })

  it('shows validation errors on empty submit and does not call the API', () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Sign In' }))
    expect(screen.getByText('Enter your username to continue.')).toBeInTheDocument()
    expect(screen.getByText('Enter your password to continue.')).toBeInTheDocument()
    expect(api.post).not.toHaveBeenCalled()
  })

  it('submits credentials to the login endpoint on success', async () => {
    renderPage()
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'secret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign In' }))
    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/api/auth/login', { username: 'admin', password: 'secret' })
    })
    await waitFor(() => expect(api.fetchCsrf).toHaveBeenCalled())
    expect(localStorage.getItem('token')).toBe('tok123')
  })

  it('shows the error message when login fails', async () => {
    vi.mocked(api.post).mockRejectedValueOnce(new Error('Invalid credentials'))
    renderPage()
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'wrong' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign In' }))
    expect(await screen.findByText('Invalid credentials')).toBeInTheDocument()
  })

  it('shows the TOTP step when the server requires 2FA and verifies the passcode', async () => {
    vi.mocked(api.post)
      .mockResolvedValueOnce({ totp_required: true, totp_token: 'tt' })
      .mockResolvedValue({ token: 'tok2' })
    renderPage()
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'secret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign In' }))

    expect(await screen.findByText('Two-Factor Authentication')).toBeInTheDocument()
    const otpInputs = screen.getAllByRole('textbox')
    expect(otpInputs).toHaveLength(6)
    otpInputs.forEach((input, i) => fireEvent.change(input, { target: { value: String(i + 1) } }))
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/api/auth/2fa/verify-login', {
        totp_token: 'tt',
        passcode: '123456',
      })
    })
  })

  it('stores the token in sessionStorage when rememberMe is unchecked', async () => {
    renderPage()
    fireEvent.click(screen.getByLabelText('Remember me'))
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'secret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign In' }))
    await waitFor(() => expect(sessionStorage.getItem('token')).toBe('tok123'))
    expect(localStorage.getItem('token')).toBeNull()
  })

  it('toggles password visibility', () => {
    renderPage()
    const pwd = screen.getByLabelText('Password')
    expect(pwd).toHaveAttribute('type', 'password')
    fireEvent.click(screen.getByRole('button', { name: 'Show password' }))
    expect(pwd).toHaveAttribute('type', 'text')
    fireEvent.click(screen.getByRole('button', { name: 'Hide password' }))
    expect(pwd).toHaveAttribute('type', 'password')
  })

  it('runs the forgot-password request and reset flow', async () => {
    const fetchMock = vi.fn()
    fetchMock.mockResolvedValueOnce(fetchRes(true, { token: 'reset-tok' }))
    fetchMock.mockResolvedValueOnce(fetchRes(true, {}))
    vi.stubGlobal('fetch', fetchMock)

    renderPage()
    fireEvent.click(screen.getByText('Forgot password?'))
    expect(await screen.findByText('Reset password')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'admin' } })
    fireEvent.click(screen.getByRole('button', { name: 'Generate reset token' }))
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/auth/forgot-password',
        expect.objectContaining({ body: JSON.stringify({ username: 'admin' }) }),
      )
    })

    expect(await screen.findByText('Set new password')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Reset code'), { target: { value: 'reset-tok' } })
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'newpass123' } })
    fireEvent.click(screen.getByRole('button', { name: 'Reset password' }))
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/auth/reset-password',
        expect.objectContaining({ body: JSON.stringify({ token: 'reset-tok', new_password: 'newpass123' }) }),
      )
    })
    expect(await screen.findByRole('button', { name: 'Sign In' })).toBeInTheDocument()
    expect(screen.getByText('Welcome back')).toBeInTheDocument()
  })

  it('shows a server-provided error when the forgot request fails', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(fetchRes(false, { error: 'No such user' })))
    renderPage()
    fireEvent.click(screen.getByText('Forgot password?'))
    await screen.findByText('Reset password')
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'ghost' } })
    fireEvent.click(screen.getByRole('button', { name: 'Generate reset token' }))
    expect(await screen.findByText('No such user')).toBeInTheDocument()
  })

  it('shows a generic error when the forgot request throws', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network down')))
    renderPage()
    fireEvent.click(screen.getByText('Forgot password?'))
    await screen.findByText('Reset password')
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'ghost' } })
    fireEvent.click(screen.getByRole('button', { name: 'Generate reset token' }))
    expect(await screen.findByText('Failed to process request')).toBeInTheDocument()
  })

  it('returns to login from the forgot view via back button', async () => {
    renderPage()
    fireEvent.click(screen.getByText('Forgot password?'))
    fireEvent.click(await screen.findByText(/Back to login/))
    expect(await screen.findByRole('button', { name: 'Sign In' })).toBeInTheDocument()
  })

  it('toggles the interface language', () => {
    renderPage()
    const langBtn = screen.getByRole('button', { name: 'RU' })
    fireEvent.click(langBtn)
    expect(screen.getByRole('button', { name: 'EN' })).toBeInTheDocument()
  })

  it('switches the theme to light', () => {
    renderPage()
    const lightBtn = screen.getByRole('button', { name: 'Use light theme' })
    expect(lightBtn).toHaveAttribute('aria-pressed', 'false')
    fireEvent.click(lightBtn)
    expect(lightBtn).toHaveAttribute('aria-pressed', 'true')
  })
})
