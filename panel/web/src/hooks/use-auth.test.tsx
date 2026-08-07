import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AuthProvider, useAuth } from './use-auth'
import type { ReactNode } from 'react'

// -- mocks --
const { mockGet, mockPost, mockFetchCsrf, mockClearCsrf } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
  mockFetchCsrf: vi.fn().mockResolvedValue('csrf-token'),
  mockClearCsrf: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    get: mockGet,
    post: mockPost,
    fetchCsrf: mockFetchCsrf,
    clearCsrf: mockClearCsrf,
  },
}))

// -- helpers --
function AuthProbe() {
  const { isAuthenticated, isLoading, totpRequired, totpToken, login, verifyTotp, logout } = useAuth()
  return (
    <div>
      <span data-testid="auth">{String(isAuthenticated)}</span>
      <span data-testid="loading">{String(isLoading)}</span>
      <span data-testid="totp-required">{String(totpRequired)}</span>
      <span data-testid="totp-token">{totpToken ?? 'null'}</span>
      <button data-testid="login" onClick={() => login('u', 'p')}>login</button>
      <button data-testid="login-no-remember" onClick={() => login('u', 'p', false)}>login-no-remember</button>
      <button data-testid="verify-totp" onClick={() => verifyTotp('123456')}>verify-totp</button>
      <button data-testid="logout" onClick={logout}>logout</button>
    </div>
  )
}

function renderWithAuth(el: ReactNode) {
  return render(<AuthProvider>{el}</AuthProvider>)
}

// -- tests --
describe('useAuth', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    vi.clearAllMocks()
    mockFetchCsrf.mockResolvedValue('csrf-token')
  })

  it('initial state: no token -> isLoading false, isAuthenticated false', async () => {
    renderWithAuth(<AuthProbe />)
    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('false')
    })
    expect(screen.getByTestId('auth')).toHaveTextContent('false')
  })

  it('localStorage token + /api/auth/me resolves -> isAuthenticated true, fetchCsrf called', async () => {
    localStorage.setItem('token', 'test-token')
    mockGet.mockResolvedValue({ user_id: '1', role: 'admin' })

    renderWithAuth(<AuthProbe />)
    await waitFor(() => {
      expect(screen.getByTestId('auth')).toHaveTextContent('true')
    })
    expect(mockGet).toHaveBeenCalledWith('/api/auth/me')
    expect(mockFetchCsrf).toHaveBeenCalled()
  })

  it('token present but /api/auth/me rejects -> token removed, isAuthenticated false', async () => {
    localStorage.setItem('token', 'bad-token')
    mockGet.mockRejectedValue(new Error('401'))

    renderWithAuth(<AuthProbe />)
    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('false')
    })
    expect(screen.getByTestId('auth')).toHaveTextContent('false')
    expect(localStorage.getItem('token')).toBeNull()
    expect(mockClearCsrf).toHaveBeenCalled()
  })

  it('login success with rememberMe -> localStorage token, isAuthenticated true', async () => {
    mockPost.mockResolvedValue({ token: 'login-token' })

    renderWithAuth(<AuthProbe />)
    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('false'))

    fireEvent.click(screen.getByTestId('login'))

    await waitFor(() => {
      expect(screen.getByTestId('auth')).toHaveTextContent('true')
    })
    expect(localStorage.getItem('token')).toBe('login-token')
    expect(sessionStorage.getItem('token')).toBeNull()
    expect(mockPost).toHaveBeenCalledWith('/api/auth/login', { username: 'u', password: 'p' })
  })

  it('login with rememberMe false -> sessionStorage token', async () => {
    mockPost.mockResolvedValue({ token: 'session-token' })

    renderWithAuth(<AuthProbe />)
    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('false'))

    fireEvent.click(screen.getByTestId('login-no-remember'))

    await waitFor(() => {
      expect(screen.getByTestId('auth')).toHaveTextContent('true')
    })
    expect(sessionStorage.getItem('token')).toBe('session-token')
    expect(localStorage.getItem('token')).toBeNull()
  })

  it('login with totp_required -> totpRequired true, totpToken set', async () => {
    mockPost.mockResolvedValue({ totp_required: true, totp_token: 'totp-key' })

    renderWithAuth(<AuthProbe />)
    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('false'))

    fireEvent.click(screen.getByTestId('login'))

    await waitFor(() => {
      expect(screen.getByTestId('totp-required')).toHaveTextContent('true')
    })
    expect(screen.getByTestId('totp-token')).toHaveTextContent('totp-key')
    expect(screen.getByTestId('auth')).toHaveTextContent('false')
  })

  it('verifyTotp success -> token stored, isAuthenticated true, totpToken null', async () => {
    mockPost.mockResolvedValueOnce({ totp_required: true, totp_token: 'totp-key' })
    mockPost.mockResolvedValueOnce({ token: 'final-token' })

    renderWithAuth(<AuthProbe />)
    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('false'))

    fireEvent.click(screen.getByTestId('login'))
    await waitFor(() => {
      expect(screen.getByTestId('totp-required')).toHaveTextContent('true')
    })
    expect(screen.getByTestId('totp-token')).toHaveTextContent('totp-key')

    fireEvent.click(screen.getByTestId('verify-totp'))
    await waitFor(() => {
      expect(screen.getByTestId('auth')).toHaveTextContent('true')
    })
    expect(screen.getByTestId('totp-token')).toHaveTextContent('null')
    expect(screen.getByTestId('totp-required')).toHaveTextContent('false')
    expect(sessionStorage.getItem('token')).toBe('final-token')
    expect(mockPost).toHaveBeenCalledWith('/api/auth/2fa/verify-login', { totp_token: 'totp-key', passcode: '123456' })
  })

  it('verifyTotp without totpToken throws error', async () => {
    let caught: unknown = null
    function ErrorProbe() {
      const { verifyTotp } = useAuth()
      return (
        <button
          data-testid="verify-bad"
          onClick={() => {
            verifyTotp('123456').catch((e: unknown) => { caught = e })
          }}
        >
          verify-bad
        </button>
      )
    }

    renderWithAuth(<ErrorProbe />)
    await waitFor(() => expect(screen.getByTestId('verify-bad')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('verify-bad'))
    await waitFor(() => {
      expect(caught).toBeInstanceOf(Error)
    })
    expect((caught as Error).message).toBe('No pending TOTP verification')
  })

  it('logout removes both storages, sets isAuthenticated false', async () => {
    localStorage.setItem('token', 'test-token')
    mockGet.mockResolvedValue({ user_id: '1', role: 'admin' })

    renderWithAuth(<AuthProbe />)
    await waitFor(() => {
      expect(screen.getByTestId('auth')).toHaveTextContent('true')
    })

    fireEvent.click(screen.getByTestId('logout'))

    expect(screen.getByTestId('auth')).toHaveTextContent('false')
    expect(localStorage.getItem('token')).toBeNull()
    expect(sessionStorage.getItem('token')).toBeNull()
    expect(mockClearCsrf).toHaveBeenCalled()
  })

  it('login with unexpected response shape throws', async () => {
    mockPost.mockResolvedValue({})

    let caught: unknown = null
    function LoginProbe() {
      const { login } = useAuth()
      return (
        <button data-testid="login-bad" onClick={() => { login('u', 'p').catch((e: unknown) => { caught = e }) }}>
          login-bad
        </button>
      )
    }

    renderWithAuth(<LoginProbe />)
    await waitFor(() => expect(screen.getByTestId('login-bad')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('login-bad'))
    await waitFor(() => {
      expect(caught).toBeInstanceOf(Error)
    })
    expect((caught as Error).message).toBe('Unexpected login response')
  })

  it('useAuth outside AuthProvider throws', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})

    function BadProbe() {
      useAuth()
      return null
    }

    expect(() => render(<BadProbe />)).toThrow('useAuth must be used within AuthProvider')
    spy.mockRestore()
  })
})