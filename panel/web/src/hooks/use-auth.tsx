import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react'
import { api } from '@/lib/api'

interface AuthContextType {
  isAuthenticated: boolean
  isLoading: boolean
  login: (username: string, password: string) => Promise<LoginResult>
  verifyTotp: (passcode: string) => Promise<void>
  logout: () => void
  totpRequired: boolean
  totpToken: string | null
}

type LoginResult = { ok: true } | { totp_required: true; totp_token: string }

const AuthContext = createContext<AuthContextType | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [totpToken, setTotpToken] = useState<string | null>(null)

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) {
      setIsAuthenticated(false)
      setIsLoading(false)
      return
    }
    api.get<{ user_id: string; role: string }>('/api/auth/me')
      .then(() => {
        setIsAuthenticated(true)
        api.fetchCsrf()
      })
      .catch(() => {
        localStorage.removeItem('token')
        api.clearCsrf()
        setIsAuthenticated(false)
      })
      .finally(() => setIsLoading(false))
  }, [])

  const login = useCallback(async (username: string, password: string): Promise<LoginResult> => {
    const res = await api.post<{ token?: string; totp_required?: boolean; totp_token?: string }>(
      '/api/auth/login',
      { username, password },
    )
    if (res.totp_required && res.totp_token) {
      setTotpToken(res.totp_token)
      return { totp_required: true, totp_token: res.totp_token }
    }
    if (res.token) {
      localStorage.setItem('token', res.token)
      await api.fetchCsrf()
      setIsAuthenticated(true)
      setTotpToken(null)
      return { ok: true }
    }
    throw new Error('Unexpected login response')
  }, [])

  const verifyTotp = useCallback(async (passcode: string) => {
    if (!totpToken) throw new Error('No pending TOTP verification')
    const res = await api.post<{ token: string }>('/api/auth/2fa/verify-login', {
      totp_token: totpToken,
      passcode,
    })
    localStorage.setItem('token', res.token)
    await api.fetchCsrf()
    setIsAuthenticated(true)
    setTotpToken(null)
  }, [totpToken])

  const logout = useCallback(() => {
    localStorage.removeItem('token')
    api.clearCsrf()
    setIsAuthenticated(false)
    setTotpToken(null)
  }, [])

  return (
    <AuthContext.Provider value={{
      isAuthenticated,
      isLoading,
      login,
      verifyTotp,
      logout,
      totpRequired: totpToken !== null,
      totpToken,
    }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
