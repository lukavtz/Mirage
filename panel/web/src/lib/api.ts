const BASE_URL = ''

interface ApiError {
  status: number
  error: string
  message?: string
}

class ApiClient {
  private csrfToken: string | null = null

  private getToken(): string | null {
    return localStorage.getItem('token')
  }

  /** Fetch a fresh CSRF token from the server and cache it in memory. */
  async fetchCsrf(): Promise<string | null> {
    try {
      const token = this.getToken()
      const headers: Record<string, string> = {}
      if (token) headers['Authorization'] = `Bearer ${token}`
      const res = await fetch(`${BASE_URL}/api/csrf`, { method: 'GET', headers })
      if (!res.ok) return null
      const tok = res.headers.get('X-CSRF-Token')
      if (tok) this.csrfToken = tok
      return tok
    } catch {
      return null
    }
  }

  /** Clear cached CSRF token (call on logout). */
  clearCsrf() {
    this.csrfToken = null
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const token = this.getToken()
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (token) headers['Authorization'] = `Bearer ${token}`

    // Attach CSRF token for state-changing methods
    const needsCsrf = method === 'POST' || method === 'PUT' || method === 'DELETE' || method === 'PATCH'
    if (needsCsrf && this.csrfToken) {
      headers['X-CSRF-Token'] = this.csrfToken
    }

    const res = await fetch(`${BASE_URL}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    })

    // CSRF token expired/invalid — refresh and retry once
    if (res.status === 403 && needsCsrf) {
      const errBody = await res.json().catch(() => null)
      if (errBody?.error?.includes('CSRF')) {
        const newTok = await this.fetchCsrf()
        if (newTok) {
          headers['X-CSRF-Token'] = newTok
          const retry = await fetch(`${BASE_URL}${path}`, {
            method,
            headers,
            body: body ? JSON.stringify(body) : undefined,
          })
          if (retry.ok) return retry.json()
          const retryErr = await retry.json().catch(() => ({ error: 'request failed' }))
          throw { status: retry.status, ...retryErr } as ApiError
        }
      }
    }

    if (res.status === 401) {
      localStorage.removeItem('token')
      this.clearCsrf()
      window.location.href = '/login'
      throw new Error('Unauthorized')
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'request failed' }))
      throw { status: res.status, ...err } as ApiError
    }

    return res.json()
  }

  get<T>(path: string, params?: Record<string, any>) {
    let url = path
    if (params) {
      const qs = Object.entries(params)
        .filter(([_, v]) => v !== undefined && v !== null && v !== '')
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
        .join('&')
      if (qs) url += '?' + qs
    }
    return this.request<T>('GET', url)
  }
  post<T>(path: string, body?: unknown) { return this.request<T>('POST', path, body) }
  put<T>(path: string, body?: unknown) { return this.request<T>('PUT', path, body) }
  del<T>(path: string) { return this.request<T>('DELETE', path) }
}

export const api = new ApiClient()
