import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { api } from './api'

function okResponse(body: unknown, headers?: Record<string, string>) {
  return {
    ok: true,
    status: 200,
    json: async () => body as any,
    headers: { get: (k: string) => headers?.[k] ?? null },
  }
}

function errResponse(status: number, body: unknown) {
  return {
    ok: false,
    status,
    json: async () => body as any,
    headers: { get: () => null },
  }
}

describe('api client', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    localStorage.clear()
    api.clearCsrf()
    fetchMock.mockReset()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('GET', () => {
    it('returns JSON on success', async () => {
      fetchMock.mockResolvedValue(okResponse({ data: [1] }))
      const result = await api.get<any>('/api/test')
      expect(result).toEqual({ data: [1] })
    })

    it('sends the correct headers and method', async () => {
      fetchMock.mockResolvedValue(okResponse({}))
      await api.get('/api/test')
      expect(fetchMock).toHaveBeenCalledWith('/api/test', {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      })
    })

    it('builds a query string from params, filtering null/undefined/empty', async () => {
      fetchMock.mockResolvedValue(okResponse({}))
      await api.get('/api/test', { a: 1, b: 'two', c: undefined, d: null, e: '' })
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/test?a=1&b=two',
        expect.anything(),
      )
    })

    it('omits the query string when params are empty', async () => {
      fetchMock.mockResolvedValue(okResponse({}))
      await api.get('/api/test', { a: undefined })
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/test',
        expect.anything(),
      )
    })

    it('injects the Authorization header when a token exists', async () => {
      localStorage.setItem('token', 'mytoken')
      fetchMock.mockResolvedValue(okResponse({}))
      await api.get('/api/test')
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/test',
        expect.objectContaining({
          headers: expect.objectContaining({ Authorization: 'Bearer mytoken' }),
        }),
      )
    })
  })

  describe('POST', () => {
    it('sends JSON body with Content-Type', async () => {
      fetchMock.mockResolvedValue(okResponse({ saved: true }))
      const result = await api.post('/api/test', { name: 'foo' })
      expect(result).toEqual({ saved: true })
      expect(fetchMock).toHaveBeenCalledWith('/api/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'foo' }),
      })
    })
  })

  describe('PUT', () => {
    it('sends PUT with body', async () => {
      fetchMock.mockResolvedValue(okResponse({ updated: true }))
      const result = await api.put('/api/test', { id: 1 })
      expect(result).toEqual({ updated: true })
      expect(fetchMock).toHaveBeenCalledWith('/api/test', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: 1 }),
      })
    })
  })

  describe('DELETE', () => {
    it('sends DELETE without body', async () => {
      fetchMock.mockResolvedValue(okResponse({ deleted: true }))
      const result = await api.del('/api/test')
      expect(result).toEqual({ deleted: true })
      expect(fetchMock).toHaveBeenCalledWith('/api/test', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
      })
    })
  })

  describe('error handling', () => {
    it('throws ApiError on non-2xx status', async () => {
      fetchMock.mockResolvedValue(errResponse(500, { error: 'boom' }))
      await expect(api.get('/api/test')).rejects.toEqual({
        status: 500,
        error: 'boom',
      })
    })

    it('handles failed JSON parsing on error response', async () => {
      fetchMock.mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => { throw new Error('bad json') },
        headers: { get: () => null },
      })
      await expect(api.get('/api/test')).rejects.toEqual({
        status: 500,
        error: 'request failed',
      })
    })

    it('handles network failure', async () => {
      fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
      await expect(api.get('/api/test')).rejects.toThrow('Failed to fetch')
    })

    describe('401', () => {
      it('removes the token and redirects to logout', async () => {
        localStorage.setItem('token', 'tok')
        fetchMock.mockResolvedValue(errResponse(401, { error: 'unauthorized' }))
        await expect(api.get('/api/test')).rejects.toThrow('Unauthorized')
        expect(localStorage.getItem('token')).toBeNull()
      })
    })
  })

  describe('CSRF handling', () => {
    it('fetchCsrf stores the token from the X-CSRF-Token header', async () => {
      fetchMock.mockResolvedValue(okResponse({}, { 'X-CSRF-Token': 'csrfabc' }))
      const tok = await api.fetchCsrf()
      expect(tok).toBe('csrfabc')
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/csrf',
        expect.objectContaining({ method: 'GET' }),
      )
    })

    it('fetchCsrf returns null when the CSRF fetch fails', async () => {
      fetchMock.mockResolvedValue(errResponse(403, { error: 'forbidden' }))
      const tok = await api.fetchCsrf()
      expect(tok).toBeNull()
    })

    it('fetchCsrf returns null on network error', async () => {
      fetchMock.mockRejectedValue(new TypeError('net err'))
      const tok = await api.fetchCsrf()
      expect(tok).toBeNull()
    })

    it('clearCsrf clears the in-memory token', async () => {
      fetchMock.mockResolvedValue(okResponse({}, { 'X-CSRF-Token': 'abc' }))
      await api.fetchCsrf()
      api.clearCsrf()
      // subsequent POST should NOT include X-CSRF-Token
      fetchMock.mockResolvedValue(okResponse({}))
      await api.post('/api/test')
      const callHeaders = fetchMock.mock.calls[1][1].headers
      expect(callHeaders['X-CSRF-Token']).toBeUndefined()
    })

    it('retries a POST once on 403 with CSRF error after refreshing the token', async () => {
      fetchMock
        .mockResolvedValueOnce(errResponse(403, { error: 'CSRF token invalid' }))
        .mockResolvedValueOnce(okResponse({ retried: true }))
      vi.spyOn(api, 'fetchCsrf').mockResolvedValue('newcsrf')

      const result = await api.post('/api/test', { x: 1 })
      expect(result).toEqual({ retried: true })
      expect(fetchMock).toHaveBeenCalledTimes(2)
    })

    it('throws on 403 without a CSRF error', async () => {
      fetchMock.mockResolvedValue(errResponse(403, { error: 'forbidden' }))
      await expect(api.post('/api/test', { x: 1 })).rejects.toEqual({
        status: 403,
        error: 'forbidden',
      })
    })
  })
})