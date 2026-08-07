import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { wsClient } from './ws'

class MockWebSocket {
  static OPEN = 1
  static CONNECTING = 0
  readyState = 0
  url: string
  sent: string[] = []
  onopen: (() => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null

  constructor(url: string) { this.url = url }

  send(data: string) { this.sent.push(data) }

  close() {
    this.readyState = 3
    this.onclose?.()
  }

  _open() {
    this.readyState = MockWebSocket.OPEN
    this.onopen?.()
  }

  _message(data: string) {
    this.onmessage?.({ data } as MessageEvent)
  }

  _error() {
    this.readyState = 3
    this.onerror?.()
  }
}

let currentWs: MockWebSocket

beforeEach(() => {
  currentWs = new MockWebSocket('')

  vi.stubGlobal('WebSocket', class extends MockWebSocket {
    constructor(url: string) {
      super(url)
      currentWs = this
    }
  })
})

afterEach(() => {
  wsClient.disconnect()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('WSClient', () => {
  it('connects with the correct WebSocket URL', () => {
    wsClient.connect('tok')
    expect(currentWs.url).toMatch(/^ws:\/\//)
    expect(currentWs.url).toContain('/ws')
  })

  it('sends an auth message on open', () => {
    wsClient.connect('tok')
    currentWs._open()
    expect(currentWs.sent).toContain(JSON.stringify({ type: 'auth', token: 'tok' }))
  })

  it('dispatches messages to registered handlers by type', () => {
    const handler = vi.fn()
    wsClient.on('log', handler)
    wsClient.connect('tok')
    currentWs._open()
    currentWs._message(JSON.stringify({ type: 'log', data: { id: 1 } }))
    expect(handler).toHaveBeenCalledWith({ id: 1 })
  })

  it('does not crash on unregistered message types', () => {
    wsClient.connect('tok')
    currentWs._open()
    expect(() =>
      currentWs._message(JSON.stringify({ type: 'unknown', data: {} })),
    ).not.toThrow()
  })

  it('does not crash on invalid JSON', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    wsClient.connect('tok')
    currentWs._open()
    currentWs._message('not json')
    expect(spy).toHaveBeenCalled()
    spy.mockRestore()
  })

  it('removes a handler via off', () => {
    const handler = vi.fn()
    wsClient.on('log', handler)
    wsClient.off('log', handler)
    wsClient.connect('tok')
    currentWs._open()
    currentWs._message(JSON.stringify({ type: 'log', data: {} }))
    expect(handler).not.toHaveBeenCalled()
  })

  it('unsubscribes via the returned function', () => {
    const handler = vi.fn()
    const unsub = wsClient.on('log', handler)
    unsub()
    wsClient.connect('tok')
    currentWs._open()
    currentWs._message(JSON.stringify({ type: 'log', data: {} }))
    expect(handler).not.toHaveBeenCalled()
  })

  it('disconnect closes the socket and clears state', () => {
    wsClient.connect('tok')
    currentWs._open()
    expect(wsClient.connected).toBe(true)
    wsClient.disconnect()
    expect(wsClient.connected).toBe(false)
  })

  it('reconnects on close up to maxReconnectAttempts', () => {
    vi.useFakeTimers()
    wsClient.connect('tok')
    currentWs._open()
    currentWs.close()
    vi.advanceTimersByTime(2000)
    expect(wsClient.connected).toBe(false)
  })

  it('stops reconnecting after disconnect', () => {
    vi.useFakeTimers()
    wsClient.connect('tok')
    currentWs._open()
    wsClient.disconnect()
    vi.advanceTimersByTime(10000)
  })

  it('ping sends a ping message when connected', () => {
    wsClient.connect('tok')
    currentWs._open()
    wsClient.ping()
    expect(currentWs.sent).toContain(JSON.stringify({ type: 'ping' }))
  })

  it('ping is a no-op when not connected', () => {
    wsClient.connect('tok')
    wsClient.ping()
    expect(currentWs.sent).not.toContain(JSON.stringify({ type: 'ping' }))
  })

  it('connected getter reflects WebSocket state', () => {
    expect(wsClient.connected).toBe(false)
    wsClient.connect('tok')
    currentWs._open()
    expect(wsClient.connected).toBe(true)
  })
})