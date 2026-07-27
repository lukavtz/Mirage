type WSMessageHandler = (data: any) => void

interface WSMessage {
  type: string
  data?: unknown
}

class WSClient {
  private ws: WebSocket | null = null
  private url: string
  private handlers = new Map<string, Set<WSMessageHandler>>()
  private reconnectAttempts = 0
  private maxReconnectAttempts = 5
  private reconnectTimeout: ReturnType<typeof setTimeout> | null = null
  private shouldReconnect = false

  constructor() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    this.url = `${protocol}//${host}/ws`
  }

  connect(token: string) {
    this.shouldReconnect = true
    this.reconnectAttempts = 0
    this.clearReconnectTimeout()
    this.doConnect(token)
  }

  private clearReconnectTimeout() {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout)
      this.reconnectTimeout = null
    }
  }

  private doConnect(token: string) {
    this.clearReconnectTimeout()
    if (this.ws) {
      this.ws.onclose = null
      this.ws.onerror = null
      this.ws.close()
    }

    this.ws = new WebSocket(this.url)

    this.ws.onopen = () => {
      this.reconnectAttempts = 0
      this.ws?.send(JSON.stringify({ type: 'auth', token }))
    }

    this.ws.onmessage = (event: MessageEvent) => {
      try {
        const msg: WSMessage = JSON.parse(event.data)
        const typeHandlers = this.handlers.get(msg.type)
        if (typeHandlers) {
          typeHandlers.forEach(handler => handler(msg.data))
        }
      } catch {
        if (import.meta.env.DEV) console.error('WS: failed to parse message')
      }
    }

    this.ws.onclose = () => {
      if (this.shouldReconnect && this.reconnectAttempts < this.maxReconnectAttempts) {
        this.reconnectAttempts++
        const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 10000)
        this.reconnectTimeout = setTimeout(() => {
          if (this.shouldReconnect) {
            this.doConnect(token)
          }
        }, delay)
      }
    }

    this.ws.onerror = () => {
      this.ws?.close()
    }
  }

  disconnect() {
    this.shouldReconnect = false
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout)
      this.reconnectTimeout = null
    }
    this.ws?.close()
    this.ws = null
  }

  on(type: string, handler: WSMessageHandler) {
    if (!this.handlers.has(type)) {
      this.handlers.set(type, new Set())
    }
    this.handlers.get(type)!.add(handler)
    return () => this.off(type, handler)
  }

  off(type: string, handler: WSMessageHandler) {
    this.handlers.get(type)?.delete(handler)
  }

  ping() {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: 'ping' }))
    }
  }

  get connected() {
    return this.ws?.readyState === WebSocket.OPEN
  }
}

export const wsClient = new WSClient()
