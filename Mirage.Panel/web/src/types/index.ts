export interface LoginRequest { username: string; password: string }
export interface LoginResponse { token: string; expires_at: string }

export interface StatsResponse {
  sessions: { total: number; today: number }
  passwords: { total: number }
  cookies: { total: number }
  cards: { total: number }
  wallets: { total: number }
  geo: Array<{ country: string; count: number }>
  browsers: Array<{ name: string; count: number }>
  timeline: Array<{ date: string; count: number }>
  top_domains: Array<{ domain: string; count: number }>
}

export interface Session {
  id: string
  build_id?: string
  hwid?: string
  os?: string
  username?: string
  ip?: string
  country_code?: string
  passwords_count: number
  cookies_count: number
  cards_count: number
  wallets_count: number
  files_count: number
  created_at: string
}

export interface WSMessage {
  type: 'stats_update' | 'new_session' | 'pong'
  data?: unknown
}

export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  per_page: number
}

export interface ApiError {
  status: number
  error: string
  message?: string
}
