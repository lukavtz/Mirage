import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useAuth } from '@/hooks/use-auth'
import { useTheme } from '@/lib/theme-provider'
import { useI18n } from '@/lib/i18n'
import { api } from '@/lib/api'
import { wsClient } from '@/lib/ws'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { LogOut, Sun, Moon, Languages, Bell, Menu } from 'lucide-react'
import { FlagIcon } from '@/components/charts/flag-icon'
import type { SessionListItem } from '@/types'

interface TopbarProps {
  onToggleMobileSidebar?: () => void
}

interface UserInfo {
  user_id: string
  username: string
  role: string
}

export function Topbar({ onToggleMobileSidebar }: TopbarProps) {
  const navigate = useNavigate()
  const { logout } = useAuth()
  const { theme, toggle } = useTheme()
  const { t, lang, setLang } = useI18n()
  const queryClient = useQueryClient()

  const [unreadCount, setUnreadCount] = useState(0)
  const [recentSessions, setRecentSessions] = useState<SessionListItem[]>([])

  const { data: userInfo } = useQuery<UserInfo>({
    queryKey: ['user-me'],
    queryFn: () => api.get<UserInfo>('/api/auth/me'),
    staleTime: 60000,
  })

  // Subscribe to new_session WS events for notification bell
  useEffect(() => {
    const unsub = wsClient.on('new_session', (data: any) => {
      setUnreadCount(c => c + 1)
      if (data) {
        setRecentSessions(prev => {
          const next = [data as SessionListItem, ...prev.filter(s => s.id !== data.id)]
          return next.slice(0, 5)
        })
      }
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
    })
    return unsub
  }, [queryClient])

  const handleBellClick = useCallback(() => {
    setUnreadCount(0)
    if (recentSessions.length === 0) {
      api.get<{ sessions: SessionListItem[] }>('/api/sessions', { limit: 5, sort: '-created_at' })
        .then(res => setRecentSessions((res.sessions ?? []).slice(0, 5)))
        .catch(() => {})
    }
  }, [recentSessions.length])

  const username = userInfo?.username ?? 'admin'
  const role = userInfo?.role ?? 'admin'
  const avatarLetter = username.charAt(0).toUpperCase()

  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  function handleToggleLang() {
    setLang(lang === 'en' ? 'ru' : 'en')
  }

  return (
    <header className="flex items-center justify-between border-b border-border bg-card/80 backdrop-blur-md h-14 px-4 md:px-6 shrink-0">
      <div className="flex items-center gap-2">
        {onToggleMobileSidebar && (
          <Button variant="ghost" size="sm" className="lg:hidden" onClick={onToggleMobileSidebar}>
            <Menu className="h-5 w-5" />
          </Button>
        )}
      </div>

      <div className="flex items-center gap-2 md:gap-3">
        <Button variant="ghost" size="sm" onClick={handleToggleLang} title={lang === 'en' ? 'Switch to Russian' : 'English'}>
          <Languages className="h-4 w-4" />
          <span className="ml-1 text-xs hidden sm:inline">{lang.toUpperCase()}</span>
        </Button>

        <Button variant="ghost" size="sm" onClick={toggle}>
          {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>

        <DropdownMenu onOpenChange={(open) => { if (open) handleBellClick() }}>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="relative">
              <Bell className="h-4 w-4" />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 h-4 min-w-4 px-1 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center">
                  {unreadCount > 99 ? '99+' : unreadCount}
                </span>
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-72">
            <div className="px-2 py-1.5 text-xs font-medium text-muted-foreground">
              {t('topbar.notifications') || 'Notifications'}
            </div>
            <DropdownMenuSeparator />
            {recentSessions.length === 0 ? (
              <div className="px-2 py-4 text-center text-xs text-muted-foreground">
                {t('topbar.no_notifications') || 'No new sessions'}
              </div>
            ) : (
              recentSessions.map((s) => (
                <DropdownMenuItem
                  key={s.id}
                  className="flex items-center gap-2 cursor-pointer"
                  onClick={() => navigate(`/sessions/${s.id}`)}
                >
                  {s.country && <FlagIcon country={s.country} className="w-4 h-3 shrink-0" />}
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium truncate">{s.ip || s.hwid || s.id}</div>
                    <div className="text-[10px] text-muted-foreground">
                      {s.created_at ? formatDistanceToNow(new Date(s.created_at), { addSuffix: true }) : ''}
                    </div>
                  </div>
                </DropdownMenuItem>
              ))
            )}
          </DropdownMenuContent>
        </DropdownMenu>

        <div className="hidden sm:flex items-center gap-2 border-l border-border pl-3 ml-1">
          <div className="h-7 w-7 rounded-full bg-foreground/10 flex items-center justify-center text-[10px] font-bold text-foreground">
            {avatarLetter}
          </div>
          <div>
            <div className="text-xs font-medium">{username}</div>
            <div className="text-[10px] text-muted-foreground capitalize">{role}</div>
          </div>
        </div>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="sm:hidden border-l border-border pl-3 ml-1 h-14 rounded-none">
              <div className="h-7 w-7 rounded-full bg-foreground/10 flex items-center justify-center text-[10px] font-bold text-foreground">
                {avatarLetter}
              </div>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <div className="px-2 py-1.5">
              <div className="text-xs font-medium">{username}</div>
              <div className="text-[10px] text-muted-foreground capitalize">{role}</div>
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={handleLogout}>
              <LogOut className="h-3.5 w-3.5 mr-2" />
              {t('auth.logout')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        <Button variant="ghost" size="sm" onClick={handleLogout} className="hidden sm:inline-flex">
          <LogOut className="h-4 w-4" />
        </Button>
      </div>
    </header>
  )
}
