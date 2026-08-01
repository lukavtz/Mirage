import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useAuth } from '@/hooks/use-auth'
import { useTheme } from '@/lib/theme-provider'
import { t, getLang, setLang } from '@/lib/i18n'
import { api } from '@/lib/api'
import { LogOut, Wifi, WifiOff, Sun, Moon, Languages, Search } from 'lucide-react'
import { useState, type KeyboardEvent } from 'react'

export function Topbar() {
  const navigate = useNavigate()
  const { logout } = useAuth()
  const { theme, toggle } = useTheme()
  const currentLang = getLang()
  const [searchValue, setSearchValue] = useState('')

  function handleSearchKey(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter' && searchValue.trim()) {
      navigate(`/search?q=${encodeURIComponent(searchValue.trim())}`)
    }
  }

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: () => api.get<{ status: string }>('/health'),
    refetchInterval: 30000,
    retry: 1,
    staleTime: 25000,
  })

  const connected = health?.status === 'ok'

  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  function handleToggleLang() {
    setLang(currentLang === 'en' ? 'ru' : 'en')
    window.location.reload()
  }

  return (
    <header className="flex items-center justify-between border-b border-border bg-card/80 backdrop-blur-md h-14 px-6 shrink-0">
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <span className="hidden md:inline">Eidos Panel v1.0</span>
      </div>

      <div className="flex items-center gap-2">
        <div className="relative hidden md:block">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
          <Input
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            onKeyDown={handleSearchKey}
            placeholder="Search sessions, domains, IPs…"
            className="pl-8 h-8 w-72 text-xs bg-muted/60 border-transparent hover:bg-muted focus-visible:bg-background focus-visible:border-brand-500/50"
          />
        </div>

        <Button variant="ghost" size="sm" onClick={handleToggleLang} title={currentLang === 'en' ? 'Switch to Russian' : 'Переключить на английский'}>
          <Languages className="h-4 w-4" />
          <span className="ml-1 text-xs">{currentLang.toUpperCase()}</span>
        </Button>

        <Button variant="ghost" size="sm" onClick={toggle}>
          {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>

        <div className="flex items-center gap-1.5 text-xs text-muted-foreground border-l border-border pl-3 ml-1">
          {connected ? (
            <>
              <Wifi className="h-3.5 w-3.5 text-success" />
              <span className="hidden sm:inline">{t('status.connected')}</span>
            </>
          ) : (
            <>
              <WifiOff className="h-3.5 w-3.5 text-destructive" />
              <span className="hidden sm:inline">{t('status.disconnected')}</span>
            </>
          )}
        </div>

        <Button variant="ghost" size="sm" onClick={handleLogout}>
          <LogOut className="h-4 w-4" />
        </Button>
      </div>
    </header>
  )
}
