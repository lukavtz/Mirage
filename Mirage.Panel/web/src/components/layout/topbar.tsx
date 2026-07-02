import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/hooks/use-auth'
import { useTheme } from '@/lib/theme-provider'
import { t, getLang, setLang } from '@/lib/i18n'
import { LogOut, Wifi, WifiOff, Sun, Moon } from 'lucide-react'

export function Topbar() {
  const navigate = useNavigate()
  const { logout } = useAuth()
  const { theme, toggle } = useTheme()
  const currentLang = getLang()

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const res = await fetch('/health')
      if (!res.ok) throw new Error('unhealthy')
      return res.json() as Promise<{ status: string }>
    },
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
    <header className="flex items-center justify-between border-b bg-card h-14 px-6 shrink-0">
      <div className="text-sm font-medium" />

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          {connected ? (
            <>
              <Wifi className="h-3.5 w-3.5 text-emerald-500" />
              <span>{t('connected')}</span>
            </>
          ) : (
            <>
              <WifiOff className="h-3.5 w-3.5 text-red-500" />
              <span>{t('disconnected')}</span>
            </>
          )}
        </div>

        <Button variant="ghost" size="sm" onClick={toggle}>
          {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>

        <Button variant="ghost" size="sm" onClick={handleToggleLang}>
          {currentLang.toUpperCase()}
        </Button>

        <Button variant="ghost" size="sm" onClick={handleLogout}>
          <LogOut className="h-4 w-4 mr-2" />
          {t('logout')}
        </Button>
      </div>
    </header>
  )
}
