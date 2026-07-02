import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/hooks/use-auth'
import { LogOut, Wifi, WifiOff } from 'lucide-react'

export function Topbar() {
  const navigate = useNavigate()
  const { logout } = useAuth()

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

  return (
    <header className="flex items-center justify-between border-b bg-card h-14 px-6 shrink-0">
      <div className="text-sm font-medium" />

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          {connected ? (
            <>
              <Wifi className="h-3.5 w-3.5 text-emerald-500" />
              <span>Connected</span>
            </>
          ) : (
            <>
              <WifiOff className="h-3.5 w-3.5 text-red-500" />
              <span>Disconnected</span>
            </>
          )}
        </div>

        <Button variant="ghost" size="sm" onClick={handleLogout}>
          <LogOut className="h-4 w-4 mr-2" />
          Logout
        </Button>
      </div>
    </header>
  )
}
