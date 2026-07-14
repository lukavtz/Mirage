import { useState } from 'react'
import { NavLink } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { t } from '@/lib/i18n'
import {
  LayoutDashboard,
  Database,
  Hammer,
  Search,
  Users,
  Settings,
  ChevronLeft,
  ChevronRight,
  Terminal,
  RotateCcw,
  Book,
} from 'lucide-react'

const navItems = [
  { to: '/', labelKey: 'nav.dashboard', icon: LayoutDashboard, end: true, desc: 'Main statistics and live data' },
  { to: '/sessions', labelKey: 'nav.sessions', icon: Database, end: false, desc: 'All collected logs' },
  { to: '/build', labelKey: 'nav.build', icon: Hammer, end: false, desc: 'Build stealer executable' },
  { to: '/restore', labelKey: 'nav.restore', icon: RotateCcw, end: false, desc: 'Cookie restore via proxy' },
  { to: '/search', labelKey: 'nav.search', icon: Search, end: false, desc: 'Search stolen data' },
  { to: '/docs', labelKey: 'nav.docs', icon: Book, end: false, desc: 'Documentation' },
  { to: '/users', labelKey: 'nav.users', icon: Users, end: false, desc: 'User management' },
  { to: '/team', labelKey: 'nav.team', icon: Users, end: false, desc: 'Team management' },
  { to: '/settings', labelKey: 'nav.settings', icon: Settings, end: false, desc: 'Panel configuration' },
]

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(() => {
    const saved = localStorage.getItem('sidebar_collapsed')
    return saved === 'true'
  })

  const toggleCollapsed = () => {
    setCollapsed(prev => {
      const next = !prev
      localStorage.setItem('sidebar_collapsed', String(next))
      return next
    })
  }

  return (
    <aside
      className={cn(
        'flex flex-col border-r bg-card transition-all duration-200',
        collapsed ? 'w-14' : 'w-56',
      )}
    >
      <div className={cn(
        'flex items-center gap-2 border-b px-3 h-14 shrink-0',
        collapsed && 'justify-center px-0',
      )}>
        <div className="rounded-lg bg-primary p-1.5">
          <Terminal className="h-4 w-4 text-primary-foreground" />
        </div>
        {!collapsed && <span className="font-semibold text-sm tracking-wide">Eidos Panel</span>}
      </div>

      <nav className="flex-1 space-y-1 p-2">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            title={t(item.labelKey)}
            className={({ isActive }) => cn(
              'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
              collapsed && 'justify-center px-2',
              isActive
                ? 'bg-primary/10 text-primary font-medium'
                : 'text-muted-foreground hover:text-primary hover:bg-accent',
            )}
          >
            <item.icon className="h-4 w-4 shrink-0" />
            {!collapsed && <span>{t(item.labelKey)}</span>}
          </NavLink>
        ))}
      </nav>

      <div className="border-t p-2">
        <Button
          variant="ghost"
          size="sm"
          className={cn('w-full', collapsed && 'px-0')}
          onClick={toggleCollapsed}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          {!collapsed && <span className="text-xs">Collapse</span>}
        </Button>
      </div>
    </aside>
  )
}
