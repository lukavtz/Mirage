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
  { to: '/', labelKey: 'nav.dashboard', icon: LayoutDashboard, end: true },
  { to: '/sessions', labelKey: 'nav.sessions', icon: Database, end: false },
  { to: '/build', labelKey: 'nav.build', icon: Hammer, end: false },
  { to: '/restore', labelKey: 'nav.restore', icon: RotateCcw, end: false },
  { to: '/search', labelKey: 'nav.search', icon: Search, end: false },
  { to: '/docs', labelKey: 'nav.docs', icon: Book, end: false },
  { to: '/users', labelKey: 'nav.users', icon: Users, end: false },
  { to: '/team', labelKey: 'nav.team', icon: Users, end: false },
  { to: '/settings', labelKey: 'nav.settings', icon: Settings, end: false },
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
        'flex flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground transition-all duration-200',
        collapsed ? 'w-14' : 'w-56',
      )}
    >
      <div className={cn(
        'flex items-center gap-2 border-b border-sidebar-border px-3 h-14 shrink-0 relative overflow-hidden',
        collapsed && 'justify-center px-0',
      )}>
        <div className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle_at_30%_50%,hsl(262_64%_53%/0.35),transparent_70%)]" />
        <div className="relative rounded-lg bg-gradient-to-br from-brand-500 to-brand-700 p-1.5 shadow-glow">
          <Terminal className="h-4 w-4 text-white" />
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
              'relative flex items-center gap-3 rounded-lg pl-4 pr-3 py-2 text-sm transition-colors',
              'before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-0.5 before:rounded-full before:bg-transparent',
              collapsed && 'justify-center px-2 pl-2',
              isActive
                ? 'bg-sidebar-primary/15 text-sidebar-primary font-medium before:bg-brand-500'
                : 'text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-foreground',
            )}
          >
            <item.icon className="h-4 w-4 shrink-0" />
            {!collapsed && <span>{t(item.labelKey)}</span>}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-sidebar-border p-2">
        <Button
          variant="ghost"
          size="sm"
          className={cn('w-full text-sidebar-foreground/70 hover:text-sidebar-foreground hover:bg-sidebar-accent', collapsed && 'px-0')}
          onClick={toggleCollapsed}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          {!collapsed && <span className="text-xs">Collapse</span>}
        </Button>
      </div>
    </aside>
  )
}
