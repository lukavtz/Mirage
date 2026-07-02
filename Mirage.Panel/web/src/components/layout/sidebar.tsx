import { useState } from 'react'
import { NavLink } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import {
  LayoutDashboard,
  Database,
  Hammer,
  Search,
  Settings,
  ChevronLeft,
  ChevronRight,
  Terminal,
} from 'lucide-react'

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/sessions', label: 'Sessions', icon: Database, end: false },
  { to: '/build', label: 'Build', icon: Hammer, end: false },
  { to: '/search', label: 'Search', icon: Search, end: false },
  { to: '/settings', label: 'Settings', icon: Settings, end: false },
]

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false)

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
            className={({ isActive }) => cn(
              'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
              collapsed && 'justify-center px-2',
              isActive
                ? 'bg-primary/10 text-primary font-medium'
                : 'text-muted-foreground hover:text-primary hover:bg-accent',
            )}
          >
            <item.icon className="h-4 w-4 shrink-0" />
            {!collapsed && <span>{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      <div className="border-t p-2">
        <Button
          variant="ghost"
          size="sm"
          className={cn('w-full', collapsed && 'px-0')}
          onClick={() => setCollapsed(!collapsed)}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          {!collapsed && <span className="text-xs">Collapse</span>}
        </Button>
      </div>
    </aside>
  )
}
