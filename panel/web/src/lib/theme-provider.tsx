import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

type Theme = 'dark' | 'light'

export const ACCENT_PRESETS = ['#3b82f6', '#22c55e', '#a855f7', '#ef4444', '#f97316', '#ec4899'] as const

interface ThemeContextType {
  theme: Theme
  setTheme: (t: Theme) => void
  toggle: () => void
  accent: string
  setAccent: (c: string) => void
}

const ThemeContext = createContext<ThemeContextType>({
  theme: 'dark', setTheme: () => {}, toggle: () => {},
  accent: '#3b82f6', setAccent: () => {},
})

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = localStorage.getItem('theme') as Theme | null
    return saved ?? 'dark'
  })

  const [accent, setAccent] = useState(() => {
    return localStorage.getItem('accent_color') ?? '#3b82f6'
  })

  useEffect(() => {
    const root = document.documentElement
    root.classList.toggle('dark', theme === 'dark')
    root.classList.toggle('light', theme === 'light')
    root.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  useEffect(() => {
    document.documentElement.style.setProperty('--accent', accent)
    document.documentElement.style.setProperty('--accent-foreground', '#ffffff')
    localStorage.setItem('accent_color', accent)
  }, [accent])

  const toggle = () => setTheme(t => t === 'dark' ? 'light' : 'dark')

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggle, accent, setAccent }}>
      {children}
    </ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)
