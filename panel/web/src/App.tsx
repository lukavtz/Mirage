import { useEffect, useRef, Component, type ReactNode } from 'react'
import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider, useAuth } from '@/hooks/use-auth'
import { ThemeProvider } from '@/lib/theme-provider'
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

class ErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean }> {
  constructor(props: { children: ReactNode }) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-background">
          <div className="text-center space-y-4">
            <h1 className="text-2xl font-bold">Something went wrong</h1>
            <p className="text-muted-foreground">
              An unexpected error occurred. Please refresh the page.
            </p>
            <button
              onClick={() => { this.setState({ hasError: false }); window.location.reload() }}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm"
            >
              Reload
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth()
  const connectedRef = useRef(false)

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (isAuthenticated && token && !connectedRef.current) {
      connectedRef.current = true
      wsClient.connect(token)
    }
    return () => {
      if (connectedRef.current) {
        wsClient.disconnect()
      }
    }
  }, [])

  if (isLoading) return <div>Loading...</div>
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

const router = createBrowserRouter([
  { path: '/login', element: <Login /> },
  { path: '/public', element: <PublicStatsPage /> },
  { path: '/refund-policy', element: <RefundPolicy /> },
  {
    path: '/',
    element: <ProtectedRoute><Shell /></ProtectedRoute>,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'sessions', element: <Sessions /> },
      { path: 'sessions/:id', element: <SessionDetail /> },
      { path: 'build', element: <BuildPage /> },
      { path: 'search', element: <SearchPage /> },
      { path: 'users', element: <UsersPage /> },
      { path: 'team', element: <TeamPage /> },
      { path: 'restore', element: <RestorePage /> },
      { path: 'settings', element: <Settings /> },
      { path: 'docs', element: <DocsPage /> },
      { path: 'docs/:path', element: <DocsPage /> },
      { path: '*', element: <NotFound /> },
    ],
  },
])

function NotFound() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center space-y-3">
        <h1 className="text-4xl font-bold text-muted-foreground">404</h1>
        <p className="text-sm text-muted-foreground">Page not found</p>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <ErrorBoundary>
            <RouterProvider router={router} />
          </ErrorBoundary>
        </AuthProvider>
      </QueryClientProvider>
    </ThemeProvider>
  )
}
