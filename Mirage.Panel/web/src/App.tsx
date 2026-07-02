import { useEffect } from 'react'
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
import LicensePage from '@/pages/License'

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

  useEffect(() => {
    if (isAuthenticated) {
      const token = localStorage.getItem('token')
      if (token) wsClient.connect(token)
      return () => wsClient.disconnect()
    }
  }, [isAuthenticated])

  if (isLoading) return <div>Loading...</div>
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

const router = createBrowserRouter([
  { path: '/login', element: <Login /> },
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
      { path: 'license', element: <LicensePage /> },
      { path: 'settings', element: <Settings /> },
    ],
  },
])

export default function App() {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <RouterProvider router={router} />
        </AuthProvider>
      </QueryClientProvider>
    </ThemeProvider>
  )
}
