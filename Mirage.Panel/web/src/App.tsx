import { useEffect } from 'react'
import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider, useAuth } from '@/hooks/use-auth'
import { Shell } from '@/components/layout/shell'
import { wsClient } from '@/lib/ws'
import Login from '@/pages/Login'
import Dashboard from '@/pages/Dashboard'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

function Sessions() {
  return <div className="text-muted-foreground">Sessions — coming in Phase 2</div>
}

function Build() {
  return <div className="text-muted-foreground">Build — coming in Phase 5</div>
}

function Search() {
  return <div className="text-muted-foreground">Search — coming in Phase 3</div>
}

function Settings() {
  return <div className="text-muted-foreground">Settings — coming in Phase 6</div>
}

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
      { path: 'sessions/:id', element: <Sessions /> },
      { path: 'build', element: <Build /> },
      { path: 'search', element: <Search /> },
      { path: 'settings', element: <Settings /> },
    ],
  },
])

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <RouterProvider router={router} />
      </AuthProvider>
    </QueryClientProvider>
  )
}
