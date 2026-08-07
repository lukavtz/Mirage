import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { api } from '@/lib/api'
import { wsClient } from '@/lib/ws'
import type { StatsResponse, SystemHealth } from '@/types'

export function useDashboard() {
  const queryClient = useQueryClient()

  const statsQuery = useQuery<StatsResponse>({
    queryKey: ['stats'],
    queryFn: () => api.get<StatsResponse>('/api/stats'),
    refetchInterval: 10_000,
    refetchOnWindowFocus: false,
  })

  const healthQuery = useQuery<SystemHealth>({
    queryKey: ['system-health'],
    queryFn: () => api.get<SystemHealth>('/api/system/health'),
    refetchInterval: 30_000,
    refetchOnWindowFocus: false,
  })

  useEffect(() => {
    const handler = () => {
      queryClient.invalidateQueries({ queryKey: ['stats'] })
    }
    wsClient.on('stats_update', handler)
    wsClient.on('new_session', handler)
    return () => {
      wsClient.off('stats_update', handler)
      wsClient.off('new_session', handler)
    }
  }, [queryClient])

  return { stats: statsQuery, health: healthQuery }
}
