import { FlagIcon } from '@/components/charts/flag-icon'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { ChevronRight } from 'lucide-react'
import { useI18n } from '@/lib/i18n'
import { countryName } from '@/lib/countries'
import { useNavigate } from 'react-router-dom'

interface TopCountriesProps {
  data: Array<{ country_code: string; count: number }>
  isLoading: boolean
  onViewAll?: () => void
}
export function TopCountries({ data, isLoading, onViewAll }: TopCountriesProps) {
  const { t, lang } = useI18n()
  const navigate = useNavigate()

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 7 }).map((_, i) => (
          <Skeleton key={i} className="h-9 w-full rounded-md" />
        ))}
      </div>
    )
  }

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-40 text-muted-foreground text-sm">
        {t('chart.no_geo')}
      </div>
    )
  }

  const total = data.reduce((s, d) => s + d.count, 0)
  const max = Math.max(...data.map(d => d.count), 1)

  return (
    <div className="space-y-1.5">
      {data.slice(0, 7).map((d, i) => {
        const pct = ((d.count / total) * 100).toFixed(1)
        const ratio = d.count / max
        const name = countryName(d.country_code, lang)
        return (
          <button
            key={d.country_code}
            onClick={() => navigate(`/sessions?country=${d.country_code}`)}
            className="group w-full flex items-center gap-3 py-1.5 px-2 hover:bg-accent/50 transition-colors text-left"
          >
            <span className="text-[11px] mono text-muted-foreground/60 w-3 text-right tabular-nums">
              {String(i + 1).padStart(2, '0')}
            </span>
            <FlagIcon country={d.country_code} width={18} height={18} />
            <span className="text-[12.5px] font-medium flex-1 truncate text-foreground">
              {name}
            </span>
            <span className="mono text-[11px] tabular-nums text-foreground w-10 text-right">
              {d.count.toLocaleString()}
            </span>
            <span className="text-[10px] text-muted-foreground mono tabular-nums w-10 text-right">
              {pct}%
            </span>
            <div className="w-16 h-1 bg-muted overflow-hidden">
              <div
                className="h-full bg-foreground transition-all duration-500 ease-out"
                style={{ width: `${ratio * 100}%` }}
              />
            </div>
          </button>
        )
      })}
      {data.length > 7 && (
        <Button
          variant="ghost"
          size="sm"
          className="w-full mt-2 text-[11px] uppercase tracking-[0.16em] text-muted-foreground hover:text-foreground"
          onClick={() => onViewAll ? onViewAll() : navigate('/sessions')}
        >
          {t('common.view_all')} <ChevronRight className="h-3 w-3 ml-1" />
        </Button>
      )}
    </div>
  )
}
