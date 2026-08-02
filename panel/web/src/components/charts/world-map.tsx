import { useMemo, useState, useRef, useCallback, useEffect } from 'react'
import { Skeleton } from '@/components/ui/skeleton'
import { FlagIcon } from '@/components/charts/flag-icon'
import { COUNTRY_NAMES } from '@/lib/countries'
import { useI18n } from '@/lib/i18n'
import { feature } from 'topojson-client'
import { geoNaturalEarth1, geoPath } from 'd3-geo'
import type { FeatureCollection, Geometry } from 'geojson'
import worldTopo from 'world-atlas/countries-110m.json'

interface WorldMapProps {
  data: Array<{ country_code: string; count: number }>
  isLoading: boolean
}

interface CountryProps { name: string }

const COUNTRY_CENTROIDS: Record<string, [number, number]> = {
  US: [-98, 39], CA: [-106, 56], MX: [-102, 23],
  BR: [-51, -14], AR: [-63, -38], CL: [-71, -35], CO: [-74, 4], PE: [-75, -9], VE: [-66, 8],
  GB: [-3, 55], IE: [-8, 53], FR: [2, 46], DE: [10, 51], NL: [5, 52], BE: [4, 50], ES: [-3, 40], IT: [12, 42],
  PT: [-8, 39], CH: [8, 47], AT: [14, 47], PL: [19, 52], CZ: [15, 49], SK: [19, 48], HU: [19, 47],
  RO: [25, 45], BG: [25, 42], GR: [22, 39], SE: [18, 62], NO: [10, 64], FI: [26, 64], DK: [10, 56],
  UA: [32, 49], RU: [105, 61], BY: [28, 53], LT: [23, 55], LV: [24, 57], EE: [26, 59],
  TR: [35, 39], IL: [35, 31], SA: [45, 24], AE: [54, 24], EG: [30, 27], NG: [8, 9], ZA: [25, -29], KE: [38, 0], MA: [-7, 31],
  IN: [78, 22], PK: [69, 30], BD: [90, 24], CN: [104, 35], JP: [138, 36], KR: [128, 36], TW: [121, 24],
  TH: [100, 15], VN: [108, 14], ID: [113, -2], MY: [101, 4], PH: [121, 13], SG: [103, 1],
  AU: [133, -25], NZ: [172, -41],
}

const ISO3_TO_ISO2: Record<string, string> = {
  USA: 'US', CAN: 'CA', MEX: 'MX',
  BRA: 'BR', ARG: 'AR', CHL: 'CL', COL: 'CO', PER: 'PE', VEN: 'VE',
  GBR: 'GB', IRL: 'IE', FRA: 'FR', DEU: 'DE', NLD: 'NL', BEL: 'BE', ESP: 'ES', ITA: 'IT',
  PRT: 'PT', CHE: 'CH', AUT: 'AT', POL: 'PL', CZE: 'CZ', SVK: 'SK', HUN: 'HU',
  ROU: 'RO', BGR: 'BG', GRC: 'GR', SWE: 'SE', NOR: 'NO', FIN: 'FI', DNK: 'DK',
  UKR: 'UA', RUS: 'RU', BLR: 'BY', LTU: 'LT', LVA: 'LV', EST: 'EE',
  TUR: 'TR', ISR: 'IL', SAU: 'SA', ARE: 'AE', EGY: 'EG', NGA: 'NG', ZAF: 'ZA', KEN: 'KE', MAR: 'MA',
  IND: 'IN', PAK: 'PK', BGD: 'BD', CHN: 'CN', JPN: 'JP', KOR: 'KR', TWN: 'TW',
  THA: 'TH', VNM: 'VN', IDN: 'ID', MYS: 'MY', PHL: 'PH', SGP: 'SG',
  AUS: 'AU', NZL: 'NZ',
}

const W = 720
const H = 360

interface Point { code: string; count: number; cx: number; cy: number; ratio: number }
interface LandFeature { d: string; iso2: string; hasData: boolean; ratio: number }

export function WorldMap({ data, isLoading }: WorldMapProps) {
  const { t } = useI18n()
  const [hovered, setHovered] = useState<{ code: string; x: number; y: number; d: number } | null>(null)
  const [activeCountry, setActiveCountry] = useState<string | null>(null)
  const containerRef = useRef<HTMLDivElement | null>(null)

  const projection = useMemo(() => geoNaturalEarth1().fitSize([W, H], { type: 'Sphere' } as never), [])
  const path = useMemo(() => geoPath(projection), [projection])

  const { total, points, lands } = useMemo(() => {
    const m = data.reduce((acc, d) => Math.max(acc, d.count), 0) || 1
    const tot = data.reduce((s, d) => s + d.count, 0)
    const pts: Point[] = []
    const map = new Map<string, number>()
    for (const d of data) {
      map.set(d.country_code, d.count)
      const c = COUNTRY_CENTROIDS[d.country_code]
      if (!c) continue
      const projected = projection(c)
      if (!projected) continue
      pts.push({ code: d.country_code, count: d.count, cx: projected[0], cy: projected[1], ratio: d.count / m })
    }
    const fc = feature(worldTopo as never, (worldTopo as any).objects.countries) as unknown as FeatureCollection<Geometry, CountryProps>
    const landFeatures: LandFeature[] = fc.features.map(f => {
      const iso2 = ISO3_TO_ISO2[(f.properties as any).name] || ''
      const count = map.get(iso2) ?? 0
      return { d: path(f) || '', iso2, hasData: count > 0, ratio: count / m }
    }).filter(s => s.d)
    return { total: tot, points: pts, lands: landFeatures }
  }, [data, path, projection])

  const onMove = useCallback((e: React.MouseEvent) => {
    if (!containerRef.current) return
    const rect = containerRef.current.getBoundingClientRect()
    const x = ((e.clientX - rect.left) / rect.width) * W
    const y = ((e.clientY - rect.top) / rect.height) * H
    let best: { code: string; x: number; y: number; d: number } | null = null
    for (const p of points) {
      const dx = p.cx - x
      const dy = p.cy - y
      const d2 = dx * dx + dy * dy
      if (!best || d2 < best.d) best = { code: p.code, x: p.cx, y: p.cy, d: d2 }
    }
    if (best && best.d < 144) setHovered(best)
    else setHovered(null)
  }, [points])

  useEffect(() => { if (isLoading) { setHovered(null); setActiveCountry(null) } }, [isLoading])

  if (isLoading) {
    return <Skeleton className="h-full min-h-[280px] w-full rounded-lg" />
  }

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-full min-h-[280px] text-muted-foreground text-sm">
        {t('chart.no_geo')}
      </div>
    )
  }

  return (
    <div ref={containerRef} className="relative w-full h-full" onMouseMove={onMove} onMouseLeave={() => setHovered(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-full block">
        <defs>
          <radialGradient id="dot-core" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="hsl(var(--status-online))" stopOpacity="1" />
            <stop offset="100%" stopColor="hsl(var(--status-online))" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* Subtle graticule */}
        <g stroke="hsl(var(--border))" strokeWidth="0.15" fill="none" opacity="0.5">
          {[-60, -30, 0, 30, 60].map(lat => (
            <line key={`g${lat}`} x1="0" y1={H/2 - (lat / 90) * (H/2)} x2={W} y2={H/2 - (lat / 90) * (H/2)} strokeDasharray="1 6" />
          ))}
          {[-120, -60, 0, 60, 120].map(lon => (
            <line key={`m${lon}`} x1={W/2 + (lon / 180) * (W/2)} y1="0" x2={W/2 + (lon / 180) * (W/2)} y2={H} strokeDasharray="1 6" />
          ))}
        </g>

        {/* Landmasses */}
        <g>
          {lands.map((s, i) => {
            const intensity = s.hasData ? Math.min(1, 0.35 + s.ratio * 0.55) : 0
            const isActive = s.iso2 === activeCountry
            return (
              <path
                key={i}
                d={s.d}
                fill={s.hasData ? `hsl(var(--status-online) / ${intensity})` : 'transparent'}
                stroke={s.hasData ? 'hsl(var(--status-online))' : 'hsl(var(--border))'}
                strokeOpacity={s.hasData ? 0.95 : 1}
                strokeWidth={isActive ? 1.4 : (s.hasData ? 0.7 : 0.5)}
                strokeLinejoin="round"
                style={{ transition: 'fill 0.2s ease, stroke-width 0.15s ease' }}
                onMouseEnter={() => setActiveCountry(s.iso2 || null)}
                onMouseLeave={() => setActiveCountry(null)}
              />
            )
          })}
        </g>
        <g>
          {points.map(p => (
            <g key={p.code}>
              <circle cx={p.cx} cy={p.cy} r={5 + p.ratio * 10} fill="hsl(var(--status-online))" opacity="0.18" />
              <circle cx={p.cx} cy={p.cy} r={3 + p.ratio * 4} fill="hsl(var(--status-online))" opacity="0.85">
                <animate attributeName="r" values={`${3 + p.ratio * 2};${6 + p.ratio * 5};${3 + p.ratio * 2}`} dur="2.4s" repeatCount="indefinite" begin={`${(p.cx % 100) / 50}s`} />
                <animate attributeName="opacity" values="0.85;0.4;0.85" dur="2.4s" repeatCount="indefinite" begin={`${(p.cx % 100) / 50}s`} />
              </circle>
              <circle cx={p.cx} cy={p.cy} r={1.8 + p.ratio * 0.8} fill="hsl(var(--status-online))" />
              <circle cx={p.cx} cy={p.cy} r={0.7} fill="hsl(var(--foreground))" />
            </g>
          ))}
        </g>

        {hovered && (
          <circle cx={hovered.x} cy={hovered.y} r={5} fill="none" stroke="hsl(var(--foreground))" strokeWidth="0.6" opacity="0.9" />
        )}
      </svg>

      {/* Tooltip */}
      {hovered && (() => {
        const entry = points.find(p => p.code === hovered.code)
        if (!entry) return null
        const name = COUNTRY_NAMES[entry.code] || entry.code
        const pct = total > 0 ? ((entry.count / total) * 100).toFixed(1) : '0'
        return (
          <div
            className="pointer-events-none absolute z-10 bg-card border border-border rounded-md px-2.5 py-1.5 shadow-lg"
            style={{
              left: `${(hovered.x / W) * 100}%`,
              top: `${(hovered.y / H) * 100}%`,
              transform: 'translate(-50%, calc(-100% - 10px))',
            }}
          >
            <div className="flex items-center gap-1.5">
              <FlagIcon country={entry.code} width={14} height={14} />
              <span className="text-[11px] font-medium text-foreground">{name}</span>
            </div>
            <div className="flex items-baseline gap-1.5 mt-0.5">
              <span className="mono text-[12px] text-foreground tabular-nums">{entry.count.toLocaleString()}</span>
              <span className="text-[10px] text-muted-foreground mono">{pct}%</span>
            </div>
          </div>
        )
      })()}

      {/* Footer */}
      <div className="absolute bottom-1 left-2 right-2 flex items-center justify-between text-[10px] text-muted-foreground/70 mono">
        <span>{points.length} {t('dashboard.countries')}</span>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-3 rounded-full bg-foreground/30" />
            <span>low</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-3 rounded-full bg-foreground/60" />
            <span>med</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-3 rounded-full bg-foreground" />
            <span>high</span>
          </div>
        </div>
      </div>
    </div>
  )
}
