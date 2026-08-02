import { useMemo, useState, useRef, useCallback, useEffect } from 'react'
import { Skeleton } from '@/components/ui/skeleton'
import { FlagIcon } from '@/components/charts/flag-icon'
import { COUNTRY_NAMES } from '@/lib/countries'
import { useI18n } from '@/lib/i18n'
import { feature } from 'topojson-client'
import { geoNaturalEarth1, geoPath, geoGraticule10 } from 'd3-geo'
import type { FeatureCollection, Geometry } from 'geojson'
import worldTopo from 'world-atlas/countries-110m.json'

interface WorldMapProps {
  data: Array<{ country_code: string; count: number }>
  isLoading: boolean
}

interface CountryProps { name: string }

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

interface Marker { code: string; count: number; cx: number; cy: number; ratio: number }
interface LandFeature { d: string; iso2: string; hasData: boolean; ratio: number; centroid: [number, number] }

export function WorldMap({ data, isLoading }: WorldMapProps) {
  const { t } = useI18n()
  const [hovered, setHovered] = useState<{ code: string; x: number; y: number; d: number } | null>(null)
  const [activeCountry, setActiveCountry] = useState<string | null>(null)
  const containerRef = useRef<HTMLDivElement | null>(null)

  const projection = useMemo(() => geoNaturalEarth1().fitSize([W, H], { type: 'Sphere' as never }), [])
  const path = useMemo(() => geoPath(projection), [projection])

  const { total, markers, lands, spherePath, graticulePath } = useMemo(() => {
    const m = data.reduce((acc, d) => Math.max(acc, d.count), 0) || 1
    const tot = data.reduce((s, d) => s + d.count, 0)
    const mkrs: Marker[] = []
    const map = new Map<string, number>()
    for (const d of data) {
      map.set(d.country_code, d.count)
    }
    if (!('objects' in worldTopo) || !worldTopo.objects || typeof worldTopo.objects !== 'object') {
      return { total: tot, markers: mkrs, lands: [] as LandFeature[], spherePath: '', graticulePath: '' }
    }
    const objects = worldTopo.objects as Record<string, unknown>
    if (!('countries' in objects)) {
      return { total: tot, markers: mkrs, lands: [] as LandFeature[], spherePath: '', graticulePath: '' }
    }
    const fc = feature(worldTopo as never, objects.countries as Parameters<typeof feature>[1]) as unknown as FeatureCollection<Geometry, CountryProps>
    const landFeatures: LandFeature[] = fc.features.map(f => {
      const props = f.properties
      const iso2 = props && 'name' in props && typeof props.name === 'string'
        ? (ISO3_TO_ISO2[props.name] || '')
        : ''
      const count = map.get(iso2) ?? 0
      const c = path.centroid(f as never)
      const cPair: [number, number] | null = c && Number.isFinite(c[0]) && Number.isFinite(c[1])
        ? [c[0], c[1]]
        : null
      if (cPair && count > 0) {
        mkrs.push({ code: iso2, count, cx: cPair[0], cy: cPair[1], ratio: count / m })
      }
      return {
        d: path(f) || '',
        iso2,
        hasData: count > 0,
        ratio: count / m,
        centroid: cPair ?? [NaN, NaN],
      }
    }).filter(s => s.d)
    const sphere = path({ type: 'Sphere' } as never) || ''
    const grat = path(geoGraticule10()) || ''
    return { total: tot, markers: mkrs, lands: landFeatures, spherePath: sphere, graticulePath: grat }
  }, [data, path])

  // Sort markers by count desc and take the top 3 for the "pulse" animation layer
  const topThree = useMemo(() => new Set(markers.slice().sort((a, b) => b.count - a.count).slice(0, 3).map(m => m.code)), [markers])

  const onMove = useCallback((e: React.MouseEvent) => {
    if (!containerRef.current) return
    const rect = containerRef.current.getBoundingClientRect()
    const x = ((e.clientX - rect.left) / rect.width) * W
    const y = ((e.clientY - rect.top) / rect.height) * H
    let best: { code: string; x: number; y: number; d: number } | null = null
    for (const p of markers) {
      const dx = p.cx - x
      const dy = p.cy - y
      const d2 = dx * dx + dy * dy
      if (!best || d2 < best.d) best = { code: p.code, x: p.cx, y: p.cy, d: d2 }
    }
    if (best && best.d < 144) setHovered(best)
    else setHovered(null)
  }, [markers])

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
          {/* Ocean radial gradient — center brighter, edge darker */}
          <radialGradient id="ocean-grad" cx="50%" cy="50%" r="65%">
            <stop offset="0%"   stopColor="var(--background)" stopOpacity="0" />
            <stop offset="100%" stopColor="var(--background)" stopOpacity="0.9" />
          </radialGradient>
          {/* Marker core glow */}
          <radialGradient id="marker-core" cx="50%" cy="50%" r="50%">
            <stop offset="0%"   stopColor="var(--status-online)" stopOpacity="0.6" />
            <stop offset="100%" stopColor="var(--status-online)" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* 1) Ocean (sphere) — silhouettes the map */}
        <path
          d={spherePath}
          fill="url(#ocean-grad)"
          stroke="rgba(255, 255, 255, 0.06)"
          strokeWidth={0.6}
        />

        {/* 2) Real graticule via d3-geo */}
        {graticulePath && (
          <path
            d={graticulePath}
            fill="none"
            stroke="rgba(255, 255, 255, 0.05)"
            strokeWidth={0.35}
          />
        )}

        {/* 3) Land glow halos (behind countries) — give "watermark" of data presence */}
        <g opacity="0.55">
          {lands.filter(s => s.hasData && Number.isFinite(s.centroid[0])).map((s, i) => (
            <circle
              key={`halo-${i}`}
              cx={s.centroid[0]}
              cy={s.centroid[1]}
              r={4 + s.ratio * 8}
              fill="url(#marker-core)"
            />
          ))}
        </g>

        {/* 4) Country paths — choropleth with WCAG-verified contrast */}
        <g>
          {lands.map((s, i) => {
            const intensity = s.hasData ? Math.min(1, 0.45 + s.ratio * 0.5) : 0
            const isActive = s.iso2 === activeCountry
            return (
              <path
                key={i}
                d={s.d}
                fill={s.hasData
                  ? `color-mix(in srgb, var(--status-online) ${Math.round(intensity * 100)}%, transparent)`
                  : 'transparent'}
                stroke={s.hasData ? 'var(--status-online)' : 'rgba(255, 255, 255, 0.10)'}
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

        {/* 5) Infection markers — 3 layers, pulse only on top-3 */}
        <g>
          {markers.map(p => {
            const isTop = topThree.has(p.code)
            return (
              <g key={p.code}>
                {/* static halo */}
                <circle cx={p.cx} cy={p.cy} r={5 + p.ratio * 10} fill="var(--status-online)" opacity="0.18" />
                {/* pulse ring — only top 3, uses CSS so prefers-reduced-motion rules */}
                {isTop && (
                  <circle
                    cx={p.cx}
                    cy={p.cy}
                    r={3 + p.ratio * 4}
                    className="anim-signal-pulse"
                    style={{ transformOrigin: `${p.cx}px ${p.cy}px`, transformBox: 'fill-box' }}
                    fill="var(--status-online)"
                    opacity="0.85"
                  />
                )}
                {/* core */}
                <circle cx={p.cx} cy={p.cy} r={1.8 + p.ratio * 0.8} fill="var(--status-online)" />
                {/* specular highlight */}
                <circle cx={p.cx} cy={p.cy} r={0.7} fill="var(--foreground)" />
              </g>
            )
          })}
        </g>

        {/* 6) Hover indicator (centroid of active country) */}
        {hovered && (
          <circle
            cx={hovered.x}
            cy={hovered.y}
            r={6}
            fill="none"
            stroke="var(--foreground)"
            strokeWidth="0.8"
            opacity="0.9"
          />
        )}
      </svg>

      {/* Tooltip — clamped to viewport */}
      {hovered && (() => {
        const entry = markers.find(p => p.code === hovered.code)
        if (!entry) return null
        const name = COUNTRY_NAMES[entry.code] || entry.code
        const pct = total > 0 ? ((entry.count / total) * 100).toFixed(1) : '0'
        const containerRect = containerRef.current?.getBoundingClientRect()
        const viewW = window.innerWidth
        const ttWidth = 200
        // Position at top of container in viewBox-relative units
        let leftPct = (hovered.x / W) * 100
        if (containerRect) {
          // If tooltip would overflow right edge, flip
          const ttCenterPx = containerRect.left + (leftPct / 100) * containerRect.width
          if (ttCenterPx + ttWidth / 2 > viewW - 8) leftPct = Math.max(0, leftPct - 12)
        }
        return (
          <div
            className="pointer-events-none absolute z-10 bg-popover border border-border rounded-md px-2.5 py-1.5 shadow-2xl"
            style={{
              left: `${leftPct}%`,
              top: `${(hovered.y / H) * 100}%`,
              transform: 'translate(-50%, calc(-100% - 12px))',
            }}
          >
            <div className="flex items-center gap-1.5">
              <FlagIcon country={entry.code} width={14} height={14} />
              <span className="text-[11px] font-medium text-popover-foreground">{name}</span>
            </div>
            <div className="flex items-baseline gap-1.5 mt-0.5">
              <span className="mono text-[12px] text-popover-foreground tabular-nums">{entry.count.toLocaleString()}</span>
              <span className="text-[10px] text-muted-foreground mono">{pct}%</span>
            </div>
          </div>
        )
      })()}

      {/* Legend / footer */}
      <div className="absolute bottom-1 left-2 right-2 flex items-center justify-between text-[10px] text-muted-foreground/70 mono">
        <span>{markers.length} {t('dashboard.countries')}</span>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-3 rounded-full" style={{ background: 'color-mix(in srgb, var(--status-online) 45%, transparent)' }} />
            <span>low</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-3 rounded-full" style={{ background: 'color-mix(in srgb, var(--status-online) 70%, transparent)' }} />
            <span>med</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-3 rounded-full bg-status-online" />
            <span>high</span>
          </div>
        </div>
      </div>
    </div>
  )
}
