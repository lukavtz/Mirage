import { useMemo, useState, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Skeleton } from '@/components/ui/skeleton'
import { useI18n } from '@/lib/i18n'
import { feature } from 'topojson-client'
import { geoEquirectangular, geoPath } from 'd3-geo'
import type { FeatureCollection, Geometry } from 'geojson'
import worldTopo from 'world-atlas/countries-110m.json'
import { countryName } from '@/lib/countries'

interface WorldMapProps {
  data: Array<{ country_code: string; count: number }>
  isLoading: boolean
}

interface CountryProps { name: string }

// TopoJSON countries-110m uses country NAMES in properties.name (not ISO3
// codes — the id field is a numeric M49 code, which we don't need). Map
// each name to ISO 3166-1 alpha-2 so the panel data (already in ISO2) can
// match the choropleth.
const NAME_TO_ISO2: Record<string, string> = {
  Afghanistan: 'AF', Albania: 'AL', Algeria: 'DZ', Angola: 'AO',
  Antarctica: 'AQ', Argentina: 'AR', Armenia: 'AM', Australia: 'AU',
  Austria: 'AT', Azerbaijan: 'AZ', Bahamas: 'BS', Bangladesh: 'BD',
  Belarus: 'BY', Belgium: 'BE', Belize: 'BZ', Benin: 'BJ',
  Bhutan: 'BT', Bolivia: 'BO', 'Bosnia and Herz.': 'BA', Botswana: 'BW',
  Brazil: 'BR', Brunei: 'BN', Bulgaria: 'BG', 'Burkina Faso': 'BF',
  Burundi: 'BI', Cambodia: 'KH', Cameroon: 'CM', Canada: 'CA',
  'Central African Rep.': 'CF', Chad: 'TD', Chile: 'CL', China: 'CN',
  Colombia: 'CO', Congo: 'CG', 'Costa Rica': 'CR', Croatia: 'HR',
  Cuba: 'CU', Cyprus: 'CY', Czechia: 'CZ', "Côte d'Ivoire": 'CI',
  'Dem. Rep. Congo': 'CD', Denmark: 'DK', Djibouti: 'DJ', 'Dominican Rep.': 'DO',
  Ecuador: 'EC', Egypt: 'EG', 'El Salvador': 'SV', 'Eq. Guinea': 'GQ',
  Eritrea: 'ER', Estonia: 'EE', Ethiopia: 'ET', 'Falkland Is.': 'FK',
  Fiji: 'FJ', Finland: 'FI', 'Fr. S. Antarctic Lands': 'TF', France: 'FR',
  Gabon: 'GA', Gambia: 'GM', Georgia: 'GE', Germany: 'DE',
  Ghana: 'GH', Greece: 'GR', Greenland: 'GL', Guatemala: 'GT',
  Guinea: 'GN', 'Guinea-Bissau': 'GW', Guyana: 'GY', Haiti: 'HT',
  Honduras: 'HN', Hungary: 'HU', Iceland: 'IS', India: 'IN',
  Indonesia: 'ID', Iran: 'IR', Iraq: 'IQ', Ireland: 'IE',
  Israel: 'IL', Italy: 'IT', Jamaica: 'JM', Japan: 'JP',
  Jordan: 'JO', Kazakhstan: 'KZ', Kenya: 'KE', Kosovo: 'XK',
  Kuwait: 'KW', Kyrgyzstan: 'KG', Laos: 'LA', Latvia: 'LV',
  Lebanon: 'LB', Lesotho: 'LS', Liberia: 'LR', Libya: 'LY',
  Lithuania: 'LT', Luxembourg: 'LU', Macedonia: 'MK', Madagascar: 'MG',
  Malawi: 'MW', Malaysia: 'MY', Mali: 'ML', Mauritania: 'MR',
  Mexico: 'MX', Moldova: 'MD', Mongolia: 'MN', Montenegro: 'ME',
  Morocco: 'MA', Mozambique: 'MZ', Myanmar: 'MM', 'N. Cyprus': 'CY',
  Namibia: 'NA', Nepal: 'NP', Netherlands: 'NL', 'New Caledonia': 'NC',
  'New Zealand': 'NZ', Nicaragua: 'NI', Niger: 'NE', Nigeria: 'NG',
  'North Korea': 'KP', Norway: 'NO', Oman: 'OM', Pakistan: 'PK',
  Palestine: 'PS', Panama: 'PA', 'Papua New Guinea': 'PG', Paraguay: 'PY',
  Peru: 'PE', Philippines: 'PH', Poland: 'PL', Portugal: 'PT',
  'Puerto Rico': 'PR', Qatar: 'QA', Romania: 'RO', Russia: 'RU',
  Rwanda: 'RW', 'S. Sudan': 'SS', 'Saudi Arabia': 'SA', Senegal: 'SN',
  Serbia: 'RS', 'Sierra Leone': 'SL', Slovakia: 'SK', Slovenia: 'SI',
  'Solomon Is.': 'SB', Somalia: 'SO', Somaliland: 'SO', 'South Africa': 'ZA',
  'South Korea': 'KR', Spain: 'ES', 'Sri Lanka': 'LK', Sudan: 'SD',
  Suriname: 'SR', Sweden: 'SE', Switzerland: 'CH', Syria: 'SY',
  Taiwan: 'TW', Tajikistan: 'TJ', Tanzania: 'TZ', Thailand: 'TH',
  'Timor-Leste': 'TL', Togo: 'TG', 'Trinidad and Tobago': 'TT', Tunisia: 'TN',
  Turkey: 'TR', Turkmenistan: 'TM', Uganda: 'UG', Ukraine: 'UA',
  'United Arab Emirates': 'AE', 'United Kingdom': 'GB', 'United States of America': 'US',
  Uruguay: 'UY', Uzbekistan: 'UZ', Vanuatu: 'VU', Venezuela: 'VE',
  Vietnam: 'VN', 'W. Sahara': 'EH', Yemen: 'YE', Zambia: 'ZM',
  Zimbabwe: 'ZW', eSwatini: 'SZ',
}
const W = 720
const H = 360

interface LandFeature { d: string; iso2: string; hasData: boolean; ratio: number }

export function WorldMap({ data, isLoading }: WorldMapProps) {
  const { t, lang } = useI18n()
  const navigate = useNavigate()
  const [activeCountry, setActiveCountry] = useState<string | null>(null)

  // Equirectangular projection — flat rectangle, no spherical curvature.
  // fitSize stretches the unit sphere to fill 720x360, so longitude [-180, 180]
  // spans [0, W] and latitude [-90, 90] spans [H, 0] (Y is inverted in SVG).
  const projection = useMemo(() => geoEquirectangular().fitSize([W, H], { type: 'Sphere' as never }), [])
  const path = useMemo(() => geoPath(projection), [projection])

  const { total, lands, max } = useMemo(() => {
    const m = data.reduce((acc, d) => Math.max(acc, d.count), 0) || 1
    const tot = data.reduce((s, d) => s + d.count, 0)
    const map = new Map<string, number>()
    for (const d of data) {
      map.set(d.country_code, d.count)
    }
    // Type guard for the imported world-atlas TopoJSON (untyped JSON import).
    if (!('objects' in worldTopo) || !worldTopo.objects || typeof worldTopo.objects !== 'object') {
      return { total: tot, lands: [] as LandFeature[], max: m }
    }
    const objects = worldTopo.objects as Record<string, unknown>
    if (!('countries' in objects)) {
      return { total: tot, lands: [] as LandFeature[], max: m }
    }
    const fc = feature(worldTopo as never, objects.countries as Parameters<typeof feature>[1]) as unknown as FeatureCollection<Geometry, CountryProps>
    const landFeatures: LandFeature[] = fc.features.map(f => {
      const props = f.properties
      const iso2 = props && 'name' in props && typeof props.name === 'string'
        ? (NAME_TO_ISO2[props.name] || '')
        : ''
      const count = map.get(iso2) ?? 0
      return {
        d: path(f) || '',
        iso2,
        hasData: count > 0,
        ratio: count / m,
      }
    }).filter(s => s.d)
    return { total: tot, lands: landFeatures, max: m }
  }, [data, path])

  const onCountryEnter = useCallback((iso2: string) => {
    setActiveCountry(iso2 || null)
  }, [])

  const onCountryLeave = useCallback(() => {
    setActiveCountry(null)
  }, [])

  const onCountryClick = useCallback((iso2: string) => {
    if (iso2) navigate(`/sessions?country=${iso2}`)
  }, [navigate])

  useEffect(() => { if (isLoading) setActiveCountry(null) }, [isLoading])

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
    <div className="relative w-full h-full">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-full block">
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
                  : 'var(--muted)'}
                stroke={s.hasData ? 'var(--status-online)' : 'var(--border)'}
                strokeOpacity={s.hasData ? 0.95 : 1}
                strokeWidth={isActive ? 1.4 : (s.hasData ? 0.7 : 0.5)}
                strokeLinejoin="round"
                className="cursor-pointer"
                style={{ transition: 'fill 0.2s ease, stroke-width 0.15s ease' }}
                onMouseEnter={() => onCountryEnter(s.iso2)}
                onMouseLeave={onCountryLeave}
                onClick={() => onCountryClick(s.iso2)}
              >
                <title>{s.iso2 ? countryName(s.iso2, lang) : ''}</title>
              </path>
            )
          })}
        </g>
      </svg>

      {/* Tooltip — anchored top-center of the map card, names the active country. */}
      {activeCountry && (() => {
        const entry = lands.find(s => s.iso2 === activeCountry && s.hasData)
        if (!entry) return null
        const count = Math.round(entry.ratio * max)
        const pct = total > 0 ? ((count / total) * 100).toFixed(1) : '0'
        const name = countryName(entry.iso2, lang)
        return (
          <div
            className="pointer-events-none absolute z-10 bg-popover border border-border rounded-md px-2.5 py-1.5 shadow-2xl"
            style={{ left: '50%', top: '8px', transform: 'translate(-50%, 0)' }}
          >
            <div className="flex items-baseline gap-1.5">
              <span className="text-[11px] font-medium text-popover-foreground">{name}</span>
            </div>
            <div className="flex items-baseline gap-1.5 mt-0.5">
              <span className="mono text-[12px] text-popover-foreground tabular-nums">{count.toLocaleString()}</span>
              <span className="text-[10px] text-muted-foreground mono">{pct}%</span>
            </div>
          </div>
        )
      })()}

      {/* Legend / footer */}
      <div className="absolute bottom-1 left-2 right-2 flex items-center justify-between text-[10px] text-muted-foreground/70 mono">
        <span>{lands.filter(s => s.hasData).length} {t('dashboard.countries')}</span>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-3 rounded-full" style={{ background: 'color-mix(in srgb, var(--status-online) 45%, transparent)' }} />
            <span>{t('chart.legend_low')}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-3 rounded-full" style={{ background: 'color-mix(in srgb, var(--status-online) 70%, transparent)' }} />
            <span>{t('chart.legend_medium')}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-3 rounded-full bg-status-online" />
            <span>{t('chart.legend_high')}</span>
          </div>
        </div>
      </div>
    </div>
  )
}
