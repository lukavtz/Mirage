import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'

interface GeoBarProps {
  data: Array<{ country: string; count: number }>
  isLoading: boolean
}

const COUNTRY_FLAGS: Record<string, string> = {
  US: '\u{1F1FA}\u{1F1F8}', GB: '\u{1F1EC}\u{1F1E7}', DE: '\u{1F1E9}\u{1F1EA}', FR: '\u{1F1EB}\u{1F1F7}',
  RU: '\u{1F1F7}\u{1F1FA}', CN: '\u{1F1E8}\u{1F1F3}', IN: '\u{1F1EE}\u{1F1F3}', BR: '\u{1F1E7}\u{1F1F7}',
  JP: '\u{1F1EF}\u{1F1F5}', KR: '\u{1F1F0}\u{1F1F7}', CA: '\u{1F1E8}\u{1F1E6}', AU: '\u{1F1E6}\u{1F1FA}',
  IT: '\u{1F1EE}\u{1F1F9}', ES: '\u{1F1EA}\u{1F1F8}', NL: '\u{1F1F3}\u{1F1F1}', SE: '\u{1F1F8}\u{1F1EA}',
  NO: '\u{1F1F3}\u{1F1F4}', FI: '\u{1F1EB}\u{1F1EE}', DK: '\u{1F1E9}\u{1F1F0}', PL: '\u{1F1F5}\u{1F1F1}',
  UA: '\u{1F1FA}\u{1F1E6}', TR: '\u{1F1F9}\u{1F1F7}', SA: '\u{1F1F8}\u{1F1E6}', AE: '\u{1F1E6}\u{1F1EA}',
  IL: '\u{1F1EE}\u{1F1F1}', SG: '\u{1F1F8}\u{1F1EC}', HK: '\u{1F1ED}\u{1F1F0}', TW: '\u{1F1F9}\u{1F1FC}',
  TH: '\u{1F1F9}\u{1F1ED}', VN: '\u{1F1FB}\u{1F1F3}', ID: '\u{1F1EE}\u{1F1E9}', MY: '\u{1F1F2}\u{1F1FE}',
  PH: '\u{1F1F5}\u{1F1ED}', NZ: '\u{1F1F3}\u{1F1FF}', ZA: '\u{1F1FF}\u{1F1E6}', MX: '\u{1F1F2}\u{1F1FD}',
  AR: '\u{1F1E6}\u{1F1F7}', CO: '\u{1F1E8}\u{1F1F4}', CL: '\u{1F1E8}\u{1F1F1}', PT: '\u{1F1F5}\u{1F1F9}',
  BE: '\u{1F1E7}\u{1F1EA}', CH: '\u{1F1E8}\u{1F1ED}', AT: '\u{1F1E6}\u{1F1F9}', CZ: '\u{1F1E8}\u{1F1FF}',
  SK: '\u{1F1F8}\u{1F1F0}', HU: '\u{1F1ED}\u{1F1FA}', RO: '\u{1F1F7}\u{1F1F4}', BG: '\u{1F1E7}\u{1F1EC}',
  GR: '\u{1F1EC}\u{1F1F7}', IE: '\u{1F1EE}\u{1F1EA}',
}

export function GeoBar({ data, isLoading }: GeoBarProps) {
  if (isLoading) {
    return <Skeleton className="h-[300px] w-full" />
  }

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-[300px] text-muted-foreground text-sm">
        No geo data yet
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data} layout="vertical" margin={{ top: 5, right: 40, left: 0, bottom: 0 }}>
        <XAxis type="number" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} stroke="hsl(var(--muted-foreground))" />
        <YAxis
          type="category"
          dataKey="country"
          tick={{ fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          stroke="hsl(var(--muted-foreground))"
          tickFormatter={(code) => `${COUNTRY_FLAGS[code] ?? ''} ${code}`}
          width={60}
        />
        <Tooltip
          contentStyle={{
            background: 'hsl(var(--popover))',
            border: '1px solid hsl(var(--border))',
            borderRadius: 'var(--radius)',
            fontSize: 13,
          }}
          formatter={(value) => Number(value ?? 0).toLocaleString()}
        />
        <Bar dataKey="count" name="Sessions" fill="hsl(var(--primary))" radius={[0, 4, 4, 0]} barSize={20} label={{ position: 'right', fontSize: 11, fill: 'hsl(var(--muted-foreground))' }} />
      </BarChart>
    </ResponsiveContainer>
  )
}
