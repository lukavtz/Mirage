import type { SVGProps } from 'react'
import { hasFlag } from 'country-flag-icons'
import * as Flags from 'country-flag-icons/react/3x2'
import { cn } from '@/lib/utils'

interface FlagIconProps extends Omit<SVGProps<SVGSVGElement>, 'children'> {
  country: string
  width?: number | string
  height?: number | string
  className?: string
}

// Named exports from country-flag-icons/react/3x2: US, DE, RU, …, uppercase only.
// hasFlag() is case-insensitive; we normalize to uppercase before lookup.
const FlagMap = Flags as unknown as Record<string, (props: { className?: string; title?: string; width?: number | string; height?: number | string }) => React.JSX.Element>

export function FlagIcon({ country, width = 20, height = 15, className }: FlagIconProps) {
  const code = (country || '').toUpperCase()
  if (!code || !hasFlag(code)) return null
  const Flag = FlagMap[code]
  if (!Flag) return null
  return (
    <Flag
      className={cn('shrink-0 rounded-[2px]', className)}
      width={width}
      height={height}
      title={code}
    />
  )
}
