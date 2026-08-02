import type { SVGProps } from 'react'

import { COUNTRY_COLORS } from '@/lib/countries'

interface FlagIconProps extends SVGProps<SVGSVGElement> {
  country: string
}

// Using shared COUNTRY_COLORS from lib/countries.ts

export function FlagIcon({ country, width = 20, height = 20, ...props }: FlagIconProps) {
  const bg = COUNTRY_COLORS[country] ?? '#52525B'

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 20 20"
      width={width}
      height={height}
      {...props}
    >
      <circle cx="10" cy="10" r="10" fill={bg} />
      <text
        x="10"
        y="10"
        textAnchor="middle"
        dominantBaseline="central"
        fill="white"
        fontSize="7"
        fontWeight="600"
        fontFamily="system-ui, sans-serif"
      >
        {country}
      </text>
    </svg>
  )
}
