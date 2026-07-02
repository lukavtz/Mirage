import type { SVGProps } from 'react'

interface FlagIconProps extends SVGProps<SVGSVGElement> {
  country: string
}

const PALETTE: Record<string, string> = {
  RU: '#D52B1E', US: '#3B3B98', GB: '#1E3A5F', DE: '#DD4814',
  FR: '#002654', CN: '#DE2910', IN: '#FF9933', BR: '#009739',
  JP: '#BC002D', KR: '#003478', CA: '#D80621', AU: '#00008B',
  IT: '#009246', ES: '#C60B1E', NL: '#FF6600', SE: '#005B99',
  NO: '#BA0C2E', FI: '#003580', DK: '#C8102E', PL: '#DC143C',
  UA: '#005BBB', TR: '#E30A17', SA: '#006C35', AE: '#FF0000',
  IL: '#0038B8', SG: '#ED2939', HK: '#EE1C25', TW: '#FE0000',
  TH: '#F4A900', VN: '#DA251D', ID: '#CE1126', MY: '#CC0000',
  PH: '#0038A8', NZ: '#00247D', ZA: '#DE3831', MX: '#006341',
  AR: '#74ACDF', CO: '#003893', CL: '#0039A6', PT: '#006600',
  BE: '#000000', CH: '#FF0000', AT: '#ED2939', CZ: '#11457E',
  SK: '#0B4EA2', HU: '#CE2939', RO: '#003399', BG: '#00966E',
  GR: '#0D5EAF', IE: '#169B62', KZ: '#00AFCA', BY: '#C4302B',
  UZ: '#1EB53A', KG: '#E80000', TJ: '#CC0000', TM: '#00A651',
  GE: '#FF0000', AZ: '#00B5E2', AM: '#D90012', LT: '#FDB913',
  LV: '#9E3039', EE: '#0072CE',
}

export function FlagIcon({ country, width = 20, height = 20, ...props }: FlagIconProps) {
  const bg = PALETTE[country] ?? '#52525B'

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
