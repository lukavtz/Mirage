// Consolidated country data — single source of truth
// Used by: flag-icon.tsx, top-countries.tsx, world-map.tsx, Sessions.tsx, PublicStatsPage.tsx

export const COUNTRY_NAMES: Record<string, string> = {
  US: 'United States', RU: 'Russian Federation', IN: 'India', BR: 'Brazil',
  DE: 'Germany', GB: 'United Kingdom', FR: 'France', CN: 'China',
  JP: 'Japan', KR: 'South Korea', CA: 'Canada', AU: 'Australia',
  IT: 'Italy', ES: 'Spain', NL: 'Netherlands', PL: 'Poland',
  UA: 'Ukraine', TR: 'Turkey', SA: 'Saudi Arabia', AE: 'UAE',
  ID: 'Indonesia', MX: 'Mexico', AR: 'Argentina', CO: 'Colombia',
  VN: 'Vietnam', TH: 'Thailand', MY: 'Malaysia', PH: 'Philippines',
  SG: 'Singapore', HK: 'Hong Kong', TW: 'Taiwan', NZ: 'New Zealand',
  ZA: 'South Africa', EG: 'Egypt', NG: 'Nigeria', PT: 'Portugal',
  BE: 'Belgium', CH: 'Switzerland', AT: 'Austria', CZ: 'Czech Republic',
  RO: 'Romania', BG: 'Bulgaria', GR: 'Greece', IE: 'Ireland',
  SE: 'Sweden', NO: 'Norway', FI: 'Finland', DK: 'Denmark',
  KZ: 'Kazakhstan', BY: 'Belarus', UZ: 'Uzbekistan',
}

// Predefined filter options for session search
export const COUNTRY_FILTER_OPTIONS = [
  { value: '', labelKey: 'sessions.all_countries' },
  { value: 'RU', labelKey: '' },
  { value: 'US', labelKey: '' },
  { value: 'BR', labelKey: '' },
  { value: 'IN', labelKey: '' },
  { value: 'DE', labelKey: '' },
  { value: 'GB', labelKey: '' },
  { value: 'FR', labelKey: '' },
  { value: 'CN', labelKey: '' },
]
