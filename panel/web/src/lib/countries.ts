// Consolidated country data — single source of truth
// Used by: flag-icon.tsx, top-countries.tsx, world-map.tsx, Sessions.tsx, PublicStatsPage.tsx

const EN_NAMES: Record<string, string> = {
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

const RU_NAMES: Record<string, string> = {
  US: 'США', RU: 'Россия', IN: 'Индия', BR: 'Бразилия',
  DE: 'Германия', GB: 'Великобритания', FR: 'Франция', CN: 'Китай',
  JP: 'Япония', KR: 'Южная Корея', CA: 'Канада', AU: 'Австралия',
  IT: 'Италия', ES: 'Испания', NL: 'Нидерланды', PL: 'Польша',
  UA: 'Украина', TR: 'Турция', SA: 'Саудовская Аравия', AE: 'ОАЭ',
  ID: 'Индонезия', MX: 'Мексика', AR: 'Аргентина', CO: 'Колумбия',
  VN: 'Вьетнам', TH: 'Таиланд', MY: 'Малайзия', PH: 'Филиппины',
  SG: 'Сингапур', HK: 'Гонконг', TW: 'Тайвань', NZ: 'Новая Зеландия',
  ZA: 'Южная Африка', EG: 'Египет', NG: 'Нигерия', PT: 'Португалия',
  BE: 'Бельгия', CH: 'Швейцария', AT: 'Австрия', CZ: 'Чехия',
  RO: 'Румыния', BG: 'Болгария', GR: 'Греция', IE: 'Ирландия',
  SE: 'Швеция', NO: 'Норвегия', FI: 'Финляндия', DK: 'Дания',
  KZ: 'Казахстан', BY: 'Беларусь', UZ: 'Узбекистан',
}

// English map is exported for back-compat with any direct consumer; the
// three dashboard/chart consumers now use `countryName(code, lang)` below.
export const COUNTRY_NAMES = EN_NAMES

// Resolves a country code to a localized display name. Falls back to the
// English map, then to the code itself if unknown.
export function countryName(code: string, lang: 'en' | 'ru' = 'en'): string {
  if (lang === 'ru') return RU_NAMES[code] || EN_NAMES[code] || code
  return EN_NAMES[code] || code
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
