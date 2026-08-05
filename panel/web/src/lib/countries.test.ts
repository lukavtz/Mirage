import { describe, it, expect } from 'vitest'
import { countryName, COUNTRY_NAMES, COUNTRY_FILTER_OPTIONS } from './countries'

describe('countryName', () => {
  it('returns the English name by default', () => {
    expect(countryName('US')).toBe('United States')
    expect(countryName('DE')).toBe('Germany')
  })

  it('returns the Russian name when lang is ru', () => {
    expect(countryName('US', 'ru')).toBe('США')
    expect(countryName('DE', 'ru')).toBe('Германия')
  })

  it('falls back to the code itself for unknown codes', () => {
    expect(countryName('ZZ')).toBe('ZZ')
    expect(countryName('ZZ', 'ru')).toBe('ZZ')
  })
})

describe('COUNTRY_NAMES back-compat map', () => {
  it('contains English names', () => {
    expect(COUNTRY_NAMES.US).toBe('United States')
    expect(COUNTRY_NAMES.RU).toBe('Russian Federation')
  })
})

describe('COUNTRY_FILTER_OPTIONS', () => {
  it('starts with an all-countries option and lists known codes', () => {
    expect(COUNTRY_FILTER_OPTIONS[0]).toEqual({ value: '', labelKey: 'sessions.all_countries' })
    const codes = COUNTRY_FILTER_OPTIONS.map(o => o.value).filter(Boolean)
    for (const code of codes) {
      expect(countryName(code)).not.toBe(code)
    }
  })
})
