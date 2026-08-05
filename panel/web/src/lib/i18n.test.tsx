import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { I18nProvider, useI18n, t, getLang, setLang, messages } from './i18n'

function Probe() {
  const { lang, setLang, t } = useI18n()
  return (
    <div>
      <span data-testid="lang">{lang}</span>
      <span data-testid="translated">{t('nav.build')}</span>
      <button onClick={() => setLang('ru')}>to-ru</button>
    </div>
  )
}

const renderProbe = () => render(
  <I18nProvider><Probe /></I18nProvider>,
)

describe('I18nProvider', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.lang = ''
  })

  it('defaults to English', () => {
    renderProbe()
    expect(screen.getByTestId('lang')).toHaveTextContent('en')
    expect(screen.getByTestId('translated')).toHaveTextContent('Build')
    expect(document.documentElement.lang).toBe('en')
  })

  it('reads a saved language from localStorage', () => {
    localStorage.setItem('lang', 'ru')
    renderProbe()
    expect(screen.getByTestId('lang')).toHaveTextContent('ru')
    expect(screen.getByTestId('translated')).toHaveTextContent(messages.ru['nav.build'])
  })

  it('setLang switches language and updates localStorage', () => {
    renderProbe()
    fireEvent.click(screen.getByText('to-ru'))
    expect(screen.getByTestId('lang')).toHaveTextContent('ru')
    expect(screen.getByTestId('translated')).toHaveTextContent(messages.ru['nav.build'])
    expect(localStorage.getItem('lang')).toBe('ru')
    expect(document.documentElement.lang).toBe('ru')
  })
})

describe('useI18n', () => {
  it('throws when used outside I18nProvider', () => {
    expect(() => render(<Probe />)).toThrow('useI18n must be used within I18nProvider')
  })
})

describe('standalone t()', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('returns the English translation for a known key', () => {
    expect(t('nav.build')).toBe('Build')
  })

  it('returns the Russian translation when lang is ru', () => {
    localStorage.setItem('lang', 'ru')
    expect(t('nav.build')).toBe(messages.ru['nav.build'])
  })

  it('interpolates params', () => {
    expect(t('common.total', { n: 5 })).toBe('5 total')
  })

  it('returns the key itself as a fallback for unknown keys', () => {
    expect(t('nope' as any)).toBe('nope')
  })
})

describe('getLang / setLang', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('getLang returns en by default', () => {
    expect(getLang()).toBe('en')
  })

  it('setLang updates localStorage', () => {
    setLang('ru')
    expect(localStorage.getItem('lang')).toBe('ru')
    expect(getLang()).toBe('ru')
  })
})

describe('i18n message dictionary', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('every key resolves in both languages', () => {
    const enKeys = Object.keys(messages.en) as (keyof typeof messages.en)[]
    expect(enKeys.length).toBeGreaterThan(50)

    for (const key of enKeys) {
      const enVal = t(key) // lang is en
      expect(enVal).toBe(messages.en[key])
    }

    setLang('ru')
    for (const key of enKeys) {
      const ruVal = t(key)
      expect(ruVal).toBe(messages.ru[key])
    }
  })
})