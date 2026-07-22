import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { LOCALE_STORAGE_KEY, TRANSLATIONS, type Locale } from './translations'

const HTML_LANG: Record<Locale, string> = { zh: 'zh-CN', en: 'en' }

interface I18nState {
  locale: Locale
  setLocale: (locale: Locale) => void
  t: (key: string, params?: Record<string, string | number>) => string
}

const I18nCtx = createContext<I18nState | null>(null)

function readInitialLocale(): Locale {
  const stored = localStorage.getItem(LOCALE_STORAGE_KEY)
  return stored === 'en' ? 'en' : 'zh' // SECURITY-irrelevant UX default: Chinese
}

function interpolate(template: string, params?: Record<string, string | number>): string {
  if (!params) return template
  return template.replace(/\{(\w+)\}/g, (match, key: string) =>
    key in params ? String(params[key]) : match,
  )
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(readInitialLocale)

  useEffect(() => {
    document.documentElement.lang = HTML_LANG[locale]
  }, [locale])

  const setLocale = (next: Locale) => {
    setLocaleState(next)
    localStorage.setItem(LOCALE_STORAGE_KEY, next)
  }

  const t = useMemo(() => {
    const dict = TRANSLATIONS[locale]
    return (key: string, params?: Record<string, string | number>) =>
      interpolate(dict[key] ?? key, params)
  }, [locale])

  return <I18nCtx.Provider value={{ locale, setLocale, t }}>{children}</I18nCtx.Provider>
}

export function useI18n(): I18nState {
  const ctx = useContext(I18nCtx)
  if (!ctx) throw new Error('useI18n must be used within I18nProvider')
  return ctx
}
