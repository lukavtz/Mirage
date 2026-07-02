const messages: Record<string, Record<string, string>> = {
  en: {
    'dashboard': 'Dashboard',
    'sessions': 'Sessions',
    'build': 'Build',
    'search': 'Search',
    'settings': 'Settings',
    'login': 'Sign In',
    'logout': 'Logout',
    'loading': 'Loading...',
    'no_data': 'No data yet',
    'connected': 'Connected',
    'disconnected': 'Disconnected',
  },
  ru: {
    'dashboard': 'Дашборд',
    'sessions': 'Сессии',
    'build': 'Сборка',
    'search': 'Поиск',
    'settings': 'Настройки',
    'login': 'Вход',
    'logout': 'Выйти',
    'loading': 'Загрузка...',
    'no_data': 'Нет данных',
    'connected': 'Подключено',
    'disconnected': 'Отключено',
  },
}

type Lang = 'en' | 'ru'

const STORAGE_KEY = 'lang'

export function getLang(): Lang {
  return (localStorage.getItem(STORAGE_KEY) as Lang) ?? 'en'
}

export function setLang(lang: Lang) {
  localStorage.setItem(STORAGE_KEY, lang)
}

export function t(key: string): string {
  const lang = getLang()
  return messages[lang]?.[key] ?? messages['en']?.[key] ?? key
}
