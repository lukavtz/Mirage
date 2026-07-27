# zialfi — План завершения

## Текущий статус

| Параметр | Значение |
|----------|----------|
| Бинарник | ✅ mirage.exe (383 KB) |
| C файлов | 27 |
| LOC | ~7365 |
| TODO | 0 |
| Coverage | ~40% от Mirage |

## Что нужно доделать (приоритеты)

### P0 — Критичные модули (без них не работает)

| # | Модуль | Файлов | Описание |
|---|--------|--------|----------|
| 1 | **keylogger** | 1 | WH_KEYBOARD_LL hook, запись нажатий |
| 2 | **hosts_poison** | 1 | Блокировка AV доменов через hosts файл |
| 3 | **http.c** | 1 | Полноценный HTTP клиент |
| 4 | **tls.c** | 1 | TLS через SChannel |
| 5 | **zip.c** | 1 | Создание ZIP архивов |
| 6 | **clipboard.c** | 1 | Сбор буфера обмена |
| 7 | **screenshot.c** | 1 | Скриншоты через GDI |

### P1 — Расширение покрытия

| # | Модуль | Файлов | Описание |
|---|--------|--------|----------|
| 8 | **amsi_bypass** | 1 | Патч AMSI |
| 9 | **etw_bypass** | 1 | Патч ETW |
| 10 | **uac_bypass** | 1 | UAC обход |
| 11 | **peb_hide** | 1 | Скрытие из PEB |
| 12 | **defender_disable** | 1 | Отключение Defender |
| 13 | **mutex** | 1 | Single-instance mutex |
| 14 | **chrome_key** | 1 | Парсинг Local State JSON |
| 15 | **socks5.c** | 1 | SOCKS5 прокси |
| 16 | **telegram.c** | 1 | Telegram backup |

### P2 — Расширение данных

| # | Модуль | Файлов | Описание |
|---|--------|--------|----------|
| 17 | **google_tokens** | 1 | Google OAuth токены |
| 18 | **outlook_tokens** | 1 | Outlook токены |
| 19 | **yandex_passman** | 1 | Яндекс менеджер паролей |
| 20 | **appbound** | 2 | Chrome App-Bound decryption |
| 21 | **webcam** | 1 | Захват веб-камеры |
| 22 | **screenshot** | 1 | Скриншоты |
| 23 | **processes** | 1 | Список процессов |
| 24 | **grabber** | 1 | Файловый граббер |
| 25 | **regex_grabber** | 1 | Regex поиск файлов |
| 26 | **seed_grabber** | 1 | Поиск seed фраз |

### P3 — Сеть и инфраструктура

| # | Модуль | Файлов | Описание |
|---|--------|--------|----------|
| 27 | **ws2.c** | 1 | WinSock wrapper |
| 28 | **proxy.c** | 1 | HTTP прокси |
| 29 | **chunked.c** | 1 | Чанковая отправка |
| 30 | **schannel.c** | 1 | SChannel TLS |

### P4 — Тесты

| # | Тест | Описание |
|---|------|----------|
| 31 | **test_peb.c** | PEB walk |
| 32 | **test_hash.c** | Hash computation |
| 33 | **test_sqlite.c** | SQLite парсер |
| 34 | **test_chromium.c** | Browser extraction |
| 35 | **test_firefox.c** | Firefox extraction |
| 36 | **test_wallets.c** | Wallet collection |
| 37 | **test_messengers.c** | Messenger collection |
| 38 | **test_network.c** | HTTP upload |
| 39 | **test_crypto.c** | ChaCha20, DPAPI |
| 40 | **test_evasion.c** | Anti-analysis |
| 41 | **e2e_test.c** | Полный pipeline |

## Оценка времени

| Приоритет | Модулей | Дней |
|-----------|---------|------|
| P0 (критичные) | 7 | 2 |
| P1 (расширение) | 9 | 3 |
| P2 (данные) | 10 | 3 |
| P3 (сеть) | 4 | 2 |
| P4 (тесты) | 11 | 3 |
| **Итого** | **41** | **~13 дней** |

## Порядок выполнения

```
День 1-2:  P0 (keylogger, geoblock, http, tls, zip, clipboard, screenshot)
День 3-5:  P1 (evasion: amsi/etw/uac/peb/defender/mutex, crypto)
День 6-8:  P2 (google/outlook tokens, yandex, appbound, webcam, grabber)
День 9-10: P3 (ws2, proxy, chunked, schannel)
День 11-13: P4 (все unit tests + e2e)
```

## Методологии

- **TDD**: Каждый модуль → сначала тест, потом реализация
- **ADD**: Clean Architecture, модули независимы
- **E2E**: Финальный тест stealer → panel
- **Code Audit**: c-review после каждого P-уровня
