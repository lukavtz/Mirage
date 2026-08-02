# Mirage v3 — Competitive Analysis & Gap Report

> Based on: raw/ reference repos (Sentinel, Phemedrone, LummaC2, RedLine, Ferrox, Antarctida), docs/concurents.md (TheVoid, Remus, Volta), and Mirage source code.

---

## Binary Size Comparison

| Stealer | Language | Weight | Notes |
|---------|----------|--------|-------|
| **VoltaStealer** | C/ASM | **215-230 KB** | Morphed, no CRT, raw syscalls |
| **TheVoid** | C/C++ | **<600 KB** | Clean build |
| **Remus** | C++ | ~400 KB | No CRT, syscalls |
| **Mirage (ours)** | C11/ASM | **333 KB** | Stripped, no CRT, polymorphic |
| LummaC2 | C# | ~800 KB | .NET runtime dependency |
| Sentinel | C# | ~1.2 MB | .NET, no anti-analysis |
| Phemedrone | C# | ~1.5 MB | .NET, dnlib obfuscation |
| RedLine | C# | ~1.5 MB | .NET |

**Verdict:** Mirage is competitive on size — smaller than all C# projects, close to Remus/Volta range. The c11-nocrt merge was the right move.

---

## Feature Matrix

| Feature | Mirage | Volta | TheVoid | Remus | Sentinel | Phemedrone | Ferrox |
|---------|--------|-------|---------|-------|----------|------------|--------|
| **Language** | C11+ASM | C+ASM | C/C++ | C++ | C# | C# | Rust |
| **No CRT** | ✅ | ✅ | ❌ | ✅ | N/A | N/A | N/A |
| **Polymorphic build** | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ (IL) | ✅ |
| **Direct syscalls** | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| **PEB-walk API** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **AMSI bypass** | ✅ HW BP | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **ETW bypass** | ✅ HW BP | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **String encryption** | ✅ XOR | ✅ | ✅ | ✅ | ❌ | ✅ IL | ✅ |
| **Anti-VM** | ✅ 15 checks | ✅ | ✅ | ✅ | ❌ | ✅ basic | ✅ 8+ |
| **CIS geoblock** | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Browsers** | 58+dynamic | 100+ | ~20 | 21 | ~20 | ~20 | ~20 |
| **Dynamic discovery** | ✅ registry+FS | ❌ | ❌ | ❌ | ❌ | ✅ FS | ❌ |
| **App-Bound COM** | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| **Elevator impersonation** | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **CDP cookie grab** | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ |
| **Locked SQLite bypass** | ✅ section-map | ✅ | ❌ | ✅ RestartMgr | ✅ RestartMgr | ✅ RestartMgr | ❌ |
| **Raw DB export** | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **Server-side decrypt** | ✅ Go panel | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Telegram tdata** | ✅ 12 forks | ✅ | ❌ | ✅ | ✅ Web | ❌ | ❌ |
| **Telegram Web session** | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Gecko browsers** | 10+dynamic | 30+ | ❌ | Firefox | Firefox | Firefox | Firefox |
| **Crypto extensions** | 96 | 60+ | ~70 | 181 | ~100 | ~100 | 18+ |
| **Desktop wallets** | 38 | 60+ | ~9 | 16 | ~30 | ~20 | 10+ |
| **Clipboard monitor** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Clipper** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Keylogger** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Screenshot** | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **File grabber** | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ |
| **Seed phrase scan** | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **WiFi passwords** | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ |
| **SOCKS5/TOR proxy** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Panel** | Go+React | Rust+React | Rust+React | Rust+React | C# | C# console | Telegram |
| **Config from panel** | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| **WebSocket realtime** | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **Rate limiter** | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **JWT auth** | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **TOTP 2FA** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

---

## Gap Analysis — What Top Projects Have That Mirage Lacks

### Critical (should implement)

| Gap | Source | Priority | Effort |
|-----|--------|----------|--------|
| **Telegram Web session extraction** | Sentinel | High | Medium — regex for dc1-5_auth_key in LevelDB, build import JSON |
| **Restart Manager API for locked files** | Sentinel, Phemedrone | High | Low — RmStartSession/RmRegisterResources/RmGetList, add as tier 1 |
| **SeBackupPrivilege for file reads** | Sentinel | High | Low — AdjustTokenPrivileges + FILE_FLAG_BACKUP_SEMANTICS |
| **CIS geoblock** | Volta, Phemedrone | High | Low — IP geolocation + keyboard layout + system language check |
| **Yandex custom crypto** | Sentinel | Medium | Medium — Ya Passman Data magic 0x20120108, custom decrypt |
| **Google OAuth token extraction** | Sentinel | Medium | Low — Web Data/token_service table, extract refresh_token |
| **Credit card CVC cross-ref** | Sentinel | Medium | Low — local_stored_cvc table in Web Data |

### Nice-to-have

| Gap | Source | Priority | Effort |
|-----|--------|----------|--------|
| **Reflective DLL injection** | Ferrox, Sentinel | Medium | High — inject ChromiumDecryptor.dll into browser process |
| **Hell's Gate syscall** | Ferrox | Low | Medium — resolve SSN from ntdll at runtime |
| **DGA fallback C2** | LummaC2 | Low | Medium — domain generation algorithm for C2 resilience |
| **Chunked exfil with resume** | Volta | Medium | Low — already have chunked.c, add resume logic |
| **Metamask auto-bruteforce** | Remus, Volta | Low | High — brute force wallet passwords |
| **Dedicated server detection** | Volta, Remus | Low | Medium — distinguish VPS from desktop |

---

## Mirage Advantages Over ALL Competitors

| Advantage | Details |
|-----------|---------|
| **AMSI bypass via HW breakpoint** | No .text patching — hardware debug registers + VEH. Unique among all analyzed projects. |
| **ETW bypass via HW breakpoint** | Same technique. All competitors either skip ETW or use detectable RET-patch. |
| **PEB-walk for ALL API resolution** | No IAT imports at all. Most competitors use GetProcAddress or have visible imports. |
| **Polymorphic per-build** | Seed + XOR key regenerated per build, all hashes change. Volta has morpher, Mirage has it built-in. |
| **Dynamic browser discovery** | Registry + filesystem scan finds ANY Chromium/Gecko browser, not just hardcoded list. |
| **No-CRT runtime** | Custom rt layer — no msvcrt.dll dependency. Reduces binary size and detection surface. |
| **Go+React panel** | Modern stack with WebSocket realtime, TOTP 2FA, filter presets. Most competitors use C#/PHP. |
| **SOCKS5/TOR for C2** | All C2 traffic routes through proxy. Most competitors use direct HTTP. |
| **Server-side decryption** | Panel decrypts v10/v11 on server. Client sends raw files + master key. |

---

## Action Items (Priority Order)

1. **Add Restart Manager locked-file bypass** (tier 1 in read_file_via_section) — 30 lines, high impact
2. **Add SeBackupPrivilege** — 15 lines, enables direct backup-semantics reads
3. **Add Telegram Web session extraction** — ~200 lines, unique collection target
4. **Add CIS geoblock** — 20 lines, market requirement for CIS-focused operations
5. **Add Google OAuth token extraction** — 50 lines, high-value credential
6. **Add Yandex custom crypto** — 100 lines, market-specific browser
7. **Add credit card CVC cross-ref** — 20 lines, completes payment card collection
