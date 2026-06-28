# Mirage Stealer — References & Code Sources

## Source Code Provenance

### Legend
```
[PORT]  = Translation from C/C++/C# to Zig
[REUSE] = Used as-is (or adapted minimally)
[REF]   = Reference only, not directly copied
[OWN]   = Written from scratch for Mirage
```

---

## 1. `raw/DumpBrowserSecrets` (Maldev-Academy)

| File/Technique | Usage in Mirage | Method | Lines |
|---------------|-----------------|--------|-------|
| `Common/SQLoot/SQLoot.c` | Custom SQLite binary parser → `src/parsers/` | **[PORT]** C → Zig | ~1600 → ~500 |
| `DumpBrowserSecrets/ExtractChromiumData.cpp` | AES-GCM/DPAPI browser decryption → `src/crypto/` | **[PORT]** C++ algorithms → Zig | ~800 |
| `DumpBrowserSecrets/ChromiumProcCreation.cpp` | Chrome process spawn for App-Bound → `src/browsers/` | **[REF]** Logic reference | ~200 |
| `DllExtractChromiumSecrets/DllMain.cpp` | COM IElevator App-Bound key extraction → `MirageDecryptor/` | **[REUSE]** Almost as-is in C++ DLL | ~150 |
| `Common/Obfuscate.hpp` | Comptime XOR obfuscation concept → `src/config/` | **[REF]** Same idea, Zig comptime | — |
| `Common/ApiHashing.cpp` | FNV1a API hashing concept → `src/types/` | **[REF]** Same idea, CRC32 in Zig | — |

**Total borrowed:** ~1000 lines ported + ~150 lines reused

---

## 2. `EidosLoader` (own project)

| File/Technique | Usage in Mirage | Method | Lines |
|---------------|-----------------|--------|-------|
| `src/syscalls/engine.zig` | Halo's Gate syscall resolution | **[PORT]** Simplified version (22 vs 50 syscalls) | ~800 → ~450 |
| `src/core/hash.zig` | CRC32 comptime hashing | **[REUSE]** Same algo, adapted | ~80 |
| `src/core/types.zig` | NT PE/PEB structure defs | **[REUSE]** Same structs | ~200 |
| `src/core/peb.zig` | PEB walk + module lookup | **[REUSE]** Simplified | ~100 |
| `src/evasion/peb_hide.zig` | PEB LDR unlinking | **[REUSE]** Simplified | ~60 |
| `src/evasion/anti_analysis.zig` | Weighted scoring gate | **[REF]** Simplified (no mouse/cpu counters) | ~150 |
| `src/config.zig` | Comptime config pattern | **[REUSE]** Same architecture | ~50 |
| `src/crypto/crypto.zig` | ChaCha20-Poly1305 pattern | **[REF]** AES-GCM instead for Mirage | ~100 |

**Total borrowed:** ~500 lines reused + ~300 lines reference

---

## 3. `raw/zcircuit` (Hiroki6)

| File/Technique | Usage in Mirage | Method |
|---------------|-----------------|--------|
| `src/root.zig` — Hell's Gate SSN extraction | Reference for syscall stub parsing | **[REF]** Validation of own impl |
| `src/asm/hells_gate.s` — ASM stubs | Inline `asm volatile` in Zig | **[REF]** Same logic, inline not MASM |
| `src/utils.zig` — CRC32 | Same algorithm, already in EidosLoader | **[REF]** |

---

## 4. `raw/ZigStrike` (0xsp-SRD)

| File/Technique | Usage in Mirage | Method |
|---------------|-----------------|--------|
| `src/core.zig` — Anti-sandbox TPM/Domain | Conceptual reference | **[REF]** |
| Python web builder | Conceptual reference for `Mirage.Builder` | **[REF]** Mirage uses C# not Python |

---

## 5. `raw/PhemedroneStealerSources/` (downloaded separately)

| File/Technique | Usage in Mirage | Method |
|---------------|-----------------|--------|
| `Tools/Builder.sln` — C# dnlib builder | Reference for `Mirage.Builder` PE-patching | **[REF]** Mirage patches .rdata, not IL |
| `Stealer/Config.cs` — XOR config pattern | Same XOR config embedding concept | **[REF]** |

---

## 6. `raw/melt-stealer` (Vorolski)

| Module | Usage in Mirage | Method |
|--------|-----------------|--------|
| `Stealer.Chromium.Recovery` — 35 browser paths | **[PORT]** Browser path list → Zig | ~150 lines |
| `Stealer.Wallets.GetWallets` — 15 wallet paths | **[PORT]** Wallet path list → Zig | ~100 lines |
| `Stealer.Steam.GetSteamSession` — Steam logic | **[REF]** Same approach | ~50 lines |
| `Stealer.Telegram.GetTelegramSessions` — Telegram tdata | **[REF]** Same approach | ~30 lines |
| `StormKitty.Implant.AntiAnalysis` — 6 anti-analysis checks | **[REF]** Same checks, Zig impl | ~100 lines reference |
| `StormKitty.Telegram.Report` — Telegram multipart | **[REF]** Same protocol | ~80 lines reference |

**Total borrowed from melt-stealer:** ~250 lines of data (paths, checks)

---

## 7. `SentinelStealerSource/` (own)

### Phase 4.2 — Browser Decryption

| Component | Usage in Mirage | Method |
|-----------|-----------------|--------|
| `Recovery\Browsers\Chromium.cs` — DPAPI/AES decryption | **[REF]** Algorithm reference | — |
| `ChromiumDecryptor.dll` — App-Bound via IElevator | **[REUSE]** Concept for `MirageDecryptor.dll` | ~150 lines |

### Phase 4.4 — System Information

| Component | Usage in Mirage | Method |
|-----------|-----------------|--------|
| `Recovery\System\ClientInformation.cs` — OS, hardware, network collection | **[REF]** System info data model | ~200 lines |

### Phase 4.5 — Messenger Theft

| Component | Usage in Mirage | Method |
|-----------|-----------------|--------|
| `Recovery\Messengers\Discord.cs` — Discord token scanning + validation | **[REF]** LevelDB token regex + API validation | ~150 lines |
| `Recovery\Messengers\TelegramClient.cs` — Telegram tdata extraction | **[REF]** Same tdata directory copy strategy | ~80 lines |
| `Recovery\Messengers\Pidgin.cs` — Pidgin accounts.xml parsing | **[REF]** XML account extraction | ~60 lines |

### Phase 4.6 — Gaming Theft

| Component | Usage in Mirage | Method |
|-----------|-----------------|--------|
| `Recovery\Games\Steam.cs` — Steam ssfn + config.vdf collection | **[REF]** Same file enumeration | ~80 lines |
| `Recovery\Games\Roblox.cs` — Roblox cookie DPAPI decryption | **[REF]** Cookie extraction via DPAPI | ~100 lines |

### Phase 4.7 — System Utilities

| Component | Usage in Mirage | Method |
|-----------|-----------------|--------|
| `Recovery\System\Screenshot.cs` — Desktop screenshot via GDI | **[REF]** BitBlt capture approach | ~50 lines |
| `Recovery\System\Wifi.cs` — Saved WiFi profile enumeration | **[REF]** WlanAPI interface pattern | ~80 lines |
| `Recovery\System\ProductKey.cs` — Windows product key retrieval | **[REF]** Registry query approach | ~40 lines |

**Total borrowed from SentinelStealer:** ~500 lines reference (~200 browser + ~300 messengers/gaming/system)

---

## 8. `raw/TheBear/` (Phase 4.4 — Wallet Extension IDs)

| File | Usage in Mirage | Method |
|------|-----------------|--------|
| `Modules/ExtensionsGrabber.c` — 42 wallet extension IDs | **[PORT]** Extension ID mapping → `src/wallets/wallet_extensions.zig` | ~200 lines → ~100 lines |

TheBear provided the initial 42-wallet ID set, which was then expanded to 62 IDs by merging with Skuld's wallet list.

---

## 9. `raw/Skuld/` (Phase 4.4 — Wallet Paths)

| File | Usage in Mirage | Method |
|------|-----------------|--------|
| `stealer/wallets.go` — 52 extension + 10 desktop wallet paths | **[REF]** Cross-referenced wallet lists from TheBear | ~150 lines reference |

Skuld's Go wallet module confirmed the 10 desktop wallet paths and contributed additional extension IDs beyond TheBear's 42, bringing the total to 62 extensions + 10 desktop.

---

## 10. `raw/PhantomStealer/` (Phase 4.7 — System Modules)

| File | Usage in Mirage | Method |
|------|-----------------|--------|
| `Phantom/SystemInfo.cs` — OS + hardware reporting | **[REF]** System info format and field selection | ~100 lines |
| `Phantom/Screenshot.cs` — Desktop screenshot capture | **[REF]** GDI BitBlt capture pattern | ~50 lines |
| `Phantom/WifiGrabber.cs` — Saved WiFi profile extraction | **[REF]** WlanAPI approach to profile enumeration | ~60 lines |
| `Phantom/ProductKey.cs` — Windows product key | **[REF]** Registry query for digital product ID | ~30 lines |

---

## 11. `raw/ferrox/` (Phase 4.6 — Gaming Modules)

| File | Usage in Mirage | Method |
|------|-----------------|--------|
| `src/gsteam.rs` — Steam session file enumeration | **[PORT]** Rust → Zig steam module | ~80 lines |
| `src/gminecraft.rs` — Minecraft launcher detection | **[PORT]** Rust → Zig minecraft module | ~70 lines |
| `src/gbattlenet.rs` — Battle.net config + DB collection | **[PORT]** Rust → Zig battlenet module | ~60 lines |

---

## 12. External Libraries (Phase 5 — Exfiltration)

### Phase 5.1 — TLS Transport

| Source | Usage in Mirage | Method |
|--------|-----------------|--------|
| `raw/PhantomLoader/schannel.cpp` — SChannel TLS handshake | **[PORT]** C++ → Zig `src/network/schannel.zig` | ~250 lines |
| `raw/melt-stealer/StormKitty/Telegram/Report.cs` — Telegram multipart | **[REF]** Same protocol | ~80 lines |

### Phase 5.2 — Archive Format

| Source | Usage in Mirage | Method |
|--------|-----------------|--------|
| `raw/PhemedroneStealerSources/Stealer/ZipStorage.cs` — Custom ZIP without compression | **[REF]** PKZIP Store method concept → `src/network/zip.zig` | ~200 lines |

### Phase 5.3 — Telegram Bot API

| Source | Usage in Mirage | Method |
|--------|-----------------|--------|
| `raw/ferrox/src/telegram.rs` — Telegram Bot API sendDocument | **[REF]** Multipart upload pattern | ~50 lines |
| `raw/SentinelStealer/Telegram.cs` — HTTP multipart formatting | **[REF]** Same boundary format | ~60 lines |

---

## Summary: Code Origin in Mirage Stealer

| Origin | Percentage | Lines (est.) |
|--------|-----------|-------------|
| Written from scratch for Mirage | 40% | ~2400 |
| Ported from DumpBrowserSecrets (SQLoot + AES-GCM) | 15% | ~900 |
| Reused/adapted from EidosLoader | 10% | ~600 |
| SentinelStealer (browsers + messengers + gaming + system) | 8% | ~500 |
| TheBear wallet extension IDs | 5% | ~300 |
| Skuld wallet paths (extensions + desktop) | 4% | ~250 |
| Phantom Stealer (system/screenshot/wifi/productkey) | 4% | ~240 |
| melt-stealer (paths, Telegram, anti-analysis) | 3% | ~180 |
| ferrox gaming (Steam, Minecraft, Battle.net) | 2% | ~120 |
| PhantomLoader (SChannel TLS) | 1% | ~80 |
| Phemedrone (custom ZIP concept) | 1% | ~60 |
| Sentinel Decryptor DLL (COM IElevator) | 2% | ~120 |
| zcircuit + ZigStrike (validation/reference) | 1% | ~60 |
| ferrox telegram (Telegram Bot API) | 1% | ~50 |
| **Total** | **~97%** | **~5860** |
