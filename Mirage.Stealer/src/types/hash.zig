const std = @import("std");
const config = @import("config");

pub fn hashString(str: []const u8, iterations: usize) u32 {
    var hash: u32 = config.SEED;
    for (str) |c| {
        const lower_c = if (c >= 'A' and c <= 'Z') c + 32 else c;
        for (0..iterations) |_| {
            hash = (hash << 5) | (hash >> 27);
            hash = hash ^ lower_c;
            hash = hash *% 0x1B873593 +% 0x85EBCA6B;
        }
    }
    return hash;
}

pub fn hashStringExact(str: []const u8, iterations: usize) u32 {
    var hash: u32 = config.SEED;
    for (str) |c| {
        for (0..iterations) |_| {
            hash = (hash << 5) | (hash >> 27);
            hash = hash ^ c;
            hash = hash *% 0x1B873593 +% 0x85EBCA6B;
        }
    }
    return hash;
}

pub fn comptimeHashModule(comptime str: []const u8) u32 {
    return hashString(str, 28);
}

pub fn comptimeHashFunc(comptime str: []const u8) u32 {
    return hashStringExact(str, 27);
}

pub fn encryptedHashFunc(comptime name: []const u8) u32 {
    @setEvalBranchQuota(30000);
    var buf: [name.len]u8 = undefined;
    inline for (name, 0..) |c, i| {
        buf[i] = c ^ config.STRING_KEY_ENC[i % 16];
    }
    defer @memset(&buf, 0);
    return hashStringExact(&buf, 27);
}

pub fn encryptedHashModule(comptime name: []const u8) u32 {
    @setEvalBranchQuota(30000);
    var buf: [name.len]u8 = undefined;
    inline for (name, 0..) |c, i| {
        buf[i] = c ^ config.STRING_KEY_ENC[i % 16];
    }
    defer @memset(&buf, 0);
    return hashString(&buf, 28);
}

// Comptime XOR encrypt — returns XOR'd bytes that can be stored in the binary
// Usage: const encrypted = comptime xorEncrypt("plaintext");
pub fn xorEncrypt(comptime s: []const u8) [s.len]u8 {
    @setEvalBranchQuota(100000);
    var buf: [s.len]u8 = undefined;
    inline for (s, 0..) |c, i| {
        buf[i] = c ^ config.STRING_KEY_ENC[i % 16];
    }
    return buf;
}

// Runtime XOR decrypt — takes encrypted bytes, returns plaintext in out buffer
pub fn xorDecrypt(encrypted: []const u8, out: []u8) void {
    for (encrypted, 0..) |c, i| {
        if (i < out.len) {
            out[i] = c ^ config.STRING_KEY_ENC[i % 16];
        }
    }
}

// Convenience: allocates and returns decrypted string (caller must free)
pub fn xorDecryptAlloc(allocator: std.mem.Allocator, encrypted: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, encrypted.len);
    xorDecrypt(encrypted, out);
    return out;
}

// ── Comptime tests ──

test "hash XOR encrypt/decrypt identity" {
    const name = "NtAllocateVirtualMemory";
    const hash1 = comptimeHashFunc(name);
    const enc = encryptedHashFunc(name);
    try std.testing.expect(hash1 != enc);
    try std.testing.expect(hash1 != config.SEED);
    try std.testing.expect(enc != config.SEED);
}

test "hash deterministic" {
    const a = comptimeHashFunc("NtAllocateVirtualMemory");
    const b = comptimeHashFunc("NtAllocateVirtualMemory");
    try std.testing.expectEqual(a, b);
}

test "hash case-insensitive" {
    const a = hashString("ntdll.dll", 28);
    const b = hashString("NTDLL.DLL", 28);
    try std.testing.expectEqual(a, b);
}

test "hash function vs module differ" {
    const f = comptimeHashFunc("NtClose");
    const m = comptimeHashModule("ntdll.dll");
    try std.testing.expect(f != m);
}

test "encrypted hash vs plain hash differ" {
    const f = comptimeHashFunc("NtClose");
    const ef = encryptedHashFunc("NtClose");
    try std.testing.expect(f != ef);
}

test "encrypted hash module vs func differ" {
    const ef = encryptedHashFunc("NtClose");
    const em = encryptedHashModule("ntdll.dll");
    try std.testing.expect(ef != em);
}

test "encrypted hash non-zero" {
    const h = encryptedHashFunc("NtAllocateVirtualMemory");
    try std.testing.expect(h != 0);
}

test "all function hashes unique" {
    const names = [_][]const u8{
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        "NtFreeVirtualMemory", "NtWriteVirtualMemory",
        "NtClose", "NtOpenFile", "NtReadVirtualMemory",
        "NtCreateSection", "NtMapViewOfSection",
        "NtQueryInformationProcess", "NtCreateFile",
    };
    var hashes: [names.len]u32 = undefined;
    inline for (names, 0..) |n, i| {
        hashes[i] = comptimeHashFunc(n);
    }
    for (0..hashes.len) |i| {
        for (i + 1..hashes.len) |j| {
            try std.testing.expect(hashes[i] != hashes[j]);
        }
    }
}

test "encrypted module hash deterministic" {
    const a = encryptedHashModule("ntdll.dll");
    const b = encryptedHashModule("ntdll.dll");
    try std.testing.expectEqual(a, b);
}
