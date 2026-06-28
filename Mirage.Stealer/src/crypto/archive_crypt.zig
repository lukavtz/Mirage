const std = @import("std");
const crypto = std.crypto;
const config = @import("config");
const hash = @import("../types/hash.zig");
const chacha_poly = @import("chacha_poly.zig");

pub const ArchiveKey = [chacha_poly.key_length]u8;
pub const ArchiveNonce = [chacha_poly.nonce_length]u8;

pub fn deriveKey(nonce: *const ArchiveNonce) ![chacha_poly.key_length]u8 {
    var key: ArchiveKey = undefined;
    var seed_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &seed_bytes, config.SEED, .little);
    try crypto.pwhash.pbkdf2(&key, &seed_bytes, nonce, 1000, crypto.auth.hmac.HmacSha1);
    return key;
}

pub fn encryptArchive(input: []const u8, out: []u8) ?[]u8 {
    var nonce: ArchiveNonce = undefined;
    for (&nonce, 0..) |*b, i| {
        const t = config.SEED +% @as(u32, @intCast(i));
        b.* = @as(u8, @truncate((t ^ (t >> 8) ^ (t >> 16) ^ (t >> 24))));
    }
    const key = deriveKey(&nonce) catch return null;
    const tag_offset = chacha_poly.nonce_length;
    if (out.len < tag_offset + input.len + chacha_poly.tag_length) return null;
    @memcpy(out[0..tag_offset], &nonce);
    const ct = chacha_poly.encrypt(input, key, nonce, "", out[tag_offset..]) orelse return null;
    return out[0 .. tag_offset + ct.len];
}

pub fn decryptArchive(input: []const u8, out: []u8) ?[]u8 {
    if (input.len < chacha_poly.nonce_length + chacha_poly.tag_length) return null;
    var nonce: ArchiveNonce = undefined;
    @memcpy(&nonce, input[0..chacha_poly.nonce_length]);
    const key = deriveKey(&nonce) catch return null;
    const ct = input[chacha_poly.nonce_length..];
    return chacha_poly.decrypt(ct, key, nonce, "", out);
}

test "deriveKey deterministic" {
    var nonce: ArchiveNonce = undefined;
    @memset(&nonce, 0x42);
    const a = try deriveKey(&nonce);
    const b = try deriveKey(&nonce);
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "deriveKey different nonce -> different key" {
    var nonce_a: ArchiveNonce = undefined;
    var nonce_b: ArchiveNonce = undefined;
    @memset(&nonce_a, 0x00);
    @memset(&nonce_b, 0xFF);
    const ka = try deriveKey(&nonce_a);
    const kb = try deriveKey(&nonce_b);
    try std.testing.expect(!std.mem.eql(u8, &ka, &kb));
}

test "encryptArchive decryptArchive roundtrip" {
    var buf: [512]u8 = undefined;
    var dec: [512]u8 = undefined;
    const input = "Hello, Archive Encryption!";

    const ct = encryptArchive(input, &buf) orelse return error.EncodeFailed;
    try std.testing.expect(ct.len > input.len);

    const pt = decryptArchive(ct, &dec) orelse return error.DecodeFailed;
    try std.testing.expectEqualSlices(u8, input, pt);
}

test "encryptArchive empty input" {
    var buf: [64]u8 = undefined;
    var dec: [64]u8 = undefined;
    const ct = encryptArchive("", &buf) orelse return error.EncodeFailed;
    try std.testing.expect(ct.len > 0);
    const pt = decryptArchive(ct, &dec) orelse return error.DecodeFailed;
    try std.testing.expectEqualSlices(u8, "", pt);
}

test "decryptArchive tampered ciphertext" {
    var buf: [512]u8 = undefined;
    var dec: [512]u8 = undefined;
    const ct = (encryptArchive("test data", &buf) orelse return error.EncodeFailed);
    if (ct.len > chacha_poly.nonce_length + chacha_poly.tag_length) {
        ct[ct.len - 1] ^= 1;
        try std.testing.expect(decryptArchive(ct, &dec) == null);
    }
}

test "encryptArchive output too small" {
    var tiny: [4]u8 = undefined;
    try std.testing.expect(encryptArchive("hello", &tiny) == null);
}
