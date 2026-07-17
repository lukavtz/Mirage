const std = @import("std");
const crypto = std.crypto;
const config = @import("config");
const hash = @import("../types/hash.zig");
const chacha_poly = @import("chacha_poly.zig");

pub const ArchiveKey = [chacha_poly.key_length]u8;
pub const ArchiveNonce = [chacha_poly.nonce_length]u8;
pub const ArchiveSalt = [16]u8;

fn fillRandom(buf: []u8) void {
    var rng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.posix.getrandom(@as([*]u8, @ptrCast(&seed))[0..@sizeOf(u64)]) catch {
            seed = @bitCast(@as(i64, @truncate(std.time.nanoTimestamp())));
        };
        break :blk seed;
    });
    rng.fill(buf);
}

pub fn deriveKey(password: []const u8, salt: *const ArchiveSalt) ![chacha_poly.key_length]u8 {
    var key: ArchiveKey = undefined;
    try crypto.pwhash.pbkdf2(&key, password, salt, 210_000, crypto.auth.hmac.HmacSha256);
    return key;
}

pub fn encryptArchive(input: []const u8, out: []u8) ?[]u8 {
    var nonce: ArchiveNonce = undefined;
    fillRandom(&nonce);

    var salt: ArchiveSalt = undefined;
    fillRandom(&salt);

    var seed_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &seed_buf, config.SEED, .little);
    const key = deriveKey(&seed_buf, &salt) catch return null;

    const header_len = chacha_poly.nonce_length + salt.len;
    if (out.len < header_len + input.len + chacha_poly.tag_length) return null;
    @memcpy(out[0..chacha_poly.nonce_length], &nonce);
    @memcpy(out[chacha_poly.nonce_length..header_len], &salt);
    const ct = chacha_poly.encrypt(input, key, nonce, "", out[header_len..]) orelse return null;
    return out[0 .. header_len + ct.len];
}

pub fn decryptArchive(input: []const u8, out: []u8) ?[]u8 {
    const header_len = chacha_poly.nonce_length + ArchiveSalt.len;
    if (input.len < header_len + chacha_poly.tag_length) return null;
    var nonce: ArchiveNonce = undefined;
    @memcpy(&nonce, input[0..chacha_poly.nonce_length]);
    var salt: ArchiveSalt = undefined;
    @memcpy(&salt, input[chacha_poly.nonce_length..header_len]);

    var seed_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &seed_buf, config.SEED, .little);
    const key = deriveKey(&seed_buf, &salt) catch return null;

    const ct = input[header_len..];
    return chacha_poly.decrypt(ct, key, nonce, "", out);
}

test "deriveKey deterministic" {
    var salt: ArchiveSalt = .{0x42} ** ArchiveSalt.len;
    var seed: [8]u8 = .{0xDE, 0xAD, 0xBE, 0xEF} ** 2;
    const a = try deriveKey(&seed, &salt);
    const b = try deriveKey(&seed, &salt);
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "deriveKey different salt -> different key" {
    var seed: [8]u8 = .{0xCA, 0xFE} ** 4;
    var salt_a: ArchiveSalt = .{0x00} ** ArchiveSalt.len;
    var salt_b: ArchiveSalt = .{0xFF} ** ArchiveSalt.len;
    const ka = try deriveKey(&seed, &salt_a);
    const kb = try deriveKey(&seed, &salt_b);
    try std.testing.expect(!std.mem.eql(u8, &ka, &kb));
}

test "encryptArchive decryptArchive roundtrip" {
    var buf: [4096]u8 = undefined;
    var dec: [4096]u8 = undefined;
    const input = "Hello, Archive Encryption!";

    const ct = encryptArchive(input, &buf) orelse return error.EncodeFailed;
    try std.testing.expect(ct.len > input.len);

    const pt = decryptArchive(ct, &dec) orelse return error.DecodeFailed;
    try std.testing.expectEqualSlices(u8, input, pt);
}

test "encryptArchive empty input" {
    var buf: [4096]u8 = undefined;
    var dec: [4096]u8 = undefined;
    const ct = encryptArchive("", &buf) orelse return error.EncodeFailed;
    try std.testing.expect(ct.len > 0);
    const pt = decryptArchive(ct, &dec) orelse return error.DecodeFailed;
    try std.testing.expectEqualSlices(u8, "", pt);
}

test "decryptArchive tampered ciphertext" {
    var buf: [4096]u8 = undefined;
    var dec: [4096]u8 = undefined;
    const ct = (encryptArchive("test data", &buf) orelse return error.EncodeFailed);
    if (ct.len > chacha_poly.nonce_length + ArchiveSalt.len + chacha_poly.tag_length) {
        ct[ct.len - 1] ^= 1;
        try std.testing.expect(decryptArchive(ct, &dec) == null);
    }
}

test "encryptArchive output too small" {
    var tiny: [4]u8 = undefined;
    try std.testing.expect(encryptArchive("hello", &tiny) == null);
}

test "encryptArchive produces different ciphertexts" {
    var buf1: [4096]u8 = undefined;
    var buf2: [4096]u8 = undefined;
    const input = "same plaintext";
    const ct1 = encryptArchive(input, &buf1) orelse return error.EncodeFailed;
    const ct2 = encryptArchive(input, &buf2) orelse return error.EncodeFailed;
    try std.testing.expect(!std.mem.eql(u8, ct1, ct2));
}
