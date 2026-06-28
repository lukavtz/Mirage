const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

pub const key_length = 32;
pub const nonce_length = 12;
pub const tag_length = 16;

const CC = crypto.stream.chacha.ChaCha20IETF;

pub fn encrypt(
    plaintext: []const u8,
    key: [key_length]u8,
    nonce: [nonce_length]u8,
    ad: []const u8,
    out: []u8,
) ?[]u8 {
    const ct_len = plaintext.len + tag_length;
    if (out.len < ct_len) return null;

    var poly_key: [32]u8 = undefined;
    var zeros: [64]u8 = undefined;
    @memset(&zeros, 0);
    CC.xor(&poly_key, zeros[0..key_length], 0, key, nonce);

    CC.xor(out[0..plaintext.len], plaintext, 1, key, nonce);

    var mac = crypto.onetimeauth.Poly1305.init(&poly_key);
    var block: [16]u8 = undefined;

    var offset: usize = 0;
    while (offset < ad.len) {
        const chunk = @min(ad.len - offset, 16);
        @memset(&block, 0);
        @memcpy(block[0..chunk], ad[offset..][0..chunk]);
        mac.update(&block);
        offset += chunk;
    }

    offset = 0;
    while (offset < plaintext.len) {
        const chunk = @min(plaintext.len - offset, 16);
        @memset(&block, 0);
        @memcpy(block[0..chunk], out[offset..][0..chunk]);
        mac.update(&block);
        offset += chunk;
    }

    var len_block: [16]u8 = undefined;
    std.mem.writeInt(u64, len_block[0..8], ad.len, .little);
    std.mem.writeInt(u64, len_block[8..16], plaintext.len, .little);
    mac.update(&len_block);

    var tag: [tag_length]u8 = undefined;
    mac.final(&tag);
    @memcpy(out[plaintext.len..][0..tag_length], &tag);
    return out[0..ct_len];
}

pub fn decrypt(
    ciphertext: []const u8,
    key: [key_length]u8,
    nonce: [nonce_length]u8,
    ad: []const u8,
    out: []u8,
) ?[]u8 {
    if (ciphertext.len < tag_length) return null;
    const ct_len = ciphertext.len - tag_length;
    if (out.len < ct_len) return null;

    var poly_key: [32]u8 = undefined;
    var zeros: [64]u8 = undefined;
    @memset(&zeros, 0);
    CC.xor(&poly_key, zeros[0..key_length], 0, key, nonce);

    var mac = crypto.onetimeauth.Poly1305.init(&poly_key);
    var block: [16]u8 = undefined;

    var offset: usize = 0;
    while (offset < ad.len) {
        const chunk = @min(ad.len - offset, 16);
        @memset(&block, 0);
        @memcpy(block[0..chunk], ad[offset..][0..chunk]);
        mac.update(&block);
        offset += chunk;
    }

    offset = 0;
    while (offset < ct_len) {
        const chunk = @min(ct_len - offset, 16);
        @memset(&block, 0);
        @memcpy(block[0..chunk], ciphertext[offset..][0..chunk]);
        mac.update(&block);
        offset += chunk;
    }

    var len_block: [16]u8 = undefined;
    std.mem.writeInt(u64, len_block[0..8], ad.len, .little);
    std.mem.writeInt(u64, len_block[8..16], ct_len, .little);
    mac.update(&len_block);

    var expected_tag: [tag_length]u8 = undefined;
    mac.final(&expected_tag);
    const tag = ciphertext[ct_len..][0..tag_length];

    var valid: u8 = 0;
    for (&expected_tag, tag) |*et, t| {
        valid |= et.* ^ t;
    }
    if (valid != 0) return null;

    CC.xor(out[0..ct_len], ciphertext[0..ct_len], 1, key, nonce);

    return out[0..ct_len];
}

// ── Test helpers ──

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    comptime {
        var result: [hex.len / 2]u8 = undefined;
        for (&result, 0..) |*b, i| {
            const hi = std.fmt.charToDigit(hex[i * 2], 16) catch @compileError("bad hex");
            const lo = std.fmt.charToDigit(hex[i * 2 + 1], 16) catch @compileError("bad hex");
            b.* = @as(u8, hi << 4) | lo;
        }
        return result;
    }
}

// ── Tests ──

test "key_length constant" {
    try testing.expect(key_length == 32);
}

test "nonce_length constant" {
    try testing.expect(nonce_length == 12);
}

test "tag_length constant" {
    try testing.expect(tag_length == 16);
}

test "roundtrip small" {
    var out: [128]u8 = undefined;
    var dec: [128]u8 = undefined;
    var key: [key_length]u8 = undefined;
    var nonce: [nonce_length]u8 = undefined;
    @memset(&key, 0x42);
    @memset(&nonce, 0x13);
    const pt = "Hello, ChaCha20-Poly1305!";

    const ct = encrypt(pt, key, nonce, "", &out) orelse return error.EncryptFailed;
    try testing.expect(ct.len == pt.len + tag_length);

    const pt2 = decrypt(ct, key, nonce, "", &dec) orelse return error.DecryptFailed;
    try testing.expectEqualSlices(u8, pt, pt2);
}

test "roundtrip empty plaintext" {
    var out: [64]u8 = undefined;
    var dec: [64]u8 = undefined;
    var key: [key_length]u8 = undefined;
    var nonce: [nonce_length]u8 = undefined;
    @memset(&key, 0x42);
    @memset(&nonce, 0x13);

    const ct = encrypt("", key, nonce, "", &out) orelse return error.EncryptFailed;
    try testing.expect(ct.len == tag_length);

    const pt = decrypt(ct, key, nonce, "", &dec) orelse return error.DecryptFailed;
    try testing.expectEqualSlices(u8, "", pt);
}

test "roundtrip with AAD" {
    var out: [256]u8 = undefined;
    var dec: [256]u8 = undefined;
    var key: [key_length]u8 = undefined;
    var nonce: [nonce_length]u8 = undefined;
    @memset(&key, 0xAB);
    @memset(&nonce, 0xCD);
    const pt = "authenticated plaintext";
    const ad = "additional data";

    const ct = encrypt(pt, key, nonce, ad, &out) orelse return error.EncryptFailed;
    const pt2 = decrypt(ct, key, nonce, ad, &dec) orelse return error.DecryptFailed;
    try testing.expectEqualSlices(u8, pt, pt2);
}

test "wrong AAD -> decrypt fails" {
    var out: [256]u8 = undefined;
    var dec: [256]u8 = undefined;
    var key: [key_length]u8 = undefined;
    var nonce: [nonce_length]u8 = undefined;
    @memset(&key, 0xAB);
    @memset(&nonce, 0xCD);

    const ct = encrypt("secret", key, nonce, "correct_ad", &out) orelse return error.EncryptFailed;
    try testing.expect(decrypt(ct, key, nonce, "wrong_ad", &dec) == null);
}

test "wrong key -> decrypt fails" {
    var out: [256]u8 = undefined;
    var dec: [256]u8 = undefined;
    var key_a: [key_length]u8 = undefined;
    var key_b: [key_length]u8 = undefined;
    var nonce: [nonce_length]u8 = undefined;
    @memset(&key_a, 0xAA);
    @memset(&key_b, 0xBB);
    @memset(&nonce, 0x13);

    const ct = encrypt("secret", key_a, nonce, "", &out) orelse return error.EncryptFailed;
    try testing.expect(decrypt(ct, key_b, nonce, "", &dec) == null);
}

test "tampered ciphertext -> decrypt fails" {
    var out: [256]u8 = undefined;
    var dec: [256]u8 = undefined;
    var key: [key_length]u8 = undefined;
    var nonce: [nonce_length]u8 = undefined;
    @memset(&key, 0x42);
    @memset(&nonce, 0x13);

    const ct_raw = encrypt("tamper test", key, nonce, "", &out) orelse return error.EncryptFailed;
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..ct_raw.len], ct_raw);
    tampered[5] ^= 0xFF;
    try testing.expect(decrypt(tampered[0..ct_raw.len], key, nonce, "", &dec) == null);
}

test "tampered tag -> decrypt fails" {
    var out: [256]u8 = undefined;
    var dec: [256]u8 = undefined;
    var key: [key_length]u8 = undefined;
    var nonce: [nonce_length]u8 = undefined;
    @memset(&key, 0x42);
    @memset(&nonce, 0x13);

    const ct_raw = encrypt("tag test", key, nonce, "", &out) orelse return error.EncryptFailed;
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..ct_raw.len], ct_raw);
    tampered[ct_raw.len - 1] ^= 0x01;
    try testing.expect(decrypt(tampered[0..ct_raw.len], key, nonce, "", &dec) == null);
}

test "output too small for encrypt" {
    var tiny: [4]u8 = undefined;
    var key: [key_length]u8 = undefined;
    var nonce: [nonce_length]u8 = undefined;
    @memset(&key, 0);
    @memset(&nonce, 0);
    try testing.expect(encrypt("hello", key, nonce, "", &tiny) == null);
}

test "ciphertext too small for decrypt" {
    var dec: [64]u8 = undefined;
    const key: [key_length]u8 = undefined;
    const nonce: [nonce_length]u8 = undefined;
    try testing.expect(decrypt("", key, nonce, "", &dec) == null);
    try testing.expect(decrypt("t" ** 15, key, nonce, "", &dec) == null);
}

test "large plaintext (multi-block)" {
    var key: [key_length]u8 = undefined;
    var nonce: [nonce_length]u8 = undefined;
    @memset(&key, 0x99);
    @memset(&nonce, 0x11);

    var pt: [2048]u8 = undefined;
    for (&pt, 0..) |*b, i| b.* = @as(u8, @truncate(i & 0xFF));

    var out: [2048 + tag_length]u8 = undefined;
    var dec: [2048]u8 = undefined;

    const ct = encrypt(&pt, key, nonce, "", &out) orelse return error.EncryptFailed;
    try testing.expect(ct.len == pt.len + tag_length);

    const pt2 = decrypt(ct, key, nonce, "", &dec) orelse return error.DecryptFailed;
    try testing.expectEqualSlices(u8, &pt, pt2);
}

test "RFC 8439 AEAD test vector" {
    const rfc_key = hexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const rfc_nonce = hexToBytes("070000004041424344454647");
    const rfc_pt = hexToBytes(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a" ++
        "204966204920636f756c64206f6666657220796f75206f6e6c79206f6e65207072696e6369706c6520" ++
        "666f7220746865206675747572652c2073696c69636f6e20776f756c642062652069742e",
    );
    const rfc_aad = hexToBytes("50515253c0c1c2c3c4c5c6c7");
    const rfc_ct = hexToBytes(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282" ++
        "fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab3" ++
        "24e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
    );
    const rfc_tag = hexToBytes("1ae10b594f09e26a7e902ecbd0600691");

    var out: [rfc_pt.len + tag_length]u8 = undefined;
    const result = encrypt(&rfc_pt, rfc_key, rfc_nonce, &rfc_aad, &out) orelse return error.EncryptFailed;

    try testing.expectEqualSlices(u8, &rfc_ct, result[0..rfc_ct.len]);
    try testing.expectEqualSlices(u8, &rfc_tag, result[rfc_ct.len..]);

    var dec: [rfc_pt.len]u8 = undefined;
    const pt2 = decrypt(result, rfc_key, rfc_nonce, &rfc_aad, &dec) orelse return error.DecryptFailed;
    try testing.expectEqualSlices(u8, &rfc_pt, pt2);
}
