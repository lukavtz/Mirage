const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");
const engine = @import("../syscalls/engine.zig");

const ntdll_hash = hash.encryptedHashModule("ntdll.dll");

const LdrLoadDll = *const fn (
    SearchPath: ?*const u16,
    DllCharacteristics: ?*const u32,
    DllName: *const types.UNICODE_STRING,
    BaseAddress: *types.PVOID,
) callconv(.c) types.NTSTATUS;

pub fn loadDll(comptime name: []const u8) ?types.PVOID {
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return null;
    const ldr_load_fn = export_resolve.getFunctionByHash(ntdll, hash.encryptedHashFunc("LdrLoadDll")) orelse return null;
    const ldr_load: LdrLoadDll = @ptrCast(@alignCast(ldr_load_fn));

    var buf: [512]u16 = undefined;
    @memset(&buf, 0);
    for (name, 0..) |c, i| {
        buf[i] = c;
    }
    var us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(name.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&buf)),
    };

    var base: types.PVOID = undefined;
    const status = ldr_load(null, null, &us, &base);
    return if (status >= 0) base else null;
}

pub fn getOrLoadDll(comptime name: []const u8) ?types.PVOID {
    const name_hash = hash.encryptedHashModule(name);
    if (peb_walk.getModuleByHash(name_hash)) |base| return base;
    return loadDll(name);
}
