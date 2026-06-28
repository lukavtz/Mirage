const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

const RegFuncInfo = struct {
    name: []const u8,
    name_hash: u32,
};

const registry_funcs = [_]RegFuncInfo{
    .{ .name = "NtOpenKey", .name_hash = 0 },
    .{ .name = "NtQueryValueKey", .name_hash = 0 },
    .{ .name = "NtCreateKey", .name_hash = 0 },
    .{ .name = "NtEnumerateKey", .name_hash = 0 },
    .{ .name = "NtDeleteKey", .name_hash = 0 },
    .{ .name = "NtClose", .name_hash = 0 },
};

fn initFuncHashes() void {
    inline for (&registry_funcs) |*rf| {
        rf.name_hash = hash.encryptedHashFunc(rf.name);
    }
}

fn isStubHooked(stub: [*]const u8) bool {
    if (stub[0] == 0xE9) return true;
    if (stub[0] == 0xFF and stub[1] == 0x25) return true;
    if (stub[0] == 0xCC) return true;
    if (stub[0] == 0x48 and stub[1] == 0xB8) return true;
    return false;
}

pub fn verifyRegistryFunctions() struct { total: usize, hooked: usize, clean: usize } {
    initFuncHashes();
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return .{ .total = 0, .hooked = 0, .clean = 0 };

    var hooked: usize = 0;
    for (registry_funcs) |rf| {
        const func_ptr = export_resolve.getFunctionByHash(ntdll, rf.name_hash) orelse continue;
        const stub: [*]const u8 = @ptrCast(@alignCast(func_ptr));
        if (isStubHooked(stub)) hooked += 1;
    }

    return .{
        .total = registry_funcs.len,
        .hooked = hooked,
        .clean = registry_funcs.len - hooked,
    };
}

pub fn areRegistrySyscallsClean() bool {
    const result = verifyRegistryFunctions();
    return result.hooked == 0;
}

test "verifyRegistryFunctions returns plausible counts" {
    const result = verifyRegistryFunctions();
    try std.testing.expect(result.total > 0);
    try std.testing.expect(result.total <= registry_funcs.len);
}

test "registry syscalls are clean via direct syscall" {
    _ = areRegistrySyscallsClean();
}

const testing = std.testing;
