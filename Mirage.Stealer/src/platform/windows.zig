const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .windows) @compileError("windows.zig is Windows-only");
}

pub const types = @import("../types/types.zig");
pub const peb = @import("../types/peb.zig");
pub const peb_walk = @import("../types/peb_walk.zig");
pub const export_resolve = @import("../types/export_resolve.zig");
pub const hash = @import("../types/hash.zig");

pub const engine = @import("../syscalls/engine.zig");
pub const stub_gen = @import("../syscalls/stubs.zig");
pub const gadget = @import("../syscalls/gadget.zig");
pub const stack_spoof = @import("../syscalls/stack_spoof.zig");
pub const ntdll_unhook = @import("../syscalls/ntdll_unhook.zig");
pub const dbg = @import("../syscalls/dbg.zig");

pub fn getEnvVarW(name: []const u8, allocator: std.mem.Allocator) ?[]const u8 {
    return std.process.getEnvVarOwned(allocator, name) catch null;
}

test "Windows module loads" {
    try std.testing.expect(@hasDecl(types, "PVOID"));
    try std.testing.expect(@hasDecl(types, "HANDLE"));
    try std.testing.expect(@hasDecl(types, "NTSTATUS"));
    try std.testing.expect(@hasDecl(peb, "getPeb"));
    try std.testing.expect(@hasDecl(engine, "NtOpenKey"));
    try std.testing.expect(@hasDecl(engine, "NtAllocateVirtualMemory"));
    try std.testing.expect(@hasDecl(engine, "resolve"));
    try std.testing.expect(@hasDecl(gadget, "initialize"));
    try std.testing.expect(@hasDecl(stack_spoof, "initialize"));
}
