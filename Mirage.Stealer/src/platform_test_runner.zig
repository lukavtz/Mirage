const std = @import("std");
const builtin = @import("builtin");
const platform = @import("platform/platform.zig");

test "currentOs returns the correct OS tag" {
    const expected: platform.OsTag = switch (builtin.os.tag) {
        .windows => .Windows,
        .linux => .Linux,
        .macos => .macOS,
        else => @compileError("unsupported"),
    };
    try std.testing.expectEqual(expected, platform.currentOs());
}

test "Windows platform module imports cleanly" {
    if (builtin.os.tag == .windows) {
        const win = @import("platform/windows.zig");
        _ = win;
    }
}

test "Windows module exports expected symbols" {
    if (builtin.os.tag == .windows) {
        const win = @import("platform/windows.zig");
        try std.testing.expect(@hasDecl(win.types, "PVOID"));
        try std.testing.expect(@hasDecl(win.types, "HANDLE"));
        try std.testing.expect(@hasDecl(win.types, "NTSTATUS"));
        try std.testing.expect(@hasDecl(win.peb, "getPeb"));
        try std.testing.expect(@hasDecl(win.engine, "NtOpenKey"));
        try std.testing.expect(@hasDecl(win.engine, "NtAllocateVirtualMemory"));
        try std.testing.expect(@hasDecl(win.engine, "resolve"));
    }
}
