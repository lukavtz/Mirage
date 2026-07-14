const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .linux) @compileError("linux.zig is Linux-only");
}

pub const DirEntry = struct {
    name: []const u8,
    kind: enum { file, directory, symlink, unknown },
};

pub fn openDir(path: []const u8) !i32 {
    _ = path;
    return error.NotImplemented;
}

pub fn readDir(fd: i32) ![]DirEntry {
    _ = fd;
    return error.NotImplemented;
}

pub fn getEnvVar(name: []const u8, allocator: std.mem.Allocator) ?[]const u8 {
    return std.process.getEnvVarOwned(allocator, name) catch null;
}

pub fn getHomeDir(allocator: std.mem.Allocator) ?[]const u8 {
    if (getEnvVar("HOME", allocator)) |home| return home;
    return null;
}

pub fn getConfigDir(allocator: std.mem.Allocator) ?[]const u8 {
    if (getEnvVar("XDG_CONFIG_HOME", allocator)) |dir| return dir;
    if (getHomeDir(allocator)) |home| {
        return std.fs.path.join(allocator, &.{ home, ".config" }) catch null;
    }
    return null;
}

pub fn getDataDir(allocator: std.mem.Allocator) ?[]const u8 {
    if (getEnvVar("XDG_DATA_HOME", allocator)) |dir| return dir;
    if (getHomeDir(allocator)) |home| {
        return std.fs.path.join(allocator, &.{ home, ".local", "share" }) catch null;
    }
    return null;
}

pub fn getProcDir(pid: u32) ?[]const u8 {
    _ = pid;
    return null;
}

test "linux stubs compile and return errors" {
    try std.testing.expectError(error.NotImplemented, openDir("/tmp"));
}

test "linux getEnvVar returns null when unset" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(?[]const u8, null), getEnvVar("MIRAGE_NONEXISTENT_VAR_XYZ", allocator));
}
