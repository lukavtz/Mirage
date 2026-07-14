const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .macos) @compileError("macos.zig is macOS-only");
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
    if (getEnvVar("HOME", allocator)) |home| {
        return std.fs.path.join(allocator, &.{ home, "Library", "Preferences" }) catch null;
    }
    return null;
}

pub fn getKeychainDir(allocator: std.mem.Allocator) ?[]const u8 {
    if (getEnvVar("HOME", allocator)) |home| {
        return std.fs.path.join(allocator, &.{ home, "Library", "Keychains" }) catch null;
    }
    return null;
}

pub fn keychainCopyGenericPassword(service: []const u8, account: []const u8) ![]u8 {
    _ = service;
    _ = account;
    return error.NotImplemented;
}

pub fn keychainCopyInternetPassword(server: []const u8, account: []const u8) ![]u8 {
    _ = server;
    _ = account;
    return error.NotImplemented;
}

test "macos stubs compile and return errors" {
    try std.testing.expectError(error.NotImplemented, openDir("/tmp"));
}

test "macos keychain stubs return NotImplemented" {
    try std.testing.expectError(error.NotImplemented, keychainCopyGenericPassword("test", "user"));
    try std.testing.expectError(error.NotImplemented, keychainCopyInternetPassword("example.com", "user"));
}
