const std = @import("std");

const SUBDIRS = [_][]const u8{ "sql", "Local Storage", "Session Storage" };

pub fn collect(allocator: std.mem.Allocator, app_data: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    try collectConfig(allocator, app_data, &files);
    try collectSubdirs(allocator, app_data, &files);

    return files.toOwnedSlice();
}

fn collectConfig(allocator: std.mem.Allocator, app_data: []const u8, files: *std.ArrayList([]const u8)) !void {
    const path = try std.fs.path.join(allocator, &[_][]const u8{ app_data, "config.json" });
    errdefer allocator.free(path);

    var file = std.fs.openFileAbsolute(path, .{}) catch return;
    file.close();

    try files.append(path);
}

fn collectSubdirs(allocator: std.mem.Allocator, app_data: []const u8, files: *std.ArrayList([]const u8)) !void {
    for (SUBDIRS) |subdir| {
        const sub_path = try std.fs.path.join(allocator, &[_][]const u8{ app_data, subdir });
        defer allocator.free(sub_path);

        var dir = std.fs.openDirAbsolute(sub_path, .{ .iterate = true }) catch continue;
        defer dir.close();

        var iter = dir.iterate();
        while (iter.next() catch break) |entry| {
            if (entry.kind != .file) continue;
            const full = try std.fs.path.join(allocator, &[_][]const u8{ sub_path, entry.name });
            errdefer allocator.free(full);
            try files.append(full);
        }
    }
}

test "collect returns empty for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__signal");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "collectConfig skips missing config" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer {
        for (list.items) |f| std.testing.allocator.free(f);
        list.deinit();
    }
    try collectConfig(std.testing.allocator, "C:\\__nonexistent__", &list);
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}

test "collectSubdirs skips missing subdirs" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer {
        for (list.items) |f| std.testing.allocator.free(f);
        list.deinit();
    }
    try collectSubdirs(std.testing.allocator, "C:\\__nonexistent__", &list);
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}
