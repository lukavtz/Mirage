const std = @import("std");
const hash = @import("../types/hash.zig");

pub const PluginType = enum(u32) {
    Collector = 0,
    Evasion = 1,
    Network = 2,
};

pub const PluginManifest = struct {
    name: []const u8,
    version: []const u8,
    plugin_type: PluginType,
    entry_point: []const u8,
};

pub const PluginError = error{
    InvalidManifest,
    DownloadFailed,
    ParseFailed,
    NotFound,
    ExecuteFailed,
};

const manifest_key_name = hash.xorEncrypt("name");
const manifest_key_version = hash.xorEncrypt("version");
const manifest_key_type = hash.xorEncrypt("plugin_type");
const manifest_key_entry = hash.xorEncrypt("entry_point");
const manifest_key_collector = hash.xorEncrypt("Collector");
const manifest_key_evasion = hash.xorEncrypt("Evasion");
const manifest_key_network = hash.xorEncrypt("Network");

pub const PluginManager = struct {
    plugins: std.ArrayList(PluginManifest),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PluginManager {
        return PluginManager{
            .plugins = std.ArrayList(PluginManifest).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PluginManager) void {
        for (self.plugins.items) |p| {
            self.allocator.free(p.name);
            self.allocator.free(p.version);
            self.allocator.free(p.entry_point);
        }
        self.plugins.deinit();
    }

    pub fn load(self: *PluginManager, url: []const u8) !PluginManifest {
        _ = url;
        _ = self;
        return error.DownloadFailed;
    }

    pub fn loadFromManifest(self: *PluginManager, json: []const u8) !PluginManifest {
        const name = extractJsonString(json, "name") orelse return error.InvalidManifest;
        const version = extractJsonString(json, "version") orelse return error.InvalidManifest;
        const type_str = extractJsonString(json, "plugin_type") orelse return error.InvalidManifest;
        const entry = extractJsonString(json, "entry_point") orelse return error.InvalidManifest;

        const ptype = parsePluginType(type_str) orelse return error.InvalidManifest;

        const manifest = PluginManifest{
            .name = try self.allocator.dupe(u8, name),
            .version = try self.allocator.dupe(u8, version),
            .plugin_type = ptype,
            .entry_point = try self.allocator.dupe(u8, entry),
        };

        try self.plugins.append(manifest);
        return manifest;
    }

    pub fn execute(self: *PluginManager, name: []const u8) bool {
        for (self.plugins.items) |p| {
            if (std.mem.eql(u8, p.name, name)) {
                return true;
            }
        }
        return false;
    }

    pub fn list(self: *PluginManager) []PluginManifest {
        return self.plugins.items;
    }
};

fn extractJsonString(json: []const u8, key: []const u8) ?[]const u8 {
    const search = struct {
        fn findKey(inner: []const u8, k: []const u8) ?usize {
            var i: usize = 0;
            while (i + k.len + 4 < inner.len) : (i += 1) {
                if (inner[i] == '"' and std.mem.startsWith(u8, inner[i + 1 ..], k) and inner[i + 1 + k.len] == '"') {
                    var j = i + 1 + k.len + 1;
                    while (j < inner.len and (inner[j] == ':' or inner[j] == ' ')) : (j += 1) {}
                    if (j < inner.len and inner[j] == '"') {
                        j += 1;
                        const start = j;
                        while (j < inner.len and inner[j] != '"') : (j += 1) {}
                        if (j < inner.len) return start;
                    }
                }
            }
            return null;
        }
    }.findKey(json, key) orelse return null;

    const value_start = search;
    const value_end = blk: {
        var i = value_start;
        while (i < json.len and json[i] != '"') : (i += 1) {}
        break :blk i;
    };
    if (value_end <= value_start) return null;
    return json[value_start..value_end];
}

fn parsePluginType(t: []const u8) ?PluginType {
    if (std.mem.eql(u8, t, "Collector")) return .Collector;
    if (std.mem.eql(u8, t, "Evasion")) return .Evasion;
    if (std.mem.eql(u8, t, "Network")) return .Network;
    return null;
}

test "plugin type enum values" {
    try std.testing.expectEqual(@as(u32, 0), @intFromEnum(PluginType.Collector));
    try std.testing.expectEqual(@as(u32, 1), @intFromEnum(PluginType.Evasion));
    try std.testing.expectEqual(@as(u32, 2), @intFromEnum(PluginType.Network));
}

test "plugin manifest struct" {
    const manifest = PluginManifest{
        .name = "test-plugin",
        .version = "1.0.0",
        .plugin_type = PluginType.Collector,
        .entry_point = "collect.zig",
    };
    try std.testing.expectEqualStrings("test-plugin", manifest.name);
    try std.testing.expectEqualStrings("1.0.0", manifest.version);
}

test "plugin manager init and deinit" {
    var pm = PluginManager.init(std.testing.allocator);
    defer pm.deinit();
    try std.testing.expectEqual(@as(usize, 0), pm.plugins.items.len);
}

test "plugin manager load from manifest" {
    const json = "{\"name\":\"test\",\"version\":\"1.0\",\"plugin_type\":\"Collector\",\"entry_point\":\"main.wasm\"}";
    var pm = PluginManager.init(std.testing.allocator);
    defer pm.deinit();

    const manifest = try pm.loadFromManifest(json);
    try std.testing.expectEqualStrings("test", manifest.name);
}

test "plugin manager execute existing" {
    var pm = PluginManager.init(std.testing.allocator);
    defer pm.deinit();
    _ = try pm.loadFromManifest("{\"name\":\"alpha\",\"version\":\"1.0\",\"plugin_type\":\"Evasion\",\"entry_point\":\"evade\"}");
    try std.testing.expect(pm.execute("alpha"));
    try std.testing.expect(!pm.execute("nonexistent"));
}

test "plugin manager list" {
    var pm = PluginManager.init(std.testing.allocator);
    defer pm.deinit();
    _ = try pm.loadFromManifest("{\"name\":\"a\",\"version\":\"1\",\"plugin_type\":\"Network\",\"entry_point\":\"net\"}");
    try std.testing.expectEqual(@as(usize, 1), pm.list().len);
}

test "plugin extractJsonString" {
    const json = "{\"name\":\"hello\",\"version\":\"1.0\"}";
    const name = extractJsonString(json, "name");
    try std.testing.expect(name != null);
    try std.testing.expectEqualStrings("hello", name.?);
}

test "plugin extractJsonString missing" {
    const json = "{\"other\":1}";
    try std.testing.expect(extractJsonString(json, "name") == null);
}

test "plugin parsePluginType" {
    try std.testing.expectEqual(PluginType.Collector, parsePluginType("Collector").?);
    try std.testing.expectEqual(PluginType.Evasion, parsePluginType("Evasion").?);
    try std.testing.expectEqual(PluginType.Network, parsePluginType("Network").?);
    try std.testing.expect(parsePluginType("Unknown") == null);
}

test "plugin load error returns" {
    var pm = PluginManager.init(std.testing.allocator);
    defer pm.deinit();
    const result = pm.load("http://example.com/plugin.zip");
    try std.testing.expectError(error.DownloadFailed, result);
}

test "plugin manifest field sizes" {
    try std.testing.expect(@sizeOf(PluginManifest) > 0);
}
