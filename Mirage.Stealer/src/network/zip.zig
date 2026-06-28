const std = @import("std");

const crc32_table = blk: {
    @setEvalBranchQuota(5000);
    var table: [256]u32 = undefined;
    for (0..256) |i| {
        var crc: u32 = @truncate(i);
        for (0..8) |_| {
            crc = if (crc & 1 != 0) (crc >> 1) ^ 0xEDB88320 else crc >> 1;
        }
        table[i] = crc;
    }
    break :blk table;
};

fn crc32(data: []const u8) u32 {
    var crc: u32 = 0xFFFFFFFF;
    for (data) |b| {
        crc = crc32_table[(crc ^ b) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

pub const ZipWriter = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8),
    files: std.ArrayList(FileEntry),

    const FileEntry = struct {
        name: []u8,
        data: []u8,
        crc: u32,
        compressed_size: u32,
        uncompressed_size: u32,
        header_offset: u32,
    };

    pub fn init(allocator: std.mem.Allocator) !ZipWriter {
        return ZipWriter{
            .allocator = allocator,
            .buffer = try std.ArrayList(u8).initCapacity(allocator, 4096),
            .files = try std.ArrayList(FileEntry).initCapacity(allocator, 32),
        };
    }

    pub fn addFile(self: *ZipWriter, name: []const u8, data: []const u8) !void {
        const crc = crc32(data);
        const offset = @as(u32, @intCast(self.buffer.items.len));

        const dos_time: u16 = (1 << 5) | (1 << 11);
        const dos_date: u16 = (1 << 5) | (1 << 9) | ((20) << 11);

        const name_copy = try self.allocator.dupe(u8, name);
        const data_copy = try self.allocator.dupe(u8, data);

        try self.files.append(self.allocator, .{
            .name = name_copy,
            .data = data_copy,
            .crc = crc,
            .compressed_size = @intCast(data.len),
            .uncompressed_size = @intCast(data.len),
            .header_offset = offset,
        });

        try writeU32Le(&self.buffer, self.allocator, 0x04034B50);
        try writeU16Le(&self.buffer, self.allocator, 20);
        try writeU16Le(&self.buffer, self.allocator, 0x0800);
        try writeU16Le(&self.buffer, self.allocator, 0);
        try writeU16Le(&self.buffer, self.allocator, dos_time);
        try writeU16Le(&self.buffer, self.allocator, dos_date);
        try writeU32Le(&self.buffer, self.allocator, crc);
        try writeU32Le(&self.buffer, self.allocator, @intCast(data.len));
        try writeU32Le(&self.buffer, self.allocator, @intCast(data.len));
        try writeU16Le(&self.buffer, self.allocator, @intCast(name.len));
        try writeU16Le(&self.buffer, self.allocator, 0);

        try self.buffer.appendSlice(self.allocator, name);
        try self.buffer.appendSlice(self.allocator, data);
    }

    pub fn finalize(self: *ZipWriter) ![]const u8 {
        const central_offset = @as(u32, @intCast(self.buffer.items.len));

        for (self.files.items) |file| {
            try writeU32Le(&self.buffer, self.allocator, 0x02014B50);
            try writeU16Le(&self.buffer, self.allocator, 20);
            try writeU16Le(&self.buffer, self.allocator, 20);
            try writeU16Le(&self.buffer, self.allocator, 0x0800);
            try writeU16Le(&self.buffer, self.allocator, 0);
            const dos_time: u16 = (1 << 5) | (1 << 11);
            const dos_date: u16 = (1 << 5) | (1 << 9) | ((20) << 11);
            try writeU16Le(&self.buffer, self.allocator, dos_time);
            try writeU16Le(&self.buffer, self.allocator, dos_date);
            try writeU32Le(&self.buffer, self.allocator, file.crc);
            try writeU32Le(&self.buffer, self.allocator, file.compressed_size);
            try writeU32Le(&self.buffer, self.allocator, file.uncompressed_size);
            try writeU16Le(&self.buffer, self.allocator, @intCast(file.name.len));
            try writeU16Le(&self.buffer, self.allocator, 0);
            try writeU16Le(&self.buffer, self.allocator, 0);
            try writeU16Le(&self.buffer, self.allocator, 0);
            try writeU16Le(&self.buffer, self.allocator, 0);
            try writeU16Le(&self.buffer, self.allocator, 0);
            try writeU32Le(&self.buffer, self.allocator, 0x8100);
            try writeU32Le(&self.buffer, self.allocator, file.header_offset);
            try self.buffer.appendSlice(self.allocator, file.name);
        }

        const central_size = @as(u32, @intCast(self.buffer.items.len - central_offset));

        try writeU32Le(&self.buffer, self.allocator, 0x06054B50);
        try writeU16Le(&self.buffer, self.allocator, 0);
        try writeU16Le(&self.buffer, self.allocator, 0);
        try writeU16Le(&self.buffer, self.allocator, @intCast(self.files.items.len));
        try writeU16Le(&self.buffer, self.allocator, @intCast(self.files.items.len));
        try writeU32Le(&self.buffer, self.allocator, central_size);
        try writeU32Le(&self.buffer, self.allocator, central_offset);
        try writeU16Le(&self.buffer, self.allocator, 0);

        return self.buffer.items;
    }

    pub fn deinit(self: *ZipWriter) void {
        for (self.files.items) |file| {
            self.allocator.free(file.name);
            self.allocator.free(file.data);
        }
        self.files.deinit(self.allocator);
        self.buffer.deinit(self.allocator);
    }
};

fn writeU16Le(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u16) !void {
    try buf.append(allocator, @as(u8, @truncate(value)));
    try buf.append(allocator, @as(u8, @truncate(value >> 8)));
}

fn writeU32Le(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) !void {
    try buf.append(allocator, @as(u8, @truncate(value)));
    try buf.append(allocator, @as(u8, @truncate(value >> 8)));
    try buf.append(allocator, @as(u8, @truncate(value >> 16)));
    try buf.append(allocator, @as(u8, @truncate(value >> 24)));
}

test "crc32 deterministic" {
    const a = crc32("hello");
    const b = crc32("hello");
    try std.testing.expectEqual(a, b);
    try std.testing.expect(a != 0);
}

test "crc32 different inputs differ" {
    const a = crc32("hello");
    const b = crc32("world");
    try std.testing.expect(a != b);
}

test "crc32 empty" {
    const c = crc32("");
    try std.testing.expectEqual(@as(u32, 0), c);
}

test "zip roundtrip single file" {
    var z = try ZipWriter.init(std.testing.allocator);
    defer z.deinit();

    try z.addFile("test.txt", "Hello, World!");
    const archive = try z.finalize();

    try std.testing.expect(archive.len > 30);
    try std.testing.expectEqual(@as(u32, 0x04034B50), std.mem.readInt(u32, archive[0..4], .little));
    try std.testing.expectEqual(@as(u32, 0x06054B50), std.mem.readInt(u32, archive[archive.len - 22 ..][0..4], .little));

    {
        const eocd_offset = archive.len - 22;
        const cd_offset = std.mem.readInt(u32, archive[eocd_offset + 16 ..][0..4], .little);
        const cd_sig = std.mem.readInt(u32, archive[cd_offset..][0..4], .little);
        try std.testing.expectEqual(@as(u32, 0x02014B50), cd_sig);
    }
}

test "zip roundtrip multiple files" {
    var z = try ZipWriter.init(std.testing.allocator);
    defer z.deinit();

    try z.addFile("a.txt", "AAA");
    try z.addFile("b.txt", "BBB");
    try z.addFile("c.txt", "CCC");
    const archive = try z.finalize();

    const eocd = archive[archive.len - 22 ..];
    try std.testing.expectEqual(@as(u16, 3), std.mem.readInt(u16, eocd[8..10], .little));
    try std.testing.expectEqual(@as(u16, 3), std.mem.readInt(u16, eocd[10..12], .little));
}

test "zip empty filename" {
    var z = try ZipWriter.init(std.testing.allocator);
    defer z.deinit();
    try z.addFile("", "data");
    const archive = try z.finalize();
    try std.testing.expect(archive.len > 0);
}
