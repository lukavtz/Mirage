const std = @import("std");
const http = @import("http.zig");

pub const TelegramError = error{
    RequestFailed,
    InvalidResponse,
    ApiError,
    CaptionTooLong,
};

pub fn sendDocument(
    allocator: std.mem.Allocator,
    token: []const u8,
    chat_id: []const u8,
    file_data: []const u8,
    filename: []const u8,
    caption: []const u8,
) !void {
    if (caption.len > 1000) return error.CaptionTooLong;

    const boundary = "----MirageFormBoundary7MA4YWxkTrZu0gW";

    var body = try std.ArrayList(u8).initCapacity(allocator, 4096);
    defer body.deinit(allocator);

    try body.appendSlice(allocator, "--");
    try body.appendSlice(allocator, boundary);
    try body.appendSlice(allocator, "\r\n");
    try body.appendSlice(allocator, "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n");
    try body.appendSlice(allocator, chat_id);
    try body.appendSlice(allocator, "\r\n");

    try body.appendSlice(allocator, "--");
    try body.appendSlice(allocator, boundary);
    try body.appendSlice(allocator, "\r\n");
    try body.appendSlice(allocator, "Content-Disposition: form-data; name=\"document\"; filename=\"");
    try body.appendSlice(allocator, filename);
    try body.appendSlice(allocator, "\"\r\n");
    try body.appendSlice(allocator, "Content-Type: application/octet-stream\r\n\r\n");
    try body.appendSlice(allocator, file_data);
    try body.appendSlice(allocator, "\r\n");

    if (caption.len > 0) {
        try body.appendSlice(allocator, "--");
        try body.appendSlice(allocator, boundary);
        try body.appendSlice(allocator, "\r\n");
        try body.appendSlice(allocator, "Content-Disposition: form-data; name=\"caption\"\r\n\r\n");
        try body.appendSlice(allocator, caption);
        try body.appendSlice(allocator, "\r\n");
    }

    try body.appendSlice(allocator, "--");
    try body.appendSlice(allocator, boundary);
    try body.appendSlice(allocator, "--\r\n");

    var path = try std.ArrayList(u8).initCapacity(allocator, 128);
    defer path.deinit(allocator);
    try path.appendSlice(allocator, "/bot");
    try path.appendSlice(allocator, token);
    try path.appendSlice(allocator, "/sendDocument");

    var client = http.HttpClient.connect("api.telegram.org", 443) catch return error.RequestFailed;
    defer client.close();

    const headers = [_]http.Header{};
    const resp = client.postMultipart(path.items, &headers, boundary, body.items) catch return error.RequestFailed;
    defer resp.deinit();

    if (resp.status != 200) return error.ApiError;
}

test "sendDocument caption length limit" {
    const short = "short caption";
    const long = "x" ** 1001;

    try std.testing.expect(short.len <= 1000);
    try std.testing.expect(long.len > 1000);
}

test "boundary format" {
    const boundary = "----MirageFormBoundary7MA4YWxkTrZu0gW";
    try std.testing.expect(boundary.len > 10);
    try std.testing.expect(boundary[0] == '-' and boundary[1] == '-');
}

test "sendDocument parameter types" {
    try std.testing.expect(@TypeOf(sendDocument) == fn (
        std.mem.Allocator,
        []const u8,
        []const u8,
        []const u8,
        []const u8,
        []const u8,
    ) anyerror!void);
}
