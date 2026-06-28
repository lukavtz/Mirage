const std = @import("std");
const tls_socket = @import("tls_socket.zig");

pub const HttpError = error{
    ConnectionFailed,
    SendFailed,
    RecvFailed,
    InvalidResponse,
    StatusError,
    HeaderParseFailed,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Response = struct {
    status: u16,
    body: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Response) void {
        self.allocator.free(self.body);
    }
};

pub const HttpClient = struct {
    socket: tls_socket.TlsSocket,
    hostname: []const u8,
    port: u16,

    pub fn connect(hostname: []const u8, port: u16) !HttpClient {
        const sock = tls_socket.TlsSocket.connect(hostname, port) catch return error.ConnectionFailed;
        return HttpClient{
            .socket = sock,
            .hostname = hostname,
            .port = port,
        };
    }

    pub fn get(self: *HttpClient, path: []const u8, headers: []const Header) !Response {
        var req = std.ArrayList(u8).initCapacity(std.heap.page_allocator, 512) catch return error.SendFailed;
        defer req.deinit(std.heap.page_allocator);

        req.appendSlice(std.heap.page_allocator, "GET ") catch return error.SendFailed;
        req.appendSlice(std.heap.page_allocator, path) catch return error.SendFailed;
        req.appendSlice(std.heap.page_allocator, " HTTP/1.1\r\n") catch return error.SendFailed;
        req.appendSlice(std.heap.page_allocator, "Host: ") catch return error.SendFailed;
        req.appendSlice(std.heap.page_allocator, self.hostname) catch return error.SendFailed;
        req.appendSlice(std.heap.page_allocator, "\r\n") catch return error.SendFailed;
        req.appendSlice(std.heap.page_allocator, "Connection: close\r\n") catch return error.SendFailed;

        for (headers) |h| {
            req.appendSlice(std.heap.page_allocator, h.name) catch return error.SendFailed;
            req.appendSlice(std.heap.page_allocator, ": ") catch return error.SendFailed;
            req.appendSlice(std.heap.page_allocator, h.value) catch return error.SendFailed;
            req.appendSlice(std.heap.page_allocator, "\r\n") catch return error.SendFailed;
        }

        req.appendSlice(std.heap.page_allocator, "\r\n") catch return error.SendFailed;

        self.socket.send(req.items) catch return error.SendFailed;
        return self.readResponse();
    }

    pub fn postMultipart(
        self: *HttpClient,
        path: []const u8,
        headers: []const Header,
        boundary: []const u8,
        body: []const u8,
    ) !Response {
        var req = std.ArrayList(u8).initCapacity(std.heap.page_allocator, 1024) catch return error.SendFailed;
        defer req.deinit(std.heap.page_allocator);

        const alloc = std.heap.page_allocator;
        req.appendSlice(alloc, "POST ") catch return error.SendFailed;
        req.appendSlice(alloc, path) catch return error.SendFailed;
        req.appendSlice(alloc, " HTTP/1.1\r\n") catch return error.SendFailed;
        req.appendSlice(alloc, "Host: ") catch return error.SendFailed;
        req.appendSlice(alloc, self.hostname) catch return error.SendFailed;
        req.appendSlice(alloc, "\r\n") catch return error.SendFailed;
        req.appendSlice(alloc, "Content-Type: multipart/form-data; boundary=") catch return error.SendFailed;
        req.appendSlice(alloc, boundary) catch return error.SendFailed;
        req.appendSlice(alloc, "\r\n") catch return error.SendFailed;
        req.appendSlice(alloc, "Content-Length: ") catch return error.SendFailed;
        {
            var cl_buf: [20]u8 = undefined;
            const cl_str = std.fmt.bufPrint(&cl_buf, "{d}", .{body.len}) catch return error.SendFailed;
            req.appendSlice(alloc, cl_str) catch return error.SendFailed;
        }
        req.appendSlice(alloc, "\r\n") catch return error.SendFailed;
        req.appendSlice(alloc, "Connection: close\r\n") catch return error.SendFailed;

        for (headers) |h| {
            req.appendSlice(alloc, h.name) catch return error.SendFailed;
            req.appendSlice(alloc, ": ") catch return error.SendFailed;
            req.appendSlice(alloc, h.value) catch return error.SendFailed;
            req.appendSlice(alloc, "\r\n") catch return error.SendFailed;
        }

        req.appendSlice(alloc, "\r\n") catch return error.SendFailed;
        req.appendSlice(alloc, body) catch return error.SendFailed;

        self.socket.send(req.items) catch return error.SendFailed;
        return self.readResponse();
    }

    fn readResponse(self: *HttpClient) !Response {
        var response = std.ArrayList(u8).initCapacity(std.heap.page_allocator, 4096) catch return error.RecvFailed;
        errdefer response.deinit(std.heap.page_allocator);
        var recv_buf: [0x8000]u8 = undefined;

        while (true) {
            const n = self.socket.recv(recv_buf[0..]) catch return error.RecvFailed;
            if (n == 0) break;
            response.appendSlice(std.heap.page_allocator, recv_buf[0..n]) catch return error.RecvFailed;
        }

        if (response.items.len == 0) return error.InvalidResponse;

        const data = response.items;
        const header_end = findHeaderEnd(data) orelse return error.HeaderParseFailed;

        const status_line = data[0..findLineEnd(data).?];
        var status: u16 = 0;
        var parts = std.mem.splitScalar(u8, status_line, ' ');
        _ = parts.next();
        if (parts.next()) |status_str| {
            status = std.fmt.parseInt(u16, status_str, 10) catch return error.InvalidResponse;
        } else {
            return error.InvalidResponse;
        }

        const body_start = header_end + 4;
        const body = if (body_start < data.len) data[body_start..] else &[_]u8{};

        var content_length: ?usize = null;
        const header_section = data[0..header_end];
        var header_lines = std.mem.splitSequence(u8, header_section, "\r\n");
        _ = header_lines.next();

        while (header_lines.next()) |line| {
            if (line.len == 0) break;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const name = std.mem.trim(u8, line[0..colon], " ");
            const value = std.mem.trim(u8, line[colon + 1 ..], " ");
            if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                content_length = std.fmt.parseInt(usize, value, 10) catch null;
            }
        }

        const final_body = if (content_length) |cl| blk: {
            if (body.len > cl) break :blk body[0..cl];
            break :blk body;
        } else body;

        const body_copy = std.heap.page_allocator.dupe(u8, final_body) catch return error.InvalidResponse;

        response.deinit(std.heap.page_allocator);

        return Response{
            .status = status,
            .body = body_copy,
            .allocator = std.heap.page_allocator,
        };
    }

    pub fn close(self: *HttpClient) void {
        self.socket.close();
    }
};

fn findHeaderEnd(data: []const u8) ?usize {
    if (data.len < 4) return null;
    var i: usize = 0;
    while (i < data.len - 3) : (i += 1) {
        if (data[i] == '\r' and data[i + 1] == '\n' and data[i + 2] == '\r' and data[i + 3] == '\n') {
            return i;
        }
    }
    return null;
}

fn findLineEnd(data: []const u8) ?usize {
    var i: usize = 0;
    while (i < data.len - 1) : (i += 1) {
        if (data[i] == '\r' and data[i + 1] == '\n') {
            return i;
        }
    }
    return null;
}

test "findHeaderEnd basic" {
    const data = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";
    try std.testing.expectEqual(@as(usize, 44), findHeaderEnd(data).?);
}

test "findHeaderEnd no header" {
    try std.testing.expect(findHeaderEnd("no header") == null);
}

test "findLineEnd basic" {
    const data = "HTTP/1.1 200 OK\r\n";
    try std.testing.expectEqual(@as(usize, 17), findLineEnd(data).?);
}

test "findLineEnd no newline" {
    try std.testing.expect(findLineEnd("no newline") == null);
}

test "Response deinit" {
    var resp = Response{
        .status = 200,
        .body = try std.testing.allocator.dupe(u8, "test"),
        .allocator = std.testing.allocator,
    };
    resp.deinit();
}

test "Header struct" {
    const h = Header{ .name = "Authorization", .value = "Bearer token" };
    try std.testing.expectEqualStrings("Authorization", h.name);
    try std.testing.expectEqualStrings("Bearer token", h.value);
}

test "HttpClient structure" {
    try std.testing.expect(@sizeOf(HttpClient) > 0);
}
