const std = @import("std");
const types = @import("../types/types.zig");
const ws2 = @import("ws2.zig");
const schannel = @import("schannel.zig");

pub const TlsSocket = struct {
    sock: types.HANDLE,
    tls: schannel.TlsContext,

    pub fn connect(hostname: []const u8, port: u16) !TlsSocket {
        var ws = try ws2.Socket.init();
        errdefer ws.deinit();

        const sock = try ws2.Socket.connect(hostname, port);
        errdefer ws2.Socket.close(sock);

        const tls = try schannel.TlsContext.connect(sock, hostname);
        ws.deinit();

        return TlsSocket{
            .sock = sock,
            .tls = tls,
        };
    }

    pub fn send(self: *TlsSocket, data: []const u8) !void {
        _ = try self.tls.send(data);
    }

    pub fn recv(self: *TlsSocket, buffer: []u8) !usize {
        return self.tls.recv(buffer);
    }

    pub fn close(self: *TlsSocket) void {
        self.tls.deinit();
        ws2.Socket.close(self.sock);
    }
};

test "TlsSocket structure" {
    try std.testing.expect(@sizeOf(TlsSocket) > 0);
}

test "TlsSocket field offsets" {
    try std.testing.expect(@offsetOf(TlsSocket, "sock") < @offsetOf(TlsSocket, "tls") orelse true);
}
