const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");
const ws2 = @import("ws2.zig");

pub const TlsError = error{
    SchannelLoadFailed,
    FunctionNotFound,
    CredentialsAcquireFailed,
    HandshakeFailed,
    EncryptFailed,
    DecryptFailed,
    IncompleteMessage,
    StreamSizesQueryFailed,
    FreeContextBufferFailed,
    ContextDeletionFailed,
};

const SEC_E_OK: i32 = 0x00000000;
const SEC_I_CONTINUE_NEEDED: i32 = 0x00090312;
const SEC_I_INCOMPLETE_CREDENTIALS: i32 = 0x00090320;
const SEC_E_INCOMPLETE_MESSAGE: i32 = -2146893032;

const SECPKG_CRED_OUTBOUND: u32 = 0x00000002;
const ISC_REQ_STREAM: u32 = 0x00008000;
const ISC_REQ_MANUAL_CRED_VALIDATION: u32 = 0x00080000;
const ISC_REQ_ALLOCATE_MEMORY: u32 = 0x00000100;
const SCH_CRED_MANUAL_CRED_VALIDATION: u32 = 0x00000008;
const SCH_CRED_VERSION: u32 = 4;
const SECPKG_ATTR_STREAM_SIZES: u32 = 0x0A;

const SECBUFFER_EMPTY: u32 = 0;
const SECBUFFER_DATA: u32 = 1;
const SECBUFFER_TOKEN: u32 = 2;
const SECBUFFER_EXTRA: u32 = 5;
const SECBUFFER_STREAM_TRAILER: u32 = 6;
const SECBUFFER_STREAM_HEADER: u32 = 7;

const SCHANNEL_CRED = extern struct {
    dwVersion: u32,
    cCreds: u32,
    paCred: ?*const anyopaque,
    hRootStore: ?*anyopaque,
    cMappers: u32,
    phMappers: ?*anyopaque,
    cSupportedAlgs: u32,
    palgSupportedAlgs: ?*anyopaque,
    dwFlags: u32,
    dwMinStrength: u32,
    dwMaxStrength: u32,
};

const SecHandle = extern struct {
    dwLower: usize,
    dwUpper: usize,
};

const TimeStamp = extern struct {
    LowPart: u32,
    HighPart: i32,
};

const SecBuffer = extern struct {
    cbBuffer: u32,
    BufferType: u32,
    pvBuffer: ?*anyopaque,
};

const SecBufferDesc = extern struct {
    ulVersion: u32,
    cBuffers: u32,
    pBuffers: *SecBuffer,
};

const SecPkgContext_StreamSizes = extern struct {
    cbHeader: u32,
    cbTrailer: u32,
    cbMaximumMessage: u32,
    cBuffers: u32,
    cbBlockSize: u32,
};

const SecFunctions = struct {
    AcquireCredentialsHandleA: *const fn (
        pszPrincipal: ?*u8,
        pszPackage: [*:0]u8,
        fCredentialUse: u32,
        pvLogonId: ?*anyopaque,
        pAuthData: ?*const anyopaque,
        pGetKeyFn: ?*const anyopaque,
        pvGetKeyArgument: ?*anyopaque,
        phCredential: *SecHandle,
        ptsExpiry: *TimeStamp,
    ) callconv(.winapi) i32,

    InitializeSecurityContextA: *const fn (
        phCredential: *SecHandle,
        phContext: ?*SecHandle,
        pszTargetName: *u8,
        fContextReq: u32,
        reserved1: u32,
        targetDataRep: u32,
        pInput: ?*SecBufferDesc,
        reserved2: u32,
        phNewContext: *SecHandle,
        pOutput: *SecBufferDesc,
        pfContextAttr: *u32,
        ptsExpiry: *TimeStamp,
    ) callconv(.winapi) i32,

    EncryptMessage: *const fn (phContext: *SecHandle, fQop: u32, pMessage: *SecBufferDesc, messageSeqNo: u32) callconv(.winapi) i32,
    DecryptMessage: *const fn (phContext: *SecHandle, pMessage: *SecBufferDesc, messageSeqNo: u32, pfQop: ?*u32) callconv(.winapi) i32,
    FreeCredentialsHandle: *const fn (phCredential: *SecHandle) callconv(.winapi) i32,
    DeleteSecurityContext: *const fn (phContext: *SecHandle) callconv(.winapi) i32,
    ApplyControlToken: *const fn (phContext: *SecHandle, pInput: *SecBufferDesc) callconv(.winapi) i32,
    CompleteAuthToken: *const fn (phContext: *SecHandle, pInput: *SecBufferDesc) callconv(.winapi) i32,
    FreeContextBuffer: *const fn (pvBuffer: *anyopaque) callconv(.winapi) i32,
    QueryContextAttributesA: *const fn (phContext: *SecHandle, ulAttribute: u32, pBuffer: *anyopaque) callconv(.winapi) i32,
};

var g_fns: SecFunctions = undefined;
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
        .Buffer = @as([*]u16, @ptrCast(&wide_buf)),
    };

    var base: types.PVOID = undefined;
    const status = ldr_load(null, null, &unicode_str, &base);
    if (status < 0) return null;
    return base;
}

fn getFunctions() !*const SecFunctions {
    if (g_initialized) return &g_fns;

    const base = loadModule("secur32.dll") orelse return error.SchannelLoadFailed;

    inline for (@typeInfo(SecFunctions).Struct.fields) |field| {
        const func_hash = hash.encryptedHashFunc(field.name);
        const ptr = export_resolve.getFunctionByHash(base, func_hash) orelse return error.FunctionNotFound;
        @field(g_fns, field.name) = @ptrCast(@alignCast(ptr));
    }

    g_initialized = true;
    return &g_fns;
}

pub const TlsContext = struct {
    cred_handle: SecHandle,
    ctx_handle: SecHandle,
    sock: types.HANDLE,
    stream_sizes: SecPkgContext_StreamSizes,

    pub fn connect(sock: types.HANDLE, hostname: []const u8) !TlsContext {
        const fns = try getFunctions();

        var cred_handle: SecHandle = .{ .dwLower = 0, .dwUpper = 0 };
        var ts_expiry: TimeStamp = undefined;

        var schannel_cred = SCHANNEL_CRED{
            .dwVersion = SCH_CRED_VERSION,
            .cCreds = 0,
            .paCred = null,
            .hRootStore = null,
            .cMappers = 0,
            .phMappers = null,
            .cSupportedAlgs = 0,
            .palgSupportedAlgs = null,
            .dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION,
            .dwMinStrength = 0,
            .dwMaxStrength = 0,
        };

        var schannel_name = [_]u8{ 'S', 'C', 'H', 'A', 'N', 'N', 'E', 'L', 0 };
        var status = fns.AcquireCredentialsHandleA(
            null,
            @as([*:0]u8, @ptrCast(&schannel_name)),
            SECPKG_CRED_OUTBOUND,
            null,
            &schannel_cred,
            null,
            null,
            &cred_handle,
            &ts_expiry,
        );
        if (status != SEC_E_OK) return error.CredentialsAcquireFailed;

        var ctx_handle: SecHandle = .{ .dwLower = 0, .dwUpper = 0 };
        var host_buf: [256]u8 = undefined;
        const host_slice = if (hostname.len < 255) hostname else hostname[0..255];
        @memcpy(host_buf[0..host_slice.len], host_slice);
        host_buf[host_slice.len] = 0;

        var first_time = true;
        var in_handshake_data: [0x4000]u8 = undefined;
        var in_handshake_len: usize = 0;

        while (true) {
            var out_bufs: [1]SecBuffer = undefined;
            out_bufs[0] = .{ .cbBuffer = 0, .BufferType = SECBUFFER_TOKEN, .pvBuffer = @ptrFromInt(0) };
            var out_desc = SecBufferDesc{
                .ulVersion = 0,
                .cBuffers = 1,
                .pBuffers = &out_bufs[0],
            };

            var in_bufs: [2]SecBuffer = undefined;
            var use_in_desc = false;
            var in_desc: SecBufferDesc = undefined;
            if (!first_time) {
                in_bufs[0] = .{
                    .cbBuffer = @intCast(in_handshake_len),
                    .BufferType = SECBUFFER_TOKEN,
                    .pvBuffer = @ptrCast(&in_handshake_data),
                };
                in_bufs[1] = .{ .cbBuffer = 0, .BufferType = SECBUFFER_EMPTY, .pvBuffer = null };
                in_desc = SecBufferDesc{
                    .ulVersion = 0,
                    .cBuffers = 2,
                    .pBuffers = &in_bufs[0],
                };
                use_in_desc = true;
            }

            var attrs: u32 = 0;
            var new_ts: TimeStamp = undefined;

            status = fns.InitializeSecurityContextA(
                &cred_handle,
                if (first_time) null else &ctx_handle,
                @as(*u8, @ptrCast(&host_buf)),
                ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION | ISC_REQ_ALLOCATE_MEMORY,
                0,
                0,
                if (use_in_desc) &in_desc else null,
                0,
                &ctx_handle,
                &out_desc,
                &attrs,
                &new_ts,
            );

            first_time = false;

            if (out_bufs[0].cbBuffer > 0 and out_bufs[0].pvBuffer != null) {
                const token = @as([*]u8, @ptrCast(out_bufs[0].pvBuffer.?))[0..out_bufs[0].cbBuffer];
                _ = try ws2.Socket.send(sock, token);

                if (fns.FreeContextBuffer(out_bufs[0].pvBuffer.?) != SEC_E_OK) {
                    return error.FreeContextBufferFailed;
                }
            }

            if (status == SEC_E_OK) {
                break;
            } else if (status == SEC_I_CONTINUE_NEEDED or status == SEC_I_INCOMPLETE_CREDENTIALS) {
                in_handshake_len = try ws2.Socket.recv(sock, in_handshake_data[0..]);
                if (in_handshake_len == 0) return error.HandshakeFailed;
            } else {
                _ = fns.DeleteSecurityContext(&ctx_handle);
                _ = fns.FreeCredentialsHandle(&cred_handle);
                return error.HandshakeFailed;
            }
        }

        var stream_sizes: SecPkgContext_StreamSizes = undefined;
        status = fns.QueryContextAttributesA(
            &ctx_handle,
            SECPKG_ATTR_STREAM_SIZES,
            @ptrCast(&stream_sizes),
        );
        if (status != SEC_E_OK) {
            _ = fns.DeleteSecurityContext(&ctx_handle);
            _ = fns.FreeCredentialsHandle(&cred_handle);
            return error.StreamSizesQueryFailed;
        }

        return TlsContext{
            .cred_handle = cred_handle,
            .ctx_handle = ctx_handle,
            .sock = sock,
            .stream_sizes = stream_sizes,
        };
    }

    pub fn send(self: *TlsContext, data: []const u8) !usize {
        const fns = try getFunctions();
        const max_msg = self.stream_sizes.cbMaximumMessage;
        const hdr = self.stream_sizes.cbHeader;
        const trl = self.stream_sizes.cbTrailer;

        var total_sent: usize = 0;
        var offset: usize = 0;
        var msg_buf: [0x10000]u8 = undefined;

        while (offset < data.len) {
            const chunk = @min(data.len - offset, max_msg);
            const msg_len = hdr + chunk + trl;
            @memset(msg_buf[0..msg_len], 0);
            @memcpy(msg_buf[hdr..][0..chunk], data[offset..][0..chunk]);

            var bufs: [4]SecBuffer = undefined;
            bufs[0] = .{ .cbBuffer = hdr, .BufferType = SECBUFFER_STREAM_HEADER, .pvBuffer = @ptrCast(&msg_buf[0]) };
            bufs[1] = .{ .cbBuffer = @intCast(chunk), .BufferType = SECBUFFER_DATA, .pvBuffer = @ptrCast(&msg_buf[hdr]) };
            bufs[2] = .{ .cbBuffer = trl, .BufferType = SECBUFFER_STREAM_TRAILER, .pvBuffer = @ptrCast(&msg_buf[hdr + chunk]) };
            bufs[3] = .{ .cbBuffer = 0, .BufferType = SECBUFFER_EMPTY, .pvBuffer = null };

            var desc = SecBufferDesc{
                .ulVersion = 0,
                .cBuffers = 4,
                .pBuffers = &bufs[0],
            };

            const e_status = fns.EncryptMessage(&self.ctx_handle, 0, &desc, 0);
            if (e_status != SEC_E_OK) return error.EncryptFailed;

            var total_frame: usize = 0;
            for (0..3) |i| {
                if (bufs[i].BufferType == SECBUFFER_STREAM_HEADER or
                    bufs[i].BufferType == SECBUFFER_DATA or
                    bufs[i].BufferType == SECBUFFER_STREAM_TRAILER)
                {
                    total_frame += bufs[i].cbBuffer;
                }
            }

            _ = try ws2.Socket.send(self.sock, msg_buf[0..total_frame]);
            total_sent += chunk;
            offset += chunk;
        }

        return total_sent;
    }

    pub fn recv(self: *TlsContext, buffer: []u8) !usize {
        const fns = try getFunctions();
        var recv_buf: [0x10000]u8 = undefined;
        var recv_len: usize = 0;

        while (true) {
            const n = try ws2.Socket.recv(self.sock, recv_buf[recv_len..]);
            if (n == 0 and recv_len == 0) return 0;
            recv_len += n;

            var bufs: [4]SecBuffer = undefined;
            bufs[0] = .{
                .cbBuffer = @intCast(recv_len),
                .BufferType = SECBUFFER_DATA,
                .pvBuffer = @ptrCast(&recv_buf),
            };
            for (1..4) |i| {
                bufs[i] = .{ .cbBuffer = 0, .BufferType = SECBUFFER_EMPTY, .pvBuffer = null };
            }

            var desc = SecBufferDesc{
                .ulVersion = 0,
                .cBuffers = 4,
                .pBuffers = &bufs[0],
            };

            const d_status = fns.DecryptMessage(&self.ctx_handle, &desc, 0, null);

            if (d_status == SEC_E_INCOMPLETE_MESSAGE) {
                continue;
            }

            if (d_status != SEC_E_OK) return error.DecryptFailed;

            var data_len: u32 = 0;
            var extra_len: u32 = 0;
            var data_ptr: ?*anyopaque = null;
            var extra_ptr: ?*anyopaque = null;

            for (&bufs) |*b| {
                if (b.BufferType == SECBUFFER_DATA) {
                    data_ptr = b.pvBuffer;
                    data_len = b.cbBuffer;
                } else if (b.BufferType == SECBUFFER_EXTRA) {
                    extra_ptr = b.pvBuffer;
                    extra_len = b.cbBuffer;
                }
            }

            if (data_ptr) |dp| {
                const src = @as([*]u8, @ptrCast(dp))[0..data_len];
                const to_copy = @min(buffer.len, src.len);
                @memcpy(buffer[0..to_copy], src);

                if (extra_len > 0 and extra_ptr != null) {
                    const extra_src = @as([*]u8, @ptrCast(extra_ptr.?))[0..extra_len];
                    if (@intFromPtr(extra_ptr.?) != @intFromPtr(&recv_buf)) {
                        @memcpy(recv_buf[0..extra_len], extra_src);
                    }
                    recv_len = extra_len;
                } else {
                    recv_len = 0;
                }

                return to_copy;
            }

            recv_len = 0;
        }
    }

    pub fn deinit(self: *TlsContext) void {
        const fns = getFunctions() catch return;
        _ = fns.DeleteSecurityContext(&self.ctx_handle);
        _ = fns.FreeCredentialsHandle(&self.cred_handle);
    }
};

test "SChannel structure sizes" {
    try std.testing.expectEqual(@as(usize, 44), @sizeOf(SCHANNEL_CRED));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(SecHandle));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(SecBuffer));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(SecBufferDesc));
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(SecPkgContext_StreamSizes));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(TimeStamp));
}

test "SChannel constant values" {
    try std.testing.expect(SEC_E_OK == 0);
    try std.testing.expect(SEC_I_CONTINUE_NEEDED != 0);
    try std.testing.expect(ISC_REQ_STREAM != 0);
    try std.testing.expect(SCH_CRED_MANUAL_CRED_VALIDATION != 0);
}

test "SecFunctions field count" {
    try std.testing.expect(@typeInfo(SecFunctions).Struct.fields.len == 10);
}
