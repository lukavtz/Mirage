const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("../syscalls/engine.zig");

const OBJ_CASE_INSENSITIVE: types.ULONG = 0x00000040;
const FILE_GENERIC_READ: types.ULONG = 0x80000000;
const FILE_SHARE_READ: types.ULONG = 0x00000001;
const FILE_SHARE_WRITE: types.ULONG = 0x00000002;
const FILE_SHARE_DELETE: types.ULONG = 0x00000004;
const FILE_OPEN: types.ULONG = 0x00000001;
const FILE_NON_DIRECTORY_FILE: types.ULONG = 0x00000040;
const FILE_SYNCHRONOUS_IO_NONALERT: types.ULONG = 0x00000020;

const SEC_COMMIT: types.ULONG = 0x08000000;
const PAGE_READONLY: types.ULONG = 0x02;
const SECTION_MAP_READ: types.ULONG = 0x0004;
const VIEW_SHARE: types.ULONG = 1;

pub const MappedFile = struct {
    base: [*]const u8,
    size: usize,
    file_handle: types.HANDLE,
    section_handle: types.HANDLE,

    pub fn open(path: []const u8) ?MappedFile {
        var buf: [512]u16 = undefined;
        for (path, 0..) |c, i| {
            if (i >= buf.len) return null;
            buf[i] = c;
        }

        var name_us = types.UNICODE_STRING{
            .Length = @as(types.USHORT, @intCast(path.len * 2)),
            .MaximumLength = @as(types.USHORT, @intCast(buf.len * 2)),
            .Buffer = @as(types.PWSTR, @ptrCast(&buf)),
        };

        var attr = types.OBJECT_ATTRIBUTES{
            .Length = @sizeOf(types.OBJECT_ATTRIBUTES),
            .RootDirectory = null,
            .ObjectName = &name_us,
            .Attributes = OBJ_CASE_INSENSITIVE,
            .SecurityDescriptor = null,
            .SecurityQualityOfService = null,
        };

        var file_handle: types.HANDLE = undefined;
        var iosb: types.IO_STATUS_BLOCK = undefined;

        const status = engine.NtCreateFile(
            &file_handle,
            FILE_GENERIC_READ,
            @as(types.PVOID, @ptrCast(&attr)),
            @as(types.PVOID, @ptrCast(&iosb)),
            null,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            null,
            0,
        );
        if (status < 0) return null;

    var null_attr = types.OBJECT_ATTRIBUTES{
        .Length = 0,
        .RootDirectory = null,
        .ObjectName = undefined,
        .Attributes = 0,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var zero_size: types.SIZE_T = 0;

    var section_handle: types.HANDLE = undefined;
    const sc_status = engine.NtCreateSection(
        &section_handle,
        SECTION_MAP_READ,
        @as(types.PVOID, @ptrCast(&null_attr)),
        @as(types.PVOID, @ptrCast(&zero_size)),
        PAGE_READONLY,
        SEC_COMMIT,
        file_handle,
    );
        if (sc_status < 0) {
            _ = engine.NtClose(file_handle);
            return null;
        }

    var base_addr: types.PVOID = @as(types.PVOID, @ptrFromInt(@as(usize, 1)));
    var view_size: types.SIZE_T = 0;
    var section_offset: types.LARGE_INTEGER = 0;

    const map_status = engine.NtMapViewOfSection(
        section_handle,
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        &base_addr,
        0,
        0,
        @as(types.PVOID, @ptrCast(&section_offset)),
        &view_size,
        VIEW_SHARE,
        0,
        0,
    );
    if (map_status < 0) {
            _ = engine.NtClose(section_handle);
            _ = engine.NtClose(file_handle);
            return null;
    }

        return MappedFile{
            .base = @as([*]const u8, @ptrCast(base_addr)),
            .size = view_size,
            .file_handle = file_handle,
            .section_handle = section_handle,
        };
    }

    pub fn close(self: *const MappedFile) void {
        _ = engine.NtClose(self.section_handle);
        _ = engine.NtClose(self.file_handle);
    }

    pub fn slice(self: *const MappedFile) []const u8 {
        return self.base[0..self.size];
    }
};
