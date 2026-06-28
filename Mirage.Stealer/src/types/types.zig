const std = @import("std");

pub const PVOID = *anyopaque;
pub const HANDLE = PVOID;
pub const ULONG = u32;
pub const USHORT = u16;
pub const UCHAR = u8;
pub const WCHAR = u16;
pub const PWSTR = [*]WCHAR;
pub const NTSTATUS = i32;
pub const SIZE_T = usize;
pub const DWORD = u32;
pub const WORD = u16;
pub const BYTE = u8;
pub const LONG = i32;
pub const BOOL = i32;
pub const BOOLEAN = u8;

pub const UNICODE_STRING = extern struct {
    Length: USHORT,
    MaximumLength: USHORT,
    Buffer: PWSTR,
};

pub const LIST_ENTRY = extern struct {
    Flink: *LIST_ENTRY,
    Blink: *LIST_ENTRY,
};

pub const LDR_DATA_TABLE_ENTRY = extern struct {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: PVOID,
    EntryPoint: PVOID,
    SizeOfImage: ULONG,
    _padding_sizeofimage: ULONG,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    Reserved5: [3]PVOID,
    u1: extern union {
        CheckSum: ULONG,
        Reserved6: PVOID,
    },
    TimeDateStamp: ULONG,
};

pub const PEB_LDR_DATA = extern struct {
    Length: ULONG,
    Initialized: UCHAR,
    SsHandle: PVOID,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
    EntryInProgress: PVOID,
    ShutdownInProgress: UCHAR,
    ShutdownThreadId: PVOID,
};

pub const PEB = extern struct {
    InheritedAddressSpace: u8,
    ReadImageFileExecOptions: u8,
    BeingDebugged: u8,
    BitField: u8,
    Mutant: PVOID,
    ImageBaseAddress: PVOID,
    Ldr: *PEB_LDR_DATA,
    ProcessParameters: PVOID,
    Reserved4: [3]PVOID,
    AtlThunkSListPtr: PVOID,
    Reserved5: PVOID,
    Reserved6: ULONG,
    Reserved7: PVOID,
    Reserved8: ULONG,
    AtlThunkSListPtr32: ULONG,
    Reserved9: [45]PVOID,
    Reserved10: [96]u8,
    PostProcessInitRoutine: PVOID,
    Reserved11: [128]u8,
    Reserved12: [1]PVOID,
    SessionId: ULONG,
};

pub const IMAGE_DOS_SIGNATURE: WORD = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: DWORD = 0x00004550;

pub const IMAGE_DOS_HEADER = extern struct {
    e_magic: WORD,
    e_cblp: WORD,
    e_cp: WORD,
    e_crlc: WORD,
    e_cparhdr: WORD,
    e_minalloc: WORD,
    e_maxalloc: WORD,
    e_ss: WORD,
    e_sp: WORD,
    e_csum: WORD,
    e_ip: WORD,
    e_cs: WORD,
    e_lfarlc: WORD,
    e_ovno: WORD,
    e_res: [4]WORD,
    e_oemid: WORD,
    e_oeminfo: WORD,
    e_res2: [10]WORD,
    e_lfanew: LONG,
};

pub const IMAGE_FILE_HEADER = extern struct {
    Machine: WORD,
    NumberOfSections: WORD,
    TimeDateStamp: DWORD,
    PointerToSymbolTable: DWORD,
    NumberOfSymbols: DWORD,
    SizeOfOptionalHeader: WORD,
    Characteristics: WORD,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: DWORD,
    Size: DWORD,
};

pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: WORD,
    MajorLinkerVersion: BYTE,
    MinorLinkerVersion: BYTE,
    SizeOfCode: DWORD,
    SizeOfInitializedData: DWORD,
    SizeOfUninitializedData: DWORD,
    AddressOfEntryPoint: DWORD,
    BaseOfCode: DWORD,
    ImageBase: u64,
    SectionAlignment: DWORD,
    FileAlignment: DWORD,
    MajorOperatingSystemVersion: WORD,
    MinorOperatingSystemVersion: WORD,
    MajorImageVersion: WORD,
    MinorImageVersion: WORD,
    MajorSubsystemVersion: WORD,
    MinorSubsystemVersion: WORD,
    Win32VersionValue: DWORD,
    SizeOfImage: DWORD,
    SizeOfHeaders: DWORD,
    CheckSum: DWORD,
    Subsystem: WORD,
    DllCharacteristics: WORD,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: DWORD,
    NumberOfRvaAndSizes: DWORD,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

pub const IMAGE_NT_HEADERS64 = extern struct {
    Signature: DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

pub const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]BYTE,
    Misc: extern union {
        PhysicalAddress: DWORD,
        VirtualSize: DWORD,
    },
    VirtualAddress: DWORD,
    SizeOfRawData: DWORD,
    PointerToRawData: DWORD,
    PointerToRelocations: DWORD,
    PointerToLinenumbers: DWORD,
    NumberOfRelocations: WORD,
    NumberOfLinenumbers: WORD,
    Characteristics: DWORD,
};

pub const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: DWORD,
    TimeDateStamp: DWORD,
    MajorVersion: WORD,
    MinorVersion: WORD,
    Name: DWORD,
    Base: DWORD,
    NumberOfFunctions: DWORD,
    NumberOfNames: DWORD,
    AddressOfFunctions: DWORD,
    AddressOfNames: DWORD,
    AddressOfNameOrdinals: DWORD,
};

pub const PROCESS_BASIC_INFORMATION = extern struct {
    ExitStatus: NTSTATUS,
    PebBaseAddress: *PEB,
    AffinityMask: usize,
    BasePriority: LONG,
    UniqueProcessId: usize,
    InheritedFromUniqueProcessId: usize,
};

pub const IO_STATUS_BLOCK = extern struct {
    anonymous: extern union {
        Status: NTSTATUS,
        Pointer: PVOID,
    },
    Information: ULONG_PTR,
};

pub const ULONG_PTR = usize;

pub const OBJECT_ATTRIBUTES = extern struct {
    Length: ULONG,
    RootDirectory: ?HANDLE,
    ObjectName: *UNICODE_STRING,
    Attributes: ULONG,
    SecurityDescriptor: ?*const anyopaque,
    SecurityQualityOfService: ?*const anyopaque,
};

pub const OBJ_CASE_INSENSITIVE: ULONG = 0x00000040;

pub const FILE_GENERIC_READ: ULONG = 0x80000000;
pub const FILE_GENERIC_WRITE: ULONG = 0x40000000;
pub const FILE_SHARE_READ: ULONG = 0x00000001;
pub const FILE_SHARE_WRITE: ULONG = 0x00000002;
pub const FILE_OPEN: ULONG = 0x00000001;
pub const FILE_CREATE: ULONG = 0x00000003;
pub const FILE_NON_DIRECTORY_FILE: ULONG = 0x00000040;
pub const FILE_SYNCHRONOUS_IO_NONALERT: ULONG = 0x00000020;

pub const MEM_COMMIT: ULONG = 0x00001000;
pub const MEM_RESERVE: ULONG = 0x00002000;
pub const MEM_RELEASE: ULONG = 0x00008000;
pub const MEM_FREE: ULONG = 0x00010000;

pub const PAGE_NOACCESS: ULONG = 0x01;
pub const PAGE_READONLY: ULONG = 0x02;
pub const PAGE_READWRITE: ULONG = 0x04;
pub const PAGE_WRITECOPY: ULONG = 0x08;
pub const PAGE_EXECUTE: ULONG = 0x10;
pub const PAGE_EXECUTE_READ: ULONG = 0x20;
pub const PAGE_EXECUTE_READWRITE: ULONG = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: ULONG = 0x80;

pub const LARGE_INTEGER = i64;

pub const SYSTEM_INFORMATION_CLASS = enum(ULONG) {
    SystemBasicInformation = 0,
    SystemCpuInformation = 39,
    _,
};

pub const SYSTEM_BASIC_INFORMATION = extern struct {
    Reserved: ULONG,
    TimerResolution: ULONG,
    PageSize: ULONG,
    NumberOfPhysicalPages: ULONG,
    LowestPhysicalPageNumber: ULONG,
    HighestPhysicalPageNumber: ULONG,
    AllocationGranularity: ULONG,
    padding: ULONG,
    MinimumUserModeAddress: ULONG_PTR,
    MaximumUserModeAddress: ULONG_PTR,
    ActiveProcessorsAffinityMask: ULONG_PTR,
    NumberOfProcessors: UCHAR,
};

pub const KEY_QUERY_VALUE: ULONG = 0x0001;
pub const KEY_ENUMERATE_SUB_KEYS: ULONG = 0x0008;
pub const KEY_READ: ULONG = 0x20019;

pub const KEY_VALUE_INFORMATION_CLASS = enum(ULONG) {
    KeyValuePartialInformation = 0,
    _,
};

pub const KEY_VALUE_PARTIAL_INFORMATION = extern struct {
    TitleIndex: ULONG,
    Type: ULONG,
    DataLength: ULONG,
    Data: [1]UCHAR,
};

pub const EVENT_TYPE = enum(ULONG) {
    NotificationEvent = 0,
    SynchronizationEvent = 1,
};

pub const PROCESSINFOCLASS = enum(ULONG) {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessBreakOnTermination = 29,
    ProcessDebugObjectHandle = 30,
    _,
};

pub const CONTEXT_FLAGS: ULONG = 0x100010; // CONTEXT_DEBUG_REGISTERS | CONTEXT_INTEGER

pub const CLIENT_ID = extern struct {
    UniqueProcess: HANDLE,
    UniqueThread: HANDLE,
};

pub const SECTION_ACCESS_MASK = struct {
    pub const SECTION_QUERY: ULONG = 0x0001;
    pub const SECTION_MAP_WRITE: ULONG = 0x0002;
    pub const SECTION_MAP_READ: ULONG = 0x0004;
    pub const SECTION_MAP_EXECUTE: ULONG = 0x0008;
    pub const SECTION_EXTEND_SIZE: ULONG = 0x0010;
    pub const SECTION_ALL_ACCESS: ULONG = 0x000F001F;
};

pub const THREAD_CREATION_FLAGS = struct {
    pub const THREAD_CREATE_RUN_IMMEDIATELY: ULONG = 0x00000000;
    pub const THREAD_CREATE_SUSPENDED: ULONG = 0x00000001;
    pub const THREAD_CREATE_HIDE_FROM_DEBUG: ULONG = 0x00000004;
};

pub const PROCESS_ACCESS_MASK = struct {
    pub const PROCESS_TERMINATE: ULONG = 0x00000001;
    pub const PROCESS_CREATE_THREAD: ULONG = 0x00000002;
    pub const PROCESS_SET_SESSIONID: ULONG = 0x00000004;
    pub const PROCESS_VM_OPERATION: ULONG = 0x00000008;
    pub const PROCESS_VM_READ: ULONG = 0x00000010;
    pub const PROCESS_VM_WRITE: ULONG = 0x00000020;
    pub const PROCESS_DUP_HANDLE: ULONG = 0x00000040;
    pub const PROCESS_CREATE_PROCESS: ULONG = 0x00000080;
    pub const PROCESS_SET_QUOTA: ULONG = 0x00000100;
    pub const PROCESS_SET_INFORMATION: ULONG = 0x00000200;
    pub const PROCESS_QUERY_INFORMATION: ULONG = 0x00000400;
    pub const PROCESS_SUSPEND_RESUME: ULONG = 0x00000800;
    pub const PROCESS_QUERY_LIMITED_INFORMATION: ULONG = 0x00001000;
    pub const PROCESS_SET_LIMITED_INFORMATION: ULONG = 0x00002000;
    pub const PROCESS_ALL_ACCESS: ULONG = 0x001F0FFF;
};

pub const FILE_DISPOSITION_INFORMATION = extern struct {
    DeleteFile: BOOLEAN,
};

pub const SYSTEM_PROCESS_INFORMATION = extern struct {
    NextEntryOffset: ULONG,
    NumberOfThreads: ULONG,
    Reserved1: [48]u8,
    Reserved2: [3]PVOID,
    UniqueProcessId: HANDLE,
    Reserved3: PVOID,
    Reserved4: [3]ULONG_PTR,
    ImageName: UNICODE_STRING,
    BasePriority: LONG,
    Reserved5: PVOID,
    Reserved6: ULONG,
    Reserved7: [4]PVOID,
};

pub const FILE_INFORMATION_CLASS = enum(ULONG) {
    FileDispositionInformation = 13,
    _,
};

pub const SEMAPHORE_ACCESS_MASK = struct {
    pub const SEMAPHORE_ALL_ACCESS: ULONG = 0x001F0003;
};

pub const CONTEXT = extern struct {
    P1Home: u64,
    P2Home: u64,
    P3Home: u64,
    P4Home: u64,
    P5Home: u64,
    P6Home: u64,
    ContextFlags: ULONG,
    MxCsr: ULONG,
    SegCs: u16,
    SegDs: u16,
    SegEs: u16,
    SegFs: u16,
    SegGs: u16,
    SegSs: u16,
    EFlags: u32,
    Dr0: u64,
    Dr1: u64,
    Dr2: u64,
    Dr3: u64,
    Dr6: u64,
    Dr7: u64,
    Rax: u64,
    Rcx: u64,
    Rdx: u64,
    Rbx: u64,
    Rsp: u64,
    Rbp: u64,
    Rsi: u64,
    Rdi: u64,
    R8: u64,
    R9: u64,
    R10: u64,
    R11: u64,
    R12: u64,
    R13: u64,
    R14: u64,
    R15: u64,
    Rip: u64,
};

test "structure sizes" {
    try std.testing.expect(@sizeOf(PEB) > 0);
    try std.testing.expect(@sizeOf(CONTEXT) > 0);
}
