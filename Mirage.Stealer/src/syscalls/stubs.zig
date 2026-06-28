comptime {
    asm (
        \\.global NtAllocateVirtualMemory_stub
        \\NtAllocateVirtualMemory_stub:
        \\    mov ssn_NtAllocateVirtualMemory(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtProtectVirtualMemory_stub
        \\NtProtectVirtualMemory_stub:
        \\    mov ssn_NtProtectVirtualMemory(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    xchgq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    pushq %r11
        \\    ret

        \\.global NtFreeVirtualMemory_stub
        \\NtFreeVirtualMemory_stub:
        \\    mov ssn_NtFreeVirtualMemory(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    pushq %rcx
        \\    popq %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtWriteVirtualMemory_stub
        \\NtWriteVirtualMemory_stub:
        \\    mov ssn_NtWriteVirtualMemory(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    pushq %r11
        \\    ret

        \\.global NtClose_stub
        \\NtClose_stub:
        \\    mov ssn_NtClose(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    xchgq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtOpenFile_stub
        \\NtOpenFile_stub:
        \\    mov ssn_NtOpenFile(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    pushq %rcx
        \\    popq %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    pushq %r11
        \\    ret

        \\.global NtReadVirtualMemory_stub
        \\NtReadVirtualMemory_stub:
        \\    mov ssn_NtReadVirtualMemory(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtCreateSection_stub
        \\NtCreateSection_stub:
        \\    mov ssn_NtCreateSection(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    xchgq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    pushq %r11
        \\    ret

        \\.global NtMapViewOfSection_stub
        \\NtMapViewOfSection_stub:
        \\    mov ssn_NtMapViewOfSection(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    pushq %rcx
        \\    popq %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtQueryInformationProcess_stub
        \\NtQueryInformationProcess_stub:
        \\    mov ssn_NtQueryInformationProcess(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    pushq %r11
        \\    ret

        \\.global NtCreateFile_stub
        \\NtCreateFile_stub:
        \\    mov ssn_NtCreateFile(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    xchgq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtWriteFile_stub
        \\NtWriteFile_stub:
        \\    mov ssn_NtWriteFile(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    pushq %rcx
        \\    popq %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    pushq %r11
        \\    ret

        \\.global NtQuerySystemInformation_stub
        \\NtQuerySystemInformation_stub:
        \\    mov ssn_NtQuerySystemInformation(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtDelayExecution_stub
        \\NtDelayExecution_stub:
        \\    mov ssn_NtDelayExecution(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtCreateEvent_stub
        \\NtCreateEvent_stub:
        \\    mov ssn_NtCreateEvent(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtWaitForSingleObject_stub
        \\NtWaitForSingleObject_stub:
        \\    mov ssn_NtWaitForSingleObject(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtOpenKey_stub
        \\NtOpenKey_stub:
        \\    mov ssn_NtOpenKey(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtQueryValueKey_stub
        \\NtQueryValueKey_stub:
        \\    mov ssn_NtQueryValueKey(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtSetInformationProcess_stub
        \\NtSetInformationProcess_stub:
        \\    mov ssn_NtSetInformationProcess(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtUserGetSystemMetrics_stub
        \\NtUserGetSystemMetrics_stub:
        \\    mov ssn_NtUserGetSystemMetrics(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtGetContextThread_stub
        \\NtGetContextThread_stub:
        \\    mov ssn_NtGetContextThread(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    xchgq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtSetContextThread_stub
        \\NtSetContextThread_stub:
        \\    mov ssn_NtSetContextThread(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    xchgq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtOpenSection_stub
        \\NtOpenSection_stub:
        \\    mov ssn_NtOpenSection(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtUnmapViewOfSection_stub
        \\NtUnmapViewOfSection_stub:
        \\    mov ssn_NtUnmapViewOfSection(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtCreateThreadEx_stub
        \\NtCreateThreadEx_stub:
        \\    mov ssn_NtCreateThreadEx(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtOpenProcess_stub
        \\NtOpenProcess_stub:
        \\    mov ssn_NtOpenProcess(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtResumeThread_stub
        \\NtResumeThread_stub:
        \\    mov ssn_NtResumeThread(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtSuspendThread_stub
        \\NtSuspendThread_stub:
        \\    mov ssn_NtSuspendThread(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtDeleteFile_stub
        \\NtDeleteFile_stub:
        \\    mov ssn_NtDeleteFile(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11

        \\.global NtSetInformationFile_stub
        \\NtSetInformationFile_stub:
        \\    mov ssn_NtSetInformationFile(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    jmpq *%r11
    );
}
