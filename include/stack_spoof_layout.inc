; stack_spoof_layout.inc — NASM version of include/stack_spoof_layout.h
; Keep byte-for-byte consistent with the .h (test_stack_spoof_offsets.c enforces).

%define SSL_ARG3_OFF    0x28
%define SSL_ARG4_OFF    0x30
%define SSL_ARG5_OFF    0x38
%define SSL_ARG6_OFF    0x40
%define SSL_ARG7_OFF    0x48
%define SSL_ARG8_OFF    0x50
%define SSL_ARG9_OFF    0x58
%define SSL_ARG10_OFF   0x60
%define SSL_ARG11_OFF   0x68

%define SSL_CHAIN_SIZE     0x28
%define SSL_CALLEE_WINDOW  0x28
%define SSL_FRAME_SIZE     0x50

%define SSL_NV_COUNT       8
%define SSL_NV_SAVE_BASE   0x68
%define SSL_NV_SAVE_SIZE   0x40

%define SSL_STASH_COUNT    8
%define SSL_STASH_BASE     0xe8
%define SSL_STASH_SIZE     0x40
