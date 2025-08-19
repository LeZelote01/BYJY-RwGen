section .text
    global CheckDebuggerAdvanced

CheckDebuggerAdvanced:
    push ebp
    mov ebp, esp
    
    ; 1. Vérification standard
    call CheckDebuggerStandard
    
    ; 2. Vérification PEB
    mov eax, [fs:0x30]     ; PEB
    mov al, [eax+0x02]     ; BeingDebugged
    test al, al
    jnz DebuggerDetected
    
    ; 3. Vérification NtGlobalFlag
    mov eax, [eax+0x68]    ; NtGlobalFlag
    and eax, 0x70          ; FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    cmp eax, 0x70
    je DebuggerDetected
    
    ; 4. Vérification Heap Flags
    mov eax, [fs:0x30]     ; PEB
    mov eax, [eax+0x18]    ; ProcessHeap
    mov eax, [eax+0x10]    ; Flags
    test eax, 0x100        ; HEAP_GROWABLE
    jz DebuggerDetected
    test eax, 0x40000000   ; HEAP_TAIL_CHECKING_ENABLED
    jnz DebuggerDetected
    
    ; 5. Vérification du temps d'exécution
    rdtsc
    push edx
    push eax
    xor eax, eax
    cpuid                   ; Serialize
    rdtsc
    sub eax, [esp]
    sbb edx, [esp+4]
    add esp, 8
    cmp eax, 0x100000
    ja DebuggerDetected
    
    ; 6. Vérification INT 2D
    push offset NoDebugger
    push dword [fs:0]
    mov [fs:0], esp
    int 2dh
    nop
    add esp, 8
    jmp DebuggerDetected
    
NoDebugger:
    mov eax, [esp]          ; Retour d'exception
    add esp, 4
    mov esp, ebp
    pop ebp
    xor eax, eax
    ret

DebuggerDetected:
    mov esp, ebp
    pop ebp
    mov eax, 1
    ret

CheckDebuggerStandard:
    mov eax, 1
    cpuid
    bt ecx, 31
    jc DebuggerDetected
    ret