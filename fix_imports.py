#!/usr/bin/env python3
"""
Import Fixer Script for BYJY-RwGen
Fixes missing imports and dependencies in the project
FOR DEFENSIVE RESEARCH PURPOSES ONLY
"""

import os
import sys
import subprocess
from pathlib import Path


def fix_python_imports():
    """Fix Python import issues"""
    print("[+] Fixing Python imports...")
    
    # Install missing Python packages
    required_packages = [
        'pycryptodome',  # For Crypto module
        'pefile',        # For PE file manipulation
        'lief',         # For binary analysis
        'psutil',       # For system monitoring
        'dnspython',    # For DNS operations
        'requests',     # For HTTP operations
        'pandas',       # For data analysis (optional)
        'matplotlib',   # For visualization (optional)
        'seaborn'       # For visualization (optional)
    ]
    
    for package in required_packages:
        try:
            __import__(package if package != 'dnspython' else 'dns')
            print(f"  ✓ {package} already installed")
        except ImportError:
            print(f"  Installing {package}...")
            subprocess.run([sys.executable, '-m', 'pip', 'install', package], 
                         capture_output=True, text=True)


def create_missing_init_files():
    """Create missing __init__.py files"""
    print("[+] Creating missing __init__.py files...")
    
    init_locations = [
        '/app/obfuscation',
        '/app/core_engine',
        '/app/core_engine/encryption',
        '/app/core_engine/injection',
        '/app/core_engine/persistence',
        '/app/builders',
        '/app/anti_analysis'
    ]
    
    for location in init_locations:
        init_file = Path(location) / '__init__.py'
        if not init_file.exists():
            init_file.touch()
            print(f"  ✓ Created {init_file}")


def fix_c_cpp_includes():
    """Fix C/C++ include issues"""
    print("[+] Checking C/C++ includes...")
    
    # Check if source files can find their dependencies
    cpp_files = [
        '/app/core_engine/encryption/file_handler.cpp',
        '/app/anti_analysis/sandbox_detection.cpp',
        '/app/core_engine/persistence/windows/registry_hook.cpp'
    ]
    
    for cpp_file in cpp_files:
        if Path(cpp_file).exists():
            print(f"  ✓ {Path(cpp_file).name} found")
        else:
            print(f"  ⚠ {Path(cpp_file).name} missing")


def validate_project_structure():
    """Validate the overall project structure"""
    print("[+] Validating project structure...")
    
    critical_files = [
        '/app/master_builder.py',
        '/app/enhanced_master_builder.py',
        '/app/validate_tool.py',
        '/app/build_config.json',
        '/app/c2_config.json',
        '/app/payload_config.json',
        '/app/obfuscation/__init__.py',
        '/app/obfuscation/ControlFlowFlattening.py',
        '/app/obfuscation/StringEncryptionPass.py',
        '/app/obfuscation/StringObfuscator.py'
    ]
    
    missing_files = []
    for file_path in critical_files:
        if Path(file_path).exists():
            print(f"  ✓ {Path(file_path).name}")
        else:
            missing_files.append(file_path)
            print(f"  ❌ {Path(file_path).name} missing")
    
    return len(missing_files) == 0


def test_imports():
    """Test if all imports work correctly"""
    print("[+] Testing imports...")
    
    try:
        # Test obfuscation module
        sys.path.insert(0, '/app')
        from obfuscation import ControlFlowFlattening, StringEncryptionPass, StringObfuscator
        print("  ✓ Obfuscation modules import successfully")
        
        # Test other critical imports
        from builders.windows_builder import AdvancedWindowsBuilder
        print("  ✓ Windows builder imports successfully")
        
    except ImportError as e:
        print(f"  ❌ Import error: {e}")
        return False
    
    return True


def main():
    """Main import fixing function"""
    print("BYJY-RwGen Import Fixer")
    print("FOR DEFENSIVE RESEARCH PURPOSES ONLY")
    print("=" * 50)
    
    # Fix Python imports
    fix_python_imports()
    
    # Create missing __init__.py files
    create_missing_init_files()
    
    # Check C++ includes
    fix_c_cpp_includes()
    
    # Validate structure
    structure_valid = validate_project_structure()
    
    # Test imports
    imports_working = test_imports()
    
    print("\n" + "=" * 50)
    print("IMPORT FIX SUMMARY")
    print("=" * 50)
    
    if structure_valid and imports_working:
        print("✅ All imports and dependencies are now fixed!")
        print("✅ Project structure is valid")
        print("✅ Ready for research use")
    else:
        print("⚠️  Some issues remain:")
        if not structure_valid:
            print("  - Project structure needs attention")
        if not imports_working:
            print("  - Import issues still exist")
    
    print("\nNext steps:")
    print("1. Run: python3 validate_tool.py")
    print("2. Run: python3 master_builder.py --validate")
    print("3. Test build: python3 master_builder.py --build linux")


if __name__ == "__main__":
    main()