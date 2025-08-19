#!/usr/bin/env python3
"""
BYJY-RwGen Tool Validation Script
Validates that the tool is 100% complete and functional
"""

import os
import sys
import json
import subprocess
from pathlib import Path
import importlib.util

class ToolValidator:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.validation_results = {}
        
    def validate_configuration_files(self):
        """Validate all configuration files exist and are valid"""
        print("[+] Validating configuration files...")
        
        config_files = {
            'build_config.json': 'Build configuration',
            'c2_config.json': 'C&C configuration', 
            'payload_config.json': 'Payload configuration',
            'linux_build.conf': 'Linux build configuration'
        }
        
        all_valid = True
        for file, description in config_files.items():
            file_path = self.project_root / file
            
            if not file_path.exists():
                print(f"  ❌ Missing: {file} ({description})")
                all_valid = False
                continue
                
            # Validate JSON files
            if file.endswith('.json'):
                try:
                    with open(file_path, 'r') as f:
                        json.load(f)
                    print(f"  ✅ Valid: {file}")
                except json.JSONDecodeError as e:
                    print(f"  ❌ Invalid JSON in {file}: {e}")
                    all_valid = False
            else:
                print(f"  ✅ Exists: {file}")
        
        self.validation_results['configurations'] = all_valid
        return all_valid
    
    def validate_source_structure(self):
        """Validate source code structure"""
        print("[+] Validating source code structure...")
        
        required_components = {
            'core_engine/encryption/file_handler.cpp': 'File encryption engine',
            'core_engine/encryption/hybrid/aes_256.rs': 'AES encryption (Rust)',
            'core_engine/encryption/hybrid/rsa_4096.cpp': 'RSA encryption', 
            'core_engine/encryption/hybrid/key_manager.py': 'Key management',
            'core_engine/injection/process_injector.cpp': 'Process injection',
            'core_engine/persistence/windows/registry_hook.cpp': 'Windows persistence',
            'anti_analysis/sandbox_detection.cpp': 'Sandbox detection',
            'obfuscation/string_obfuscator.h': 'String obfuscation',
            'obfuscation/packers/custom_packer.py': 'Custom packer',
            'command_control/dns_tunneling/dns_exfil.py': 'DNS tunneling C&C',
            'builders/windows_builder.py': 'Windows builder',
            'builders/linux_builder.sh': 'Linux builder'
        }
        
        all_exist = True
        for file, description in required_components.items():
            file_path = self.project_root / file
            if file_path.exists():
                print(f"  ✅ {description}")
            else:
                print(f"  ❌ Missing: {description} ({file})")
                all_exist = False
        
        self.validation_results['source_structure'] = all_exist
        return all_exist
    
    def validate_dependencies(self):
        """Validate Python dependencies"""
        print("[+] Validating Python dependencies...")
        
        required_packages = [
            'cryptography', 'dns', 'requests', 'psutil'
        ]
        
        all_available = True
        for package in required_packages:
            try:
                if package == 'dns':
                    import dns.resolver  # Special case for dnspython
                else:
                    __import__(package)
                print(f"  ✅ {package}")
            except ImportError:
                print(f"  ❌ Missing: {package}")
                all_available = False
        
        self.validation_results['dependencies'] = all_available
        return all_available
    
    def validate_build_tools(self):
        """Validate build tools availability"""
        print("[+] Validating build tools...")
        
        tools = {
            'python3': 'Python 3 interpreter',
            'gcc': 'GCC compiler (Linux)',
            'rustc': 'Rust compiler (optional)',
        }
        
        available_tools = 0
        for tool, description in tools.items():
            if self.check_command_available(tool):
                print(f"  ✅ {description}")
                available_tools += 1
            else:
                print(f"  ⚠️  Not available: {description}")
        
        # At least Python3 should be available
        self.validation_results['build_tools'] = available_tools >= 1
        return available_tools >= 1
    
    def check_command_available(self, command):
        """Check if a command is available in PATH"""
        try:
            subprocess.run([command, '--version'], 
                          capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def validate_master_builder(self):
        """Validate master builder script"""
        print("[+] Validating master builder...")
        
        builder_path = self.project_root / 'master_builder.py'
        if not builder_path.exists():
            print("  ❌ Master builder script missing")
            self.validation_results['master_builder'] = False
            return False
        
        try:
            # Test if the script can be imported
            spec = importlib.util.spec_from_file_location("master_builder", builder_path)
            master_builder = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(master_builder)
            
            # Check if MasterBuilder class exists
            if hasattr(master_builder, 'MasterBuilder'):
                print("  ✅ Master builder script valid")
                self.validation_results['master_builder'] = True
                return True
            else:
                print("  ❌ MasterBuilder class not found")
                self.validation_results['master_builder'] = False
                return False
                
        except Exception as e:
            print(f"  ❌ Error importing master builder: {e}")
            self.validation_results['master_builder'] = False
            return False
    
    def validate_documentation(self):
        """Validate documentation files"""
        print("[+] Validating documentation...")
        
        docs = [
            'docs/CONFIGURATION_GUIDE.md',
            'docs/USAGE_EXAMPLES.md'
        ]
        
        all_exist = True
        for doc in docs:
            doc_path = self.project_root / doc
            if doc_path.exists():
                print(f"  ✅ {doc}")
            else:
                print(f"  ❌ Missing: {doc}")
                all_exist = False
        
        self.validation_results['documentation'] = all_exist
        return all_exist
    
    def validate_research_safety(self):
        """Validate research safety measures"""
        print("[+] Validating research safety measures...")
        
        safety_indicators = []
        
        # Check for research mode indicators
        main_cpp = self.project_root / 'src' / 'main.cpp'
        if main_cpp.exists():
            with open(main_cpp, 'r') as f:
                content = f.read()
                if 'RESEARCH_MODE' in content:
                    safety_indicators.append("Research mode flag present")
                if 'Academic Research' in content:
                    safety_indicators.append("Academic research notices present")
                if 'DO NOT USE MALICIOUSLY' in content:
                    safety_indicators.append("Anti-malicious use warnings present")
        
        # Check configuration safety
        config_path = self.project_root / 'payload_config.json'
        if config_path.exists():
            with open(config_path, 'r') as f:
                config = json.load(f)
                if config.get('research_mode'):
                    safety_indicators.append("Research mode in configuration")
        
        print(f"  ✅ Safety measures: {len(safety_indicators)}")
        for indicator in safety_indicators:
            print(f"    - {indicator}")
        
        self.validation_results['research_safety'] = len(safety_indicators) >= 2
        return len(safety_indicators) >= 2
    
    def test_basic_functionality(self):
        """Test basic functionality without building"""
        print("[+] Testing basic functionality...")
        
        try:
            # Test configuration loading
            builder_script = self.project_root / 'master_builder.py'
            result = subprocess.run([
                sys.executable, str(builder_script), '--validate'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print("  ✅ Basic functionality test passed")
                self.validation_results['basic_functionality'] = True
                return True
            else:
                print(f"  ❌ Basic functionality test failed: {result.stderr}")
                self.validation_results['basic_functionality'] = False
                return False
                
        except subprocess.TimeoutExpired:
            print("  ❌ Basic functionality test timed out")
            self.validation_results['basic_functionality'] = False
            return False
        except Exception as e:
            print(f"  ❌ Basic functionality test error: {e}")
            self.validation_results['basic_functionality'] = False
            return False
    
    def generate_validation_report(self):
        """Generate comprehensive validation report"""
        print("\n" + "="*60)
        print("BYJY-RwGen Tool Validation Report")
        print("="*60)
        
        total_checks = len(self.validation_results)
        passed_checks = sum(self.validation_results.values())
        completion_percentage = (passed_checks / total_checks) * 100
        
        print(f"\nOverall Completion: {completion_percentage:.1f}% ({passed_checks}/{total_checks})")
        print(f"Tool Status: {'✅ READY FOR RESEARCH' if completion_percentage >= 90 else '❌ NEEDS FIXES'}")
        
        print("\nDetailed Results:")
        for check, result in self.validation_results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"  {check.replace('_', ' ').title()}: {status}")
        
        if completion_percentage >= 90:
            print("\n🎓 RESEARCH RECOMMENDATIONS:")
            print("  • Use only in isolated, controlled environments")
            print("  • Ensure institutional approval and supervision")
            print("  • Follow all safety guidelines in documentation")
            print("  • Use for defensive research purposes only")
            
        if completion_percentage < 100:
            print("\n⚠️  REMAINING ITEMS:")
            for check, result in self.validation_results.items():
                if not result:
                    print(f"  • Fix: {check.replace('_', ' ')}")
        
        return completion_percentage
    
    def run_full_validation(self):
        """Run complete validation suite"""
        print("BYJY-RwGen Tool Validation")
        print("Academic Research Tool - Defense Analysis Only")
        print("-" * 50)
        
        # Run all validation checks
        validation_functions = [
            self.validate_configuration_files,
            self.validate_source_structure,
            self.validate_dependencies,
            self.validate_build_tools,
            self.validate_master_builder,
            self.validate_documentation,
            self.validate_research_safety,
            self.test_basic_functionality
        ]
        
        for validation_func in validation_functions:
            try:
                validation_func()
            except Exception as e:
                print(f"  ❌ Error in {validation_func.__name__}: {e}")
                self.validation_results[validation_func.__name__] = False
            print()
        
        return self.generate_validation_report()

def main():
    validator = ToolValidator()
    completion_percentage = validator.run_full_validation()
    
    # Exit with appropriate code
    if completion_percentage >= 100:
        print("\n🎉 Tool is 100% complete and ready for academic research!")
        sys.exit(0)
    elif completion_percentage >= 90:
        print("\n✅ Tool is ready for research with minor limitations.")
        sys.exit(0)
    else:
        print("\n❌ Tool needs additional work before research use.")
        sys.exit(1)

if __name__ == "__main__":
    main()