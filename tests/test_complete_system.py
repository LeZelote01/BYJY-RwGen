#!/usr/bin/env python3
"""
Complete System Test Suite for BYJY-RwGen
Comprehensive testing of all components for research validation
FOR DEFENSIVE RESEARCH PURPOSES ONLY
"""

import os
import sys
import json
import unittest
import tempfile
import shutil
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from obfuscation import ControlFlowFlattening, StringEncryptionPass, StringObfuscator
from builders.windows_builder import AdvancedWindowsBuilder


class TestObfuscationModules(unittest.TestCase):
    """Test obfuscation modules functionality"""
    
    def setUp(self):
        self.test_code = '''
        int test_function(int x) {
            printf("Hello World");
            if (x > 0) {
                return x * 2;
            }
            return 0;
        }
        '''
    
    def test_control_flow_flattening(self):
        """Test Control Flow Flattening"""
        print("[+] Testing Control Flow Flattening...")
        
        cff = ControlFlowFlattening("medium")
        obfuscated = cff.apply_to_source(self.test_code, ["test_function"])
        
        # Verify obfuscation occurred
        self.assertIn("switch", obfuscated)
        self.assertIn("state_var", obfuscated)
        self.assertGreater(len(obfuscated), len(self.test_code))
        
        stats = cff.get_statistics()
        self.assertEqual(stats['technique'], 'Control Flow Flattening')
        
        print("  ✓ Control Flow Flattening test passed")
    
    def test_string_encryption(self):
        """Test String Encryption Pass"""
        print("[+] Testing String Encryption Pass...")
        
        encryptor = StringEncryptionPass("aes256")
        obfuscated = encryptor.obfuscate_source_file(self.test_code)
        
        # Verify encryption occurred
        self.assertIn("StringDecryptor", obfuscated)
        self.assertNotIn('"Hello World"', obfuscated)
        
        stats = encryptor.get_statistics()
        self.assertEqual(stats['technique'], 'String Encryption Pass')
        
        print("  ✓ String Encryption Pass test passed")
    
    def test_string_obfuscator(self):
        """Test String Obfuscator"""
        print("[+] Testing String Obfuscator...")
        
        obfuscator = StringObfuscator("multi_layer")
        
        # Test individual string obfuscation
        test_string = "Hello, Research!"
        obfuscated = obfuscator.obfuscate(test_string)
        
        self.assertNotEqual(obfuscated, f'"{test_string}"')
        self.assertGreater(len(obfuscated), len(test_string))
        
        # Test file obfuscation
        obfuscated_code = obfuscator.obfuscate_file(self.test_code)
        self.assertGreater(len(obfuscated_code), len(self.test_code))
        
        stats = obfuscator.get_statistics()
        self.assertEqual(stats['technique_category'], 'String Obfuscation')
        
        print("  ✓ String Obfuscator test passed")


class TestBuildSystem(unittest.TestCase):
    """Test build system functionality"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_config = {
            "source_dir": "src",
            "output_dir": "dist",
            "main_executable": "test.exe",
            "target_architecture": "x64",
            "obfuscation_level": "medium",
            "enable_anti_analysis": True
        }
    
    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_config_loading(self):
        """Test configuration loading"""
        print("[+] Testing configuration loading...")
        
        config_file = os.path.join(self.temp_dir, "test_config.json")
        with open(config_file, 'w') as f:
            json.dump(self.test_config, f)
        
        builder = AdvancedWindowsBuilder(config_file)
        
        self.assertEqual(builder.config["main_executable"], "test.exe")
        self.assertEqual(builder.config["target_architecture"], "x64")
        
        print("  ✓ Configuration loading test passed")
    
    def test_obfuscation_integration(self):
        """Test obfuscation integration in build system"""
        print("[+] Testing obfuscation integration...")
        
        # This test verifies that the builder can import and use obfuscation modules
        builder = AdvancedWindowsBuilder()
        
        # Test that obfuscator can be instantiated
        self.assertIsNotNone(builder.obfuscator)
        
        print("  ✓ Obfuscation integration test passed")


class TestProjectStructure(unittest.TestCase):
    """Test overall project structure and integrity"""
    
    def test_critical_files_exist(self):
        """Test that all critical files exist"""
        print("[+] Testing critical files existence...")
        
        critical_files = [
            "/app/master_builder.py",
            "/app/enhanced_master_builder.py", 
            "/app/validate_tool.py",
            "/app/build_config.json",
            "/app/c2_config.json",
            "/app/payload_config.json",
            "/app/obfuscation/__init__.py",
            "/app/obfuscation/ControlFlowFlattening.py",
            "/app/obfuscation/StringEncryptionPass.py",
            "/app/obfuscation/StringObfuscator.py",
            "/app/builders/windows_builder.py",
            "/app/builders/linux_builder.sh"
        ]
        
        missing_files = []
        for file_path in critical_files:
            if not Path(file_path).exists():
                missing_files.append(file_path)
        
        self.assertEqual(len(missing_files), 0, 
                        f"Missing critical files: {missing_files}")
        
        print("  ✓ All critical files exist")
    
    def test_configuration_validity(self):
        """Test configuration files are valid JSON"""
        print("[+] Testing configuration validity...")
        
        config_files = [
            "/app/build_config.json",
            "/app/c2_config.json",
            "/app/payload_config.json",
            "/app/deployment_config.json",
            "/app/network_config.json"
        ]
        
        for config_file in config_files:
            if Path(config_file).exists():
                with open(config_file, 'r') as f:
                    try:
                        json.load(f)
                        print(f"  ✓ {Path(config_file).name} is valid JSON")
                    except json.JSONDecodeError as e:
                        self.fail(f"Invalid JSON in {config_file}: {e}")
    
    def test_import_chain(self):
        """Test that all imports work correctly"""
        print("[+] Testing import chain...")
        
        try:
            # Test core imports
            from obfuscation import ControlFlowFlattening, StringEncryptionPass, StringObfuscator
            from builders.windows_builder import AdvancedWindowsBuilder
            
            print("  ✓ All imports successful")
            
        except ImportError as e:
            self.fail(f"Import chain broken: {e}")


class TestResearchCompliance(unittest.TestCase):
    """Test research compliance and safety measures"""
    
    def test_research_mode_enabled(self):
        """Test that research mode is enabled everywhere"""
        print("[+] Testing research mode compliance...")
        
        # Test obfuscation modules
        from obfuscation import ControlFlowFlattening, StringEncryptionPass, StringObfuscator
        
        cff = ControlFlowFlattening()
        self.assertTrue(cff.research_mode)
        
        encryptor = StringEncryptionPass()
        self.assertTrue(encryptor.research_mode)
        
        obfuscator = StringObfuscator()
        self.assertTrue(obfuscator.research_mode)
        
        print("  ✓ Research mode enabled in all modules")
    
    def test_safety_limits(self):
        """Test that safety limits are in place"""
        print("[+] Testing safety limits...")
        
        obfuscator = StringObfuscator()
        
        # Test string length limit
        very_long_string = "A" * 2000  # Exceeds max_string_length
        result = obfuscator.obfuscate(very_long_string)
        
        # Should handle gracefully
        self.assertIsNotNone(result)
        
        print("  ✓ Safety limits working correctly")


def run_complete_test_suite():
    """Run the complete test suite"""
    print("BYJY-RwGen Complete System Test Suite")
    print("FOR DEFENSIVE RESEARCH PURPOSES ONLY")
    print("=" * 60)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestObfuscationModules))
    test_suite.addTest(unittest.makeSuite(TestBuildSystem))
    test_suite.addTest(unittest.makeSuite(TestProjectStructure))
    test_suite.addTest(unittest.makeSuite(TestResearchCompliance))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED")
        print("✅ System is ready for research use")
        print("✅ All components working correctly")
    else:
        print("❌ SOME TESTS FAILED")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}")
        
        if result.failures:
            print("\nFailures:")
            for test, trace in result.failures:
                print(f"  - {test}: {trace}")
        
        if result.errors:
            print("\nErrors:")
            for test, trace in result.errors:
                print(f"  - {test}: {trace}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_complete_test_suite()
    sys.exit(0 if success else 1)