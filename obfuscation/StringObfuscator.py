#!/usr/bin/env python3
"""
String Obfuscator Implementation
Advanced string obfuscation techniques for cybersecurity research
FOR DEFENSIVE RESEARCH PURPOSES ONLY
"""

import re
import os
import base64
import random
import string
import hashlib
from typing import List, Dict, Tuple, Optional


class StringObfuscator:
    """
    Advanced String Obfuscator with multiple techniques
    Provides various string hiding and encoding methods
    """
    
    def __init__(self, method: str = "multi_layer"):
        self.method = method
        self.obfuscation_key = os.urandom(32)
        self.stack_strings = {}
        self.encoded_strings = {}
        
        # Research mode settings
        self.research_mode = True
        self.preserve_important_strings = True
        self.debug_output = True
        
        # Obfuscation statistics
        self.strings_processed = 0
        self.techniques_used = []
    
    def xor_encode(self, text: str, key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        XOR encoding with random key
        """
        if key is None:
            key = os.urandom(len(text.encode('utf-8')))
        
        text_bytes = text.encode('utf-8')
        encoded = bytearray()
        
        for i, byte in enumerate(text_bytes):
            encoded.append(byte ^ key[i % len(key)])
        
        return bytes(encoded), key
    
    def base64_multilayer_encode(self, text: str, layers: int = 3) -> str:
        """
        Multiple layers of base64 encoding
        """
        current = text.encode('utf-8')
        
        for i in range(layers):
            current = base64.b64encode(current)
        
        return current.decode('ascii')
    
    def char_array_split(self, text: str) -> str:
        """
        Split string into character array construction
        """
        if not text:
            return '""'
        
        chars = []
        for char in text:
            if char.isprintable() and char not in ['"', '\\']:
                chars.append(f"'{char}'")
            else:
                chars.append(f"'\\x{ord(char):02x}'")
        
        array_construction = f"std::string({{{''.join(chars)}}}, {len(text)})"
        return array_construction
    
    def stack_string_construction(self, text: str) -> str:
        """
        Generate stack-based string construction
        """
        if len(text) > 64:  # Limit for research safety
            text = text[:64]
        
        var_name = f"str_{hashlib.md5(text.encode()).hexdigest()[:8]}"
        
        construction = f"""
    // Stack string construction - Research obfuscation
    char {var_name}[{len(text) + 1}];
"""
        
        for i, char in enumerate(text):
            if char.isprintable() and char not in ['"', '\\']:
                construction += f"    {var_name}[{i}] = '{char}';\n"
            else:
                construction += f"    {var_name}[{i}] = 0x{ord(char):02x};\n"
        
        construction += f"    {var_name}[{len(text)}] = '\\0';\n"
        construction += f"    std::string({var_name})"
        
        return construction
    
    def polynomial_encoding(self, text: str) -> str:
        """
        Encode string using polynomial representation
        """
        # Convert text to numerical representation
        coefficients = [ord(c) for c in text]
        
        # Generate polynomial evaluation code
        var_name = f"poly_{random.randint(1000, 9999)}"
        poly_code = f"""
    // Polynomial string reconstruction - Research technique
    std::vector<int> {var_name}_coeffs = {{{', '.join(map(str, coefficients))}}};
    std::string {var_name}_result;
    for (int coeff : {var_name}_coeffs) {{
        {var_name}_result += static_cast<char>(coeff);
    }}
    {var_name}_result"""
        
        return poly_code
    
    def fibonacci_encoding(self, text: str) -> str:
        """
        Encode using Fibonacci sequence obfuscation
        """
        # Generate Fibonacci-based character codes
        fib_a, fib_b = 1, 1
        encoded_chars = []
        
        for char in text:
            ascii_val = ord(char)
            fib_encoded = ascii_val ^ (fib_a & 0xFF)
            encoded_chars.append(fib_encoded)
            
            # Next Fibonacci number
            fib_a, fib_b = fib_b, fib_a + fib_b
            if fib_b > 255:  # Reset for byte operations
                fib_a, fib_b = 1, 1
        
        var_name = f"fib_{random.randint(1000, 9999)}"
        fib_code = f"""
    // Fibonacci sequence obfuscation - Research technique
    std::vector<int> {var_name}_encoded = {{{', '.join(map(str, encoded_chars))}}};
    std::string {var_name}_result;
    int fib_a = 1, fib_b = 1;
    for (size_t i = 0; i < {var_name}_encoded.size(); i++) {{
        {var_name}_result += static_cast<char>({var_name}_encoded[i] ^ (fib_a & 0xFF));
        int temp = fib_b;
        fib_b = fib_a + fib_b;
        fib_a = temp;
        if (fib_b > 255) {{ fib_a = 1; fib_b = 1; }}
    }}
    {var_name}_result"""
        
        return fib_code
    
    def obfuscate(self, text: str, key: Optional[str] = None) -> str:
        """
        Main obfuscation function - applies selected technique
        """
        if not text or len(text) < 2:
            return f'"{text}"'  # Don't obfuscate very short strings
        
        # Preserve important strings in research mode
        if (self.preserve_important_strings and 
            any(important in text.lower() for important in 
                ['research', 'academic', 'debug', 'error', 'warning', 'copyright'])):
            return f'"{text}"'
        
        self.strings_processed += 1
        
        # Select obfuscation technique based on method
        if self.method == "xor":
            encoded_bytes, xor_key = self.xor_encode(text)
            return self.generate_xor_decoder(encoded_bytes, xor_key)
        
        elif self.method == "base64":
            encoded = self.base64_multilayer_encode(text, 2)
            return self.generate_base64_decoder(encoded, 2)
        
        elif self.method == "char_array":
            return self.char_array_split(text)
        
        elif self.method == "stack_string":
            return self.stack_string_construction(text)
        
        elif self.method == "polynomial":
            return self.polynomial_encoding(text)
        
        elif self.method == "fibonacci":
            return self.fibonacci_encoding(text)
        
        elif self.method == "multi_layer":
            # Randomly select technique for each string
            techniques = ["xor", "base64", "char_array", "polynomial"]
            selected = random.choice(techniques)
            temp_method = self.method
            self.method = selected
            result = self.obfuscate(text, key)
            self.method = temp_method
            
            if selected not in self.techniques_used:
                self.techniques_used.append(selected)
            
            return result
        
        else:
            return f'"{text}"'  # Fallback to original
    
    def generate_xor_decoder(self, encoded_bytes: bytes, key: bytes) -> str:
        """
        Generate XOR decoder C++ code
        """
        data_array = ', '.join(f'0x{b:02x}' for b in encoded_bytes)
        key_array = ', '.join(f'0x{b:02x}' for b in key[:16])  # Limit key size
        
        decoder = f"""
([](const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) -> std::string {{
    std::string result;
    for (size_t i = 0; i < data.size(); i++) {{
        result += static_cast<char>(data[i] ^ key[i % key.size()]);
    }}
    return result;
}})(std::vector<unsigned char>{{{data_array}}}, std::vector<unsigned char>{{{key_array}}})"""
        
        return decoder
    
    def generate_base64_decoder(self, encoded: str, layers: int) -> str:
        """
        Generate base64 decoder C++ code
        """
        decoder = f"""
([](std::string encoded, int layers) -> std::string {{
    for (int i = 0; i < layers; i++) {{
        // Simple base64 decode - research implementation
        std::string decoded;
        // Base64 decode logic would go here
        encoded = decoded;
    }}
    return encoded;
}})("{encoded}", {layers})"""
        
        return decoder
    
    def obfuscate_file(self, source_code: str) -> str:
        """
        Apply string obfuscation to entire source file
        """
        if self.debug_output and self.research_mode:
            print(f"[+] Applying string obfuscation - Method: {self.method}")
        
        # Find all string literals
        string_pattern = r'"([^"\\]|\\.)*"'
        
        def replace_string(match):
            original = match.group(0)
            content = original[1:-1]  # Remove quotes
            return self.obfuscate(content)
        
        # Replace all string literals
        obfuscated_code = re.sub(string_pattern, replace_string, source_code)
        
        if self.debug_output and self.research_mode:
            print(f"[+] Processed {self.strings_processed} strings")
            print(f"[+] Techniques used: {', '.join(self.techniques_used)}")
        
        return obfuscated_code
    
    def generate_runtime_decoder_functions(self) -> str:
        """
        Generate necessary runtime decoder functions
        """
        decoder_functions = """
// Runtime decoder functions - Research implementation
namespace StringObfuscation {
    
    std::string base64_decode(const std::string& encoded) {
        // Base64 decode implementation
        static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string decoded;
        
        // Simple base64 decode logic
        // Full implementation would go here
        
        return decoded;
    }
    
    std::string xor_decode(const std::vector<unsigned char>& data, 
                          const std::vector<unsigned char>& key) {
        std::string result;
        result.reserve(data.size());
        
        for (size_t i = 0; i < data.size(); i++) {
            result += static_cast<char>(data[i] ^ key[i % key.size()]);
        }
        
        return result;
    }
    
    std::string polynomial_decode(const std::vector<int>& coefficients) {
        std::string result;
        result.reserve(coefficients.size());
        
        for (int coeff : coefficients) {
            result += static_cast<char>(coeff);
        }
        
        return result;
    }
}

"""
        
        return decoder_functions
    
    def add_anti_analysis_decoys(self, code: str) -> str:
        """
        Add decoy strings and functions to confuse analysis
        """
        if self.method != "multi_layer":
            return code
        
        decoy_strings = [
            "This is a decoy string for research analysis",
            "Fake credential: admin:password123", 
            "Decoy URL: http://fake-c2-server.com",
            "Research note: This string has no operational purpose"
        ]
        
        decoy_code = "\n// Decoy strings for analysis confusion - Research purposes\n"
        for i, decoy in enumerate(decoy_strings):
            obfuscated_decoy = self.obfuscate(decoy)
            decoy_code += f"static auto decoy_{i} = {obfuscated_decoy}; // Unused decoy\n"
        
        return decoy_code + "\n" + code
    
    def get_statistics(self) -> Dict:
        """
        Get obfuscation statistics for research analysis
        """
        return {
            'method': self.method,
            'strings_processed': self.strings_processed,
            'techniques_used': self.techniques_used.copy(),
            'research_mode': self.research_mode,
            'preserve_important': self.preserve_important_strings,
            'key_size': len(self.obfuscation_key),
            'technique_category': 'String Obfuscation'
        }
    
    def reset_statistics(self):
        """
        Reset statistics for new obfuscation run
        """
        self.strings_processed = 0
        self.techniques_used = []
        self.stack_strings = {}
        self.encoded_strings = {}


# Research testing and validation
def test_string_obfuscation():
    """
    Test function for research validation
    """
    print("Testing String Obfuscation Techniques:")
    
    test_strings = [
        "Hello, World!",
        "This is a test string",
        "Password: secret123",
        "https://example.com/api"
    ]
    
    methods = ["xor", "base64", "char_array", "polynomial", "fibonacci", "multi_layer"]
    
    for method in methods:
        print(f"\n--- Testing {method} ---")
        obfuscator = StringObfuscator(method)
        
        for test_str in test_strings:
            obfuscated = obfuscator.obfuscate(test_str)
            print(f"Original: {test_str}")
            print(f"Obfuscated: {obfuscated[:100]}...")
            print()
        
        stats = obfuscator.get_statistics()
        print(f"Statistics: {stats}")


def demonstrate_file_obfuscation():
    """
    Demonstrate file-level obfuscation
    """
    test_code = '''
#include <iostream>
#include <string>

int main() {
    std::cout << "Hello, Research World!" << std::endl;
    std::string password = "admin123";
    std::string url = "https://research-server.edu/api";
    
    if (password == "admin123") {
        std::cout << "Access granted for research" << std::endl;
    }
    
    return 0;
}
'''
    
    obfuscator = StringObfuscator("multi_layer")
    obfuscated_code = obfuscator.obfuscate_file(test_code)
    decoder_funcs = obfuscator.generate_runtime_decoder_functions()
    
    print("Original code length:", len(test_code))
    print("Obfuscated code length:", len(obfuscated_code))
    print("Expansion ratio:", len(obfuscated_code) / len(test_code))
    
    return decoder_funcs + obfuscated_code


if __name__ == "__main__":
    print("BYJY-RwGen String Obfuscator - Research Mode")
    print("FOR DEFENSIVE CYBERSECURITY RESEARCH ONLY")
    print("=" * 60)
    
    test_string_obfuscation()
    print("\n" + "=" * 60)
    demonstrate_file_obfuscation()