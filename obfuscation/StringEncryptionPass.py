#!/usr/bin/env python3
"""
String Encryption Pass Implementation
Advanced string obfuscation for cybersecurity research
FOR DEFENSIVE RESEARCH PURPOSES ONLY
"""

import re
import os
import base64
import hashlib
from typing import List, Dict, Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class StringEncryptionPass:
    """
    Advanced String Encryption Pass for source code obfuscation
    Encrypts string literals and generates runtime decryption
    """
    
    def __init__(self, encryption_method: str = "aes256"):
        self.encryption_method = encryption_method
        self.key = get_random_bytes(32)  # 256-bit key
        self.string_table = {}
        self.string_counter = 0
        
        # Research safety settings
        self.research_mode = True
        self.preserve_debug_strings = True
        self.max_string_length = 1024  # Limit for safety
        
    def encrypt_string(self, plaintext: str) -> Tuple[bytes, bytes]:
        """
        Encrypt a string using AES-256-CBC
        Returns (ciphertext, iv)
        """
        if len(plaintext) > self.max_string_length:
            plaintext = plaintext[:self.max_string_length]  # Research safety limit
        
        # Generate random IV
        iv = get_random_bytes(16)
        
        # Create cipher
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Pad and encrypt
        padded_text = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        
        return ciphertext, iv
    
    def generate_decryption_function(self) -> str:
        """
        Generate C++ decryption function
        """
        key_hex = self.key.hex()
        
        decryption_code = f"""
// String decryption function - Generated for research purposes
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string>
#include <vector>

class StringDecryptor {{
private:
    static const unsigned char key[32];
    
public:
    static std::string decrypt(const unsigned char* ciphertext, size_t cipher_len, 
                              const unsigned char* iv) {{
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return "";
        
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {{
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }}
        
        std::vector<unsigned char> plaintext(cipher_len + AES_BLOCK_SIZE);
        int len;
        int plaintext_len;
        
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, cipher_len) != 1) {{
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }}
        plaintext_len = len;
        
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {{
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }}
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    }}
    
    // Convenience function for encrypted string literals
    static std::string get_string(int string_id) {{
        return decrypt_by_id(string_id);
    }}
    
private:
    static std::string decrypt_by_id(int id);
}};

// Obfuscated key storage - Research implementation
const unsigned char StringDecryptor::key[32] = {{
    {', '.join(f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2))}
}};

"""
        
        return decryption_code
    
    def process_string_literal(self, string_literal: str) -> str:
        """
        Process a single string literal
        """
        # Remove quotes
        content = string_literal[1:-1]  # Remove surrounding quotes
        
        # Skip empty strings or debug strings in research mode
        if not content or (self.preserve_debug_strings and 
                          any(debug_keyword in content.lower() 
                              for debug_keyword in ['debug', 'error', 'warning', 'research'])):
            return string_literal
        
        # Encrypt the string
        ciphertext, iv = self.encrypt_string(content)
        
        # Generate unique ID
        string_id = self.string_counter
        self.string_counter += 1
        
        # Store in string table
        self.string_table[string_id] = {
            'original': content,
            'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
            'iv': base64.b64encode(iv).decode('ascii'),
            'length': len(content)
        }
        
        # Return obfuscated call
        return f'StringDecryptor::get_string({string_id})'
    
    def generate_string_table(self) -> str:
        """
        Generate the encrypted string table implementation
        """
        if not self.string_table:
            return ""
        
        table_code = """
// Encrypted string table - Research implementation
std::string StringDecryptor::decrypt_by_id(int id) {
    struct EncryptedString {
        const char* ciphertext_b64;
        const char* iv_b64;
        size_t original_length;
    };
    
    static const EncryptedString string_table[] = {
"""
        
        for string_id, data in self.string_table.items():
            table_code += f'        {{ "{data["ciphertext"]}", "{data["iv"]}", {data["length"]} }},  // ID: {string_id}\n'
        
        table_code += """    };
    
    if (id < 0 || id >= sizeof(string_table) / sizeof(string_table[0])) {
        return "";  // Invalid ID - research safety
    }
    
    // Decode base64
    std::vector<unsigned char> ciphertext = base64_decode(string_table[id].ciphertext_b64);
    std::vector<unsigned char> iv = base64_decode(string_table[id].iv_b64);
    
    // Decrypt
    return decrypt(ciphertext.data(), ciphertext.size(), iv.data());
}

// Base64 decoder helper - Research implementation
std::vector<unsigned char> StringDecryptor::base64_decode(const std::string& encoded) {
    // Simple base64 decode implementation
    // In production, use proper base64 library
    std::vector<unsigned char> decoded;
    // Implementation would go here...
    return decoded;
}
"""
        
        return table_code
    
    def obfuscate_source_file(self, source_code: str) -> str:
        """
        Apply string encryption to entire source file
        """
        if self.research_mode:
            print(f"[+] Applying string encryption pass (Research Mode)")
            print(f"[+] Encryption method: {self.encryption_method}")
        
        # Find all string literals
        string_pattern = r'"([^"\\]|\\.)*"'
        strings_found = re.findall(string_pattern, source_code)
        
        if self.research_mode:
            print(f"[+] Found {len(strings_found)} string literals")
        
        # Process each string literal
        obfuscated_code = source_code
        for string_match in re.finditer(string_pattern, source_code):
            original_string = string_match.group(0)
            obfuscated_string = self.process_string_literal(original_string)
            obfuscated_code = obfuscated_code.replace(original_string, obfuscated_string, 1)
        
        # Add decryption function at the beginning
        decryption_func = self.generate_decryption_function()
        string_table = self.generate_string_table()
        
        # Combine everything
        final_code = decryption_func + string_table + "\n\n" + obfuscated_code
        
        if self.research_mode:
            print(f"[+] Processed {len(self.string_table)} strings for encryption")
            print(f"[+] Code expansion ratio: {len(final_code) / len(source_code):.2f}x")
        
        return final_code
    
    def generate_xor_variant(self, plaintext: str, key: bytes = None) -> Tuple[str, str]:
        """
        Generate XOR-obfuscated variant (simpler alternative to AES)
        """
        if key is None:
            key = os.urandom(len(plaintext))
        
        # XOR encryption
        encrypted = bytearray()
        for i, char in enumerate(plaintext.encode('utf-8')):
            encrypted.append(char ^ key[i % len(key)])
        
        # Generate C++ code for XOR decryption
        key_hex = ', '.join(f'0x{b:02x}' for b in key[:16])  # Limit key size
        data_hex = ', '.join(f'0x{b:02x}' for b in encrypted)
        
        xor_code = f"""
// XOR obfuscated string - Research implementation
[]() -> std::string {{
    static const unsigned char key[] = {{ {key_hex} }};
    static const unsigned char data[] = {{ {data_hex} }};
    static const size_t key_len = sizeof(key);
    static const size_t data_len = sizeof(data);
    
    std::string result;
    result.reserve(data_len);
    
    for (size_t i = 0; i < data_len; i++) {{
        result += static_cast<char>(data[i] ^ key[i % key_len]);
    }}
    
    return result;
}}()"""
        
        return xor_code, key.hex()
    
    def get_statistics(self) -> Dict:
        """
        Get encryption statistics for research analysis
        """
        return {
            'encryption_method': self.encryption_method,
            'strings_processed': len(self.string_table),
            'research_mode': self.research_mode,
            'key_size': len(self.key) * 8,  # bits
            'technique': 'String Encryption Pass',
            'preserve_debug': self.preserve_debug_strings
        }
    
    def export_key_for_analysis(self) -> str:
        """
        Export encryption key for research analysis (research mode only)
        """
        if not self.research_mode:
            return "Key export disabled in production mode"
        
        return {
            'key_hex': self.key.hex(),
            'key_b64': base64.b64encode(self.key).decode('ascii'),
            'method': self.encryption_method,
            'note': 'FOR RESEARCH ANALYSIS ONLY - DO NOT USE IN PRODUCTION'
        }


# Research testing and validation
def test_string_encryption():
    """
    Test function for research validation
    """
    encryptor = StringEncryptionPass()
    
    test_code = '''
    int main() {
        printf("Hello, World!");
        printf("This is a test string for research");
        return 0;
    }
    '''
    
    obfuscated = encryptor.obfuscate_source_file(test_code)
    stats = encryptor.get_statistics()
    
    print("Original code length:", len(test_code))
    print("Obfuscated code length:", len(obfuscated))
    print("Statistics:", stats)
    
    return obfuscated


if __name__ == "__main__":
    print("BYJY-RwGen String Encryption Pass - Research Mode")
    print("FOR DEFENSIVE CYBERSECURITY RESEARCH ONLY")
    test_string_encryption()