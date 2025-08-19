#ifndef ADVANCED_STRING_OBFUSCATOR_H
#define ADVANCED_STRING_OBFUSCATOR_H

#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <stdexcept>
#include <random>
#include <openssl/evp.h>

class AdvancedStringObfuscator {
public:
    static std::string obfuscate(const std::string& input, const std::string& key) {
        // First layer: AES-256 encryption
        std::string aes_encrypted = aesEncrypt(input, key);
        
        // Second layer: custom permutation
        std::string permuted = applyPermutation(aes_encrypted, key);
        
        // Third layer: XOR with rotating key
        return rotatingXor(permuted, key);
    }

    static std::string deobfuscate(const std::string& input, const std::string& key) {
        // Reverse XOR
        std::string xor_decrypted = rotatingXor(input, key);
        
        // Reverse permutation
        std::string unpermuted = reversePermutation(xor_decrypted, key);
        
        // AES decrypt
        return aesDecrypt(unpermuted, key);
    }

private:
    static std::string aesEncrypt(const std::string& plaintext, const std::string& key) {
        if (key.size() < 32) {
            throw std::invalid_argument("Key must be at least 32 bytes for AES-256");
        }
        
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        std::string real_key = key.substr(0, 32);
        std::array<unsigned char, 16> iv;
        std::fill(iv.begin(), iv.end(), 0);
        
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                          reinterpret_cast<const unsigned char*>(real_key.data()), 
                          iv.data());
        
        int out_len = plaintext.size() + EVP_CIPHER_CTX_block_size(ctx);
        std::vector<unsigned char> out(out_len);
        
        int final_len;
        EVP_EncryptUpdate(ctx, out.data(), &out_len, 
                         reinterpret_cast<const unsigned char*>(plaintext.data()), 
                         plaintext.size());
        EVP_EncryptFinal_ex(ctx, out.data() + out_len, &final_len);
        
        EVP_CIPHER_CTX_free(ctx);
        return std::string(out.begin(), out.begin() + out_len + final_len);
    }
    
    static std::string aesDecrypt(const std::string& ciphertext, const std::string& key) {
        if (key.size() < 32) {
            throw std::invalid_argument("Key must be at least 32 bytes for AES-256");
        }
        
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        std::string real_key = key.substr(0, 32);
        std::array<unsigned char, 16> iv;
        std::fill(iv.begin(), iv.end(), 0);
        
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                          reinterpret_cast<const unsigned char*>(real_key.data()), 
                          iv.data());
        
        int out_len = ciphertext.size();
        std::vector<unsigned char> out(out_len);
        
        int final_len;
        EVP_DecryptUpdate(ctx, out.data(), &out_len, 
                         reinterpret_cast<const unsigned char*>(ciphertext.data()), 
                         ciphertext.size());
        EVP_DecryptFinal_ex(ctx, out.data() + out_len, &final_len);
        
        EVP_CIPHER_CTX_free(ctx);
        return std::string(out.begin(), out.begin() + out_len + final_len);
    }
    
    static std::string applyPermutation(const std::string& input, const std::string& key) {
        size_t size = input.size();
        if (size == 0) return input;
        
        std::vector<size_t> indices(size);
        for (size_t i = 0; i < size; ++i) {
            indices[i] = i;
        }
        
        // Seed RNG with key-derived value
        uint32_t seed = 0;
        for (char c : key) {
            seed = (seed << 5) + seed + c;
        }
        std::mt19937 rng(seed);
        std::shuffle(indices.begin(), indices.end(), rng);
        
        // Apply permutation
        std::string result(size, '\0');
        for (size_t i = 0; i < size; ++i) {
            result[i] = input[indices[i]];
        }
        
        return result;
    }
    
    static std::string reversePermutation(const std::string& input, const std::string& key) {
        size_t size = input.size();
        if (size == 0) return input;
        
        std::vector<size_t> indices(size);
        for (size_t i = 0; i < size; ++i) {
            indices[i] = i;
        }
        
        // Seed RNG with key-derived value
        uint32_t seed = 0;
        for (char c : key) {
            seed = (seed << 5) + seed + c;
        }
        std::mt19937 rng(seed);
        std::shuffle(indices.begin(), indices.end(), rng);
        
        // Reverse permutation
        std::string result(size, '\0');
        for (size_t i = 0; i < size; ++i) {
            result[indices[i]] = input[i];
        }
        
        return result;
    }
    
    static std::string rotatingXor(const std::string& input, const std::string& key) {
        if (key.empty()) return input;
        
        std::string result = input;
        size_t key_index = 0;
        for (size_t i = 0; i < input.size(); ++i) {
            result[i] ^= key[key_index];
            key_index = (key_index + 1) % key.size();
            
            // Rotate key
            if (i % key.size() == 0) {
                char first = key[0];
                for (size_t j = 0; j < key.size() - 1; ++j) {
                    key[j] = key[j + 1];
                }
                key[key.size() - 1] = first;
            }
        }
        return result;
    }
};

#endif // ADVANCED_STRING_OBFUSCATOR_H