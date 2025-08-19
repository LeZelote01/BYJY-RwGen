#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <chrono>
#include <wmicommon.h>
#include <winternl.h>
#include <intrin.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "wbemuuid.lib")

// Déclarations NtAPI
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Structures non documentées
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

class AdvancedSandboxDetector {
public:
    bool isSandboxed() {
        return (
            checkMemorySize() ||
            checkProcesses() ||
            checkCPUUsage() ||
            checkSleepAcceleration() ||
            checkMouseActivity() ||
            checkDiskSize() ||
            checkWMISandbox() ||
            checkDebuggerPresent() ||
            checkTicks() ||
            checkProcessorCores()
        );
    }

private:
    bool checkMemorySize() {
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);

        // Moins de 4GB = potentiel sandbox
        return (memStatus.ullTotalPhys < (4ULL * 1024 * 1024 * 1024));
    }

    bool checkProcesses() {
        const std::vector<std::wstring> sandboxProcesses = {
            L"sandboxie", L"cuckoo", L"vmware", L"vbox", 
            L"procmon", L"wireshark", L"processhacker"
        };

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);

        if (!Process32FirstW(snapshot, &pe)) {
            CloseHandle(snapshot);
            return false;
        }

        do {
            std::wstring exeName(pe.szExeFile);
            std::transform(exeName.begin(), exeName.end(), exeName.begin(), ::towlower);

            for (const auto& proc : sandboxProcesses) {
                if (exeName.find(proc) != std::wstring::npos) {
                    CloseHandle(snapshot);
                    return true;
                }
            }
        } while (Process32NextW(snapshot, &pe));

        CloseHandle(snapshot);
        return false;
    }

    bool checkCPUUsage() {
        NtQuerySystemInformation_t NtQuerySystemInformation = 
            reinterpret_cast<NtQuerySystemInformation_t>(
                GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation")
            );
        
        if (!NtQuerySystemInformation) return false;

        SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION sppi[16];
        ULONG returnLength;
        NTSTATUS status = NtQuerySystemInformation(
            static_cast<SYSTEM_INFORMATION_CLASS>(8), // SystemProcessorPerformanceInformation
            sppi,
            sizeof(sppi),
            &returnLength
        );

        if (!NT_SUCCESS(status)) return false;

        // Attendre 1 seconde
        std::this_thread::sleep_for(std::chrono::seconds(1));

        SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION sppi2[16];
        status = NtQuerySystemInformation(
            static_cast<SYSTEM_INFORMATION_CLASS>(8),
            sppi2,
            sizeof(sppi2),
            &returnLength
        );

        if (!NT_SUCCESS(status)) return false;

        // Calculer le temps CPU utilisé
        ULONGLONG totalIdle = 0;
        ULONGLONG totalKernel = 0;
        ULONGLONG totalUser = 0;

        int cores = returnLength / sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION);
        for (int i = 0; i < cores; i++) {
            totalIdle += sppi2[i].IdleTime.QuadPart - sppi[i].IdleTime.QuadPart;
            totalKernel += sppi2[i].KernelTime.QuadPart - sppi[i].KernelTime.QuadPart;
            totalUser += sppi2[i].UserTime.QuadPart - sppi[i].UserTime.QuadPart;
        }

        ULONGLONG totalSys = totalKernel + totalUser;
        ULONGLONG cpuUsage = (totalSys > 0) ? (100ULL - (totalIdle * 100ULL / totalSys)) : 0;

        // Si CPU usage < 5%, probablement dans une sandbox
        return (cpuUsage < 5);
    }

    bool checkSleepAcceleration() {
        auto start = std::chrono::high_resolution_clock::now();
        std::this_thread::sleep_for(std::chrono::seconds(10));
        auto end = std::chrono::high_resolution_clock::now();

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        // Marge d'erreur de 500ms
        return (duration < 9500);
    }

    bool checkMouseActivity() {
        POINT lastPosition;
        GetCursorPos(&lastPosition);
        std::this_thread::sleep_for(std::chrono::seconds(5));
        POINT newPosition;
        GetCursorPos(&newPosition);

        // Si la souris n'a pas bougé
        return (lastPosition.x == newPosition.x && lastPosition.y == newPosition.y);
    }

    bool checkDiskSize() {
        ULARGE_INTEGER freeBytes, totalBytes, totalFreeBytes;
        if (GetDiskFreeSpaceExW(L"C:\\", &freeBytes, &totalBytes, &totalFreeBytes)) {
            // Disque < 100GB = probable sandbox
            return (totalBytes.QuadPart < (100ULL * 1024 * 1024 * 1024));
        }
        return false;
    }

    bool checkWMISandbox() {
        IWbemLocator* locator = nullptr;
        IWbemServices* services = nullptr;
        bool result = false;

        if (CoInitializeEx(0, COINIT_MULTITHREADED) != S_OK) 
            return false;
        
        if (CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, 
                            IID_IWbemLocator, (LPVOID*)&locator) != S_OK) {
            CoUninitialize();
            return false;
        }

        if (locator->ConnectServer(BSTR(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &services) != S_OK) {
            locator->Release();
            CoUninitialize();
            return false;
        }

        IEnumWbemClassObject* enumerator = nullptr;
        if (services->ExecQuery(BSTR(L"WQL"), BSTR(L"SELECT * FROM Win32_BaseBoard"), 
                               WBEM_FLAG_FORWARD_ONLY, NULL, &enumerator) == S_OK) {
            
            IWbemClassObject* obj = nullptr;
            ULONG returned = 0;

            while (enumerator->Next(WBEM_INFINITE, 1, &obj, &returned) == S_OK) {
                VARIANT manufacturer;
                VariantInit(&manufacturer);

                if (obj->Get(L"Manufacturer", 0, &manufacturer, 0, 0) == S_OK) {
                    if (manufacturer.vt == VT_BSTR) {
                        std::wstring manuf(manufacturer.bstrVal);
                        if (manuf.find(L"VMware") != std::wstring::npos || 
                            manuf.find(L"VirtualBox") != std::wstring::npos) {
                            result = true;
                        }
                    }
                    VariantClear(&manufacturer);
                }
                obj->Release();
            }
            enumerator->Release();
        }

        services->Release();
        locator->Release();
        CoUninitialize();
        return result;
    }

    bool checkDebuggerPresent() {
        return IsDebuggerPresent();
    }

    bool checkTicks() {
        ULONGLONG ticks1 = GetTickCount64();
        DWORD_PTR threadAffinity = SetThreadAffinityMask(GetCurrentThread(), 1);
        ULONGLONG startTsc = __rdtsc();
        SetThreadAffinityMask(GetCurrentThread(), threadAffinity);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        ULONGLONG ticks2 = GetTickCount64();
        threadAffinity = SetThreadAffinityMask(GetCurrentThread(), 1);
        ULONGLONG endTsc = __rdtsc();
        SetThreadAffinityMask(GetCurrentThread(), threadAffinity);
        
        ULONGLONG ticksDelta = ticks2 - ticks1;
        ULONGLONG tscDelta = endTsc - startTsc;
        
        // TSC devrait être beaucoup plus grand que les ticks
        return (tscDelta < (ticksDelta * 1000000));
    }

    bool checkProcessorCores() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        return (sysInfo.dwNumberOfProcessors < 4);
    }
};