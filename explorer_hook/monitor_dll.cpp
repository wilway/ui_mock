#include <windows.h>
#include <string>
#include <cwctype>
#include "../minhook/include/MinHook.h"

// ====================================================================================
// 核心监控 DLL：利用外部注入器实现跨架构、全自动递归注入
// ====================================================================================

typedef BOOL (WINAPI *CREATEPROCESSINTERNALW)(
    HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken
);

CREATEPROCESSINTERNALW fpCreateProcessInternalW = NULL;

// 调试日志输出函数：输出到系统调试器 (可用 DebugView 查看)
void DebugLog(const wchar_t* format, ...) {
    wchar_t buf[1024];
    va_list args;
    va_start(args, format);
    wvsprintfW(buf, format, args);
    va_end(args);
    OutputDebugStringW(L"[MonitorDLL] ");
    OutputDebugStringW(buf);
    OutputDebugStringW(L"\n");
}

// 存储当前监控环境所在的目录路径
wchar_t g_baseDir[MAX_PATH] = { 0 };

// 判断目标进程是否为 64 位
bool IsProcess64Bit(HANDLE hProcess) {
    BOOL isWow64 = FALSE;
    if (!IsWow64Process(hProcess, &isWow64)) return false;
    return (isWow64 == FALSE);
}

// 检查字符串是否包含子串（不区分大小写）
bool ContainsIgnoreCase(const wchar_t* str, const wchar_t* search) {
    if (!str || !search) return false;
    std::wstring s1 = str;
    std::wstring s2 = search;
    for (auto& c : s1) c = towlower(c);
    for (auto& c : s2) c = towlower(c);
    return s1.find(s2) != std::wstring::npos;
}

// ====================================================================================
// 进程黑名单：这些进程通常对 Hook 极其敏感，注入可能导致系统不稳定或应用崩溃
// ====================================================================================
bool IsBlacklistedProcess(LPCWSTR name, LPCWSTR cmdLine) {
    static const wchar_t* blacklist[] = {
        L"csrss.exe", L"lsass.exe", L"wininit.exe", L"smss.exe", L"services.exe",
        L"dwm.exe", L"logonui.exe", L"winlogon.exe", L"fontdrvhost.exe",
        L"SogouCloud.exe", L"SogouExe.exe", L"SGTool.exe", // 搜狗输入法敏感
        L"nvspcaps64.exe", L"nvcontainer.exe", // NVIDIA 组件
        L"SearchIndexer.exe", L"SearchHost.exe",
        L"inj32.exe", L"inj64.exe", L"demo.exe" // 自身工具
    };

    for (const auto& item : blacklist) {
        if (name && ContainsIgnoreCase(name, item)) return true;
        if (cmdLine && ContainsIgnoreCase(cmdLine, item)) return true;
    }
    return false;
}

// 调用外部注入器进程 (如 inj32.exe 或 inj64.exe)
// 命令行格式参考： "injector.exe <PID> <DLL_PATH> <MODE>"
bool RunExternalInjector(DWORD pid, const wchar_t* injectorName, const wchar_t* targetDllPathOrName) {
    wchar_t injectorPath[MAX_PATH];
    lstrcpyW(injectorPath, g_baseDir);
    lstrcatW(injectorPath, injectorName);

    // 处理 DLL 路径：如果是相对路径则拼接到 g_baseDir
    wchar_t finalDllPath[MAX_PATH];
    if (GetFileAttributesW(targetDllPathOrName) == INVALID_FILE_ATTRIBUTES) {
        lstrcpyW(finalDllPath, g_baseDir);
        lstrcatW(finalDllPath, targetDllPathOrName);
    } else {
        lstrcpyW(finalDllPath, targetDllPathOrName);
    }

    // 检查所需文件是否存在
    if (GetFileAttributesW(injectorPath) == INVALID_FILE_ATTRIBUTES) return false;
    if (GetFileAttributesW(finalDllPath) == INVALID_FILE_ATTRIBUTES) return false;

    // 构造命令行参数： "path\to\inj32.exe" PID "path\to\target.dll" 0
    wchar_t cmdLine[MAX_PATH * 3];
    wsprintfW(cmdLine, L"\"%s\" %lu \"%s\" 0", injectorPath, pid, finalDllPath);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // 启动注入器进程
    if (CreateProcessW(injectorPath, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        DebugLog(L"Started injector: %s", cmdLine);
        // 等待注入操作完成
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    } else {
        DebugLog(L"Error: Failed to start injector (Code: %lu)", GetLastError());
    }
    return false;
}

// Hook 回调函数：当有新进程创建时被激活
BOOL WINAPI DetourCreateProcessInternalW(
    HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken
) {
    DWORD originalFlags = dwCreationFlags;

    // ====================================================================================
    // 安全检查：判断是否在黑名单中，防止无限递归或系统组件崩溃
    // ====================================================================================
    if (IsBlacklistedProcess(lpApplicationName, lpCommandLine)) {
        return fpCreateProcessInternalW(
            hToken, lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags,
            lpEnvironment, lpCurrentDirectory, lpStartupInfo,
            lpProcessInformation, hNewToken
        );
    }

    // 正常启动新进程
    BOOL result = fpCreateProcessInternalW(
        hToken, lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo,
        lpProcessInformation, hNewToken
    );
    DWORD lastErr = GetLastError();
    if (result && lpProcessInformation && lpProcessInformation->hProcess) {
        DWORD targetPid = lpProcessInformation->dwProcessId;
        bool targetIs64 = IsProcess64Bit(lpProcessInformation->hProcess);

        DebugLog(L"Infecting PID: %lu, Name: %s", targetPid, lpApplicationName ? lpApplicationName : L"Unknown");

        if (targetIs64) {
            RunExternalInjector(targetPid, L"inj64.exe", L"monitor64.dll");
        } else {
            RunExternalInjector(targetPid, L"inj32.exe", L"monitor32.dll");
        }
    }
    SetLastError(lastErr);
    return result;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // 初始化：获取 DLL 所在的路径作为基准工作目录
        wchar_t selfPath[MAX_PATH];
        GetModuleFileNameW(hModule, selfPath, MAX_PATH);
        wchar_t* lastSlash = wcsrchr(selfPath, L'\\');
        if (lastSlash) {
            *(lastSlash + 1) = L'\0';
            lstrcpyW(g_baseDir, selfPath);
        }

        // --- 直接在 DllMain 中加载业务 DLL ---
        wchar_t configPath[MAX_PATH];
        lstrcpyW(configPath, g_baseDir);
        lstrcatW(configPath, L"config.ini");

        wchar_t businessDll[MAX_PATH];
#ifdef _WIN64
        GetPrivateProfileStringW(L"Settings", L"Test64Path", L"test64.dll", businessDll, MAX_PATH, configPath);
#else
        GetPrivateProfileStringW(L"Settings", L"Test32Path", L"test32.dll", businessDll, MAX_PATH, configPath);
#endif

        wchar_t finalDllPath[MAX_PATH];
        if (GetFileAttributesW(businessDll) == INVALID_FILE_ATTRIBUTES) {
            lstrcpyW(finalDllPath, g_baseDir);
            lstrcatW(finalDllPath, businessDll);
        } else {
            lstrcpyW(finalDllPath, businessDll);
        }
        LoadLibraryW(finalDllPath);
        // -------------------------------------

        // 初始化 MinHook 库并设置钩子
        if (MH_Initialize() == MH_OK) {
            HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
            if (hKernelBase) {
                void* pTarget = (void*)GetProcAddress(hKernelBase, "CreateProcessInternalW");
                if (pTarget) {
                    MH_CreateHook(pTarget, (LPVOID)&DetourCreateProcessInternalW, (LPVOID*)&fpCreateProcessInternalW);
                    MH_EnableHook(pTarget);
                }
            }
        }
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        // 清理钩子
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}

