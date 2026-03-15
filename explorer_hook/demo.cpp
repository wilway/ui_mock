#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <string>

#pragma comment(lib, "shlwapi.lib")

// 定义资源 ID
#define IDR_INJ32_EXE      1001
#define IDR_INJ64_EXE      1002
#define IDR_MONITOR32_DLL  1003
#define IDR_MONITOR64_DLL  1004

// 辅助函数：查找进程 PID
DWORD GetProcessPidByName(const wchar_t* name) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (lstrcmpiW(pe.szExeFile, name) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return pid;
}

// 辅助函数：释放资源到文件
bool ExtractResourceToFile(UINT resId, const wchar_t* fileName) {
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(resId), L"BINARY");
    if (!hRes) return false;

    HGLOBAL hGlobal = LoadResource(NULL, hRes);
    if (!hGlobal) return false;

    DWORD size = SizeofResource(NULL, hRes);
    void* pData = LockResource(hGlobal);

    HANDLE hFile = CreateFileW(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD bytesWritten;
    BOOL result = WriteFile(hFile, pData, size, &bytesWritten, NULL);
    CloseHandle(hFile);

    return result && (bytesWritten == size);
}

// 辅助函数：简单的 LoadLibraryW 注入 (假设 demo 是 64 位，Explorer 也是 64 位)
// 辅助函数：判断进程是否为 64 位
bool IsProcess64Bit(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;
    BOOL isWow64 = FALSE;
    BOOL result = IsWow64Process(hProcess, &isWow64);
    CloseHandle(hProcess);
    if (!result) return false;
    return (isWow64 == FALSE);
}

// 辅助函数：调用刚刚释放出的注入器
bool RunProxyInjector(const std::wstring& baseDir, DWORD pid, const wchar_t* injectorName, const wchar_t* dllName) {
    std::wstring injectorPath = baseDir + injectorName;
    std::wstring dllPath = baseDir + dllName;

    wchar_t cmdLine[MAX_PATH * 3];
    wsprintfW(cmdLine, L"\"%s\" %lu \"%s\" 0", injectorPath.c_str(), pid, dllPath.c_str());

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return (exitCode == 0);
    }
    return false;
}

// 调试日志输出函数
void DebugLog(const wchar_t* format, ...) {
    wchar_t buf[1024];
    va_list args;
    va_start(args, format);
    wvsprintfW(buf, format, args);
    va_end(args);
    OutputDebugStringW(L"[HookLauncher] ");
    OutputDebugStringW(buf);
    OutputDebugStringW(L"\n");
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPWSTR lpCmdLine, int nShow) {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecW(exePath);
    lstrcatW(exePath, L"\\");

    std::wstring baseDir = exePath;

    // 1. 释放所有需要的组件
    ExtractResourceToFile(IDR_INJ32_EXE,     (baseDir + L"inj32.exe").c_str());
    ExtractResourceToFile(IDR_INJ64_EXE,     (baseDir + L"inj64.exe").c_str());
    ExtractResourceToFile(IDR_MONITOR32_DLL, (baseDir + L"monitor32.dll").c_str());
    ExtractResourceToFile(IDR_MONITOR64_DLL, (baseDir + L"monitor64.dll").c_str());
    
    DebugLog(L"Core components extracted to: %s", baseDir.c_str());

    // 2. 找到 explorer.exe
    DWORD explorerPid = GetProcessPidByName(L"explorer.exe");
    if (explorerPid == 0) {
        DebugLog(L"Error: Could not find explorer.exe process.");
        return 1;
    }

    // 3. 判断 Explorer 架构并调用代理注入器
    bool isExplorer64 = IsProcess64Bit(explorerPid);
    bool success = false;

    if (isExplorer64) {
        DebugLog(L"Explorer is 64-bit. Using inj64.exe -> monitor64.dll");
        success = RunProxyInjector(baseDir, explorerPid, L"inj64.exe", L"monitor64.dll");
    } else {
        DebugLog(L"Explorer is 32-bit. Using inj32.exe -> monitor32.dll");
        success = RunProxyInjector(baseDir, explorerPid, L"inj32.exe", L"monitor32.dll");
    }

    if (success) {
        DebugLog(L"Initial injection successful! Recursive monitoring is now ACTIVE.");
    } else {
        DebugLog(L"Initial injection failed. Check administrator privileges.");
    }

    return success ? 0 : 1;
}
