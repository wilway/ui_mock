#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>

extern "C" {
    #pragma function(memset)
    void* __cdecl memset(void* p, int c, size_t n) {
        unsigned char* s = (unsigned char*)p;
        while (n--) *s++ = (unsigned char)c;
        return p;
    }
}

bool FreeRemoteDLL(DWORD processID, const wchar_t* dllPath) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    HMODULE hRemoteMod = NULL;
    MODULEENTRY32W me;
    me.dwSize = sizeof(MODULEENTRY32W);
    if (Module32FirstW(hSnap, &me)) {
        do {
            if (lstrcmpiW(me.szExePath, dllPath) == 0 || lstrcmpiW(me.szModule, dllPath) == 0) {
                hRemoteMod = (HMODULE)me.modBaseAddr;
                break;
            }
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);

    if (!hRemoteMod) return false;

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processID);
    if (!hProcess) return false;

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pFreeLibrary = GetProcAddress(hKernel32, "FreeLibrary");

    if (!pFreeLibrary) {
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFreeLibrary, hRemoteMod, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }

    CloseHandle(hProcess);
    return false;
}

bool InjectRemoteDLL_CRT(DWORD processID, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processID);
    if (!hProcess) return false;

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibrary) {
        CloseHandle(hProcess);
        return false;
    }

    size_t pathSize = (lstrlenW(dllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMem) {
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath, pathSize, NULL)) {
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMem, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE); 
        CloseHandle(hThread);
    } else {
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return true;
}

DWORD my_wtol(const wchar_t* str) {
    DWORD res = 0;
    while (*str >= L'0' && *str <= L'9') {
        res = res * 10 + (*str - L'0');
        str++;
    }
    return res;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 4) return 1;

    DWORD pid = my_wtol(argv[1]);
    const wchar_t* dllPath = argv[2];
    DWORD mode = my_wtol(argv[3]);

    bool success = false;
    if (mode == 1) { // 1 means free
        success = FreeRemoteDLL(pid, dllPath);
    } else { // 0 means inject
        success = InjectRemoteDLL_CRT(pid, dllPath);
    }

    return success ? 0 : 1;
}

void __stdcall wmainCRTStartup() {
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int ret = 1;
    if (argv) {
        ret = wmain(argc, argv);
        LocalFree(argv);
    }
    ExitProcess(ret);
}
