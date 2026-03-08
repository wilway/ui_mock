#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlwapi.h>

#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// 控件 ID 定义
#define ID_RAD_INJECT 101
#define ID_RAD_FREE   102
#define ID_CMB_METHOD 103
#define ID_TXT_PROC   104
#define ID_BTN_PROC   105
#define ID_TXT_DLL    106
#define ID_BTN_DLL    107
#define ID_BTN_ACTION 108
#define ID_TXT_LOG    109
#define ID_BTN_CLEAR  110
#define ID_BTN_SAVE   111

#define ID_LST_PROCS  201
#define ID_BTN_SEL_PROC 202
#define ID_TXT_SEARCH 203
#define ID_BTN_SEARCH 204
#define ID_RAD_ALL  205
#define ID_RAD_32BIT  206
#define ID_RAD_64BIT  207
#define ID_PIC_FINDER 208

// 全局句柄与变量
HWND hLog;
HWND hTxtDll;
HWND hTxtProc;
HWND hProcDlg = NULL;
HWND hModDlg = NULL;
HINSTANCE g_hInst;

wchar_t g_injectDllPath[MAX_PATH] = L"";
wchar_t g_freeDllName[MAX_PATH] = L"";
int g_currentMode = ID_RAD_INJECT;

extern "C" {
    #pragma function(memset)
    void* __cdecl memset(void* p, int c, size_t n) {
        unsigned char* s = (unsigned char*)p;
        while (n--) *s++ = (unsigned char)c;
        return p;
    }
}

void* MemAlloc(size_t size) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}
void MemFree(void* ptr) {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

struct DwordList {
    DWORD* data;
    size_t count;
    size_t capacity;

    void push_back(DWORD val) {
        if (count >= capacity) {
            size_t newCap = capacity == 0 ? 16 : capacity * 2;
            DWORD* newData = (DWORD*)MemAlloc(newCap * sizeof(DWORD));
            if (data) {
                for (size_t i = 0; i < count; ++i) newData[i] = data[i];
                MemFree(data);
            }
            data = newData;
            capacity = newCap;
        }
        data[count++] = val;
    }
    void clear() {
        if (data) MemFree(data);
        data = NULL;
        count = capacity = 0;
    }
};

struct ProcInfo {
    DWORD pid;
    DWORD ppid;
    wchar_t name[MAX_PATH];
    const wchar_t* arch;
    DwordList children;
};

ProcInfo* g_procMap = NULL;
size_t g_procCount = 0;
size_t g_procCap = 0;

void AddProcInfo(const ProcInfo& info) {
    if (g_procCount >= g_procCap) {
        size_t newCap = g_procCap == 0 ? 64 : g_procCap * 2;
        ProcInfo* newData = (ProcInfo*)MemAlloc(newCap * sizeof(ProcInfo));
        if (g_procMap) {
            for (size_t i = 0; i < g_procCount; ++i) newData[i] = g_procMap[i];
            MemFree(g_procMap);
        }
        g_procMap = newData;
        g_procCap = newCap;
    }
    g_procMap[g_procCount++] = info;
}

ProcInfo* FindProcInfo(DWORD pid) {
    for (size_t i = 0; i < g_procCount; ++i) {
        if (g_procMap[i].pid == pid) return &g_procMap[i];
    }
    return NULL;
}

void ClearProcMap() {
    for (size_t i = 0; i < g_procCount; ++i) g_procMap[i].children.clear();
    if (g_procMap) MemFree(g_procMap);
    g_procMap = NULL;
    g_procCount = g_procCap = 0;
}

DwordList g_rootProcs = {0};

DWORD my_wtol(const wchar_t* str) {
    DWORD res = 0;
    while (*str >= L'0' && *str <= L'9') {
        res = res * 10 + (*str - L'0');
        str++;
    }
    return res;
}

bool StartsWith(const wchar_t* str, const wchar_t* prefix) {
    while (*prefix) {
        if (*prefix++ != *str++) return false;
    }
    return true;
}

const wchar_t* GetProcessArch(DWORD processID) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID);
    if (!hProcess) return L"(?)";
    
    BOOL bIsWow64 = FALSE;
    if (IsWow64Process(hProcess, &bIsWow64)) {
        CloseHandle(hProcess);
        if (bIsWow64) return L"(32-bit)";
        else return L"(64-bit)";
    }
    CloseHandle(hProcess);
    return L"(?)";
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
}

bool IsDll64Bit(const wchar_t* dllPath, bool& is64Bit) {
    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        return false;
    }

    void* pView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pView) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    bool success = false;
    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pView;
    if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)((BYTE*)pView + pDos->e_lfanew);
        if (pNt->Signature == IMAGE_NT_SIGNATURE) {
            WORD machine = pNt->FileHeader.Machine;
            if (machine == IMAGE_FILE_MACHINE_AMD64 || machine == IMAGE_FILE_MACHINE_IA64) {
                is64Bit = true;
                success = true;
            } else if (machine == IMAGE_FILE_MACHINE_I386) {
                is64Bit = false;
                success = true;
            }
        }
    }

    UnmapViewOfFile(pView);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return success;
}

bool IsTargetProcess32Bit(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;
    BOOL bIsWow64 = FALSE;
    if (IsWow64Process(hProcess, &bIsWow64)) {
        CloseHandle(hProcess);
        return bIsWow64 != FALSE;
    }
    CloseHandle(hProcess);
    return false;
}

bool ExtractAndRun32BitInjector(DWORD targetPid, const wchar_t* dllPath, bool isFree) {
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(1001), L"EXE");
    if (!hRes) return false;
    
    HGLOBAL hMem = LoadResource(NULL, hRes);
    if (!hMem) return false;
    
    DWORD resSize = SizeofResource(NULL, hRes);
    void* pResData = LockResource(hMem);
    if (!pResData) return false;

    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    
    wchar_t helperExePath[MAX_PATH];
    wsprintfW(helperExePath, L"%sinj32_helper_%lu.exe", tempPath, GetCurrentProcessId());

    HANDLE hFile = CreateFileW(helperExePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(hFile, pResData, resSize, &bytesWritten, NULL);
        CloseHandle(hFile);
    } else {
        return false;
    }

    wchar_t cmdLine[MAX_PATH * 2];
    wsprintfW(cmdLine, L"\"%s\" %lu \"%s\" %d", helperExePath, targetPid, dllPath, isFree ? 1 : 0);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    bool success = false;
    
    if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        success = (exitCode == 0);
        
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    DeleteFileW(helperExePath);

    return success;
}

void BuildProcTree() {
    ClearProcMap();
    g_rootProcs.clear();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                ProcInfo info = {0};
                info.pid = pe.th32ProcessID;
                info.ppid = pe.th32ParentProcessID;
                lstrcpyW(info.name, pe.szExeFile);
                info.arch = GetProcessArch(pe.th32ProcessID);
                AddProcInfo(info);
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    
    for (size_t i = 0; i < g_procCount; ++i) {
        DWORD ppid = g_procMap[i].ppid;
        ProcInfo* pParent = FindProcInfo(ppid);
        if (ppid != 0 && pParent != NULL) {
            pParent->children.push_back(g_procMap[i].pid);
        } else {
            g_rootProcs.push_back(g_procMap[i].pid);
        }
    }
}

// 递归查找某个节点及其子节点是否包含符合关键字的项
bool NodeContainsMatch(DWORD pid, const wchar_t* filter) {
    ProcInfo* pInfo = FindProcInfo(pid);
    if (!pInfo) return false;

    bool passText = true;
    if (filter && filter[0] != L'\0') {
        passText = false;
        if (StrStrIW(pInfo->name, filter) != NULL) {
            passText = true;
        }
    }

    if (passText) return true;

    for (size_t i = 0; i < pInfo->children.count; ++i) {
        if (NodeContainsMatch(pInfo->children.data[i], filter)) return true;
    }
    return false;
}

void PopulateTreeViewRecursive(HWND hTree, HTREEITEM hParent, DWORD pid, const wchar_t* filter, bool shouldExpand) {
    ProcInfo* pInfo = FindProcInfo(pid);
    if (!pInfo) return;
    
    wchar_t entryText[MAX_PATH + 64];
    wsprintfW(entryText, L"%s (PID: %lu) %s", pInfo->name, pInfo->pid, pInfo->arch);

    TVINSERTSTRUCTW tvis = { 0 };
    tvis.hParent = hParent;
    tvis.hInsertAfter = TVI_LAST;
    tvis.item.mask = TVIF_TEXT | TVIF_PARAM;
    tvis.item.pszText = entryText;
    tvis.item.lParam = (LPARAM)pInfo->pid;

    HTREEITEM hItem = (HTREEITEM)SendMessageW(hTree, TVM_INSERTITEM, 0, (LPARAM)&tvis);

    for (size_t i = 0; i < pInfo->children.count; ++i) {
        DWORD childId = pInfo->children.data[i];
        if (!filter || filter[0] == L'\0') {
            PopulateTreeViewRecursive(hTree, hItem, childId, filter, true); 
        } else {
            if (NodeContainsMatch(childId, filter)) {
                PopulateTreeViewRecursive(hTree, hItem, childId, filter, true); 
            }
        }
    }

    if (shouldExpand) {
        SendMessage(hTree, TVM_EXPAND, TVE_EXPAND, (LPARAM)hItem);
    }
}

void RefreshTreeView(HWND hwnd) {
    HWND hTree = GetDlgItem(hwnd, ID_LST_PROCS);
    SendMessage(hTree, TVM_DELETEITEM, 0, (LPARAM)TVI_ROOT);

    wchar_t kw[256] = { 0 };
    GetWindowTextW(GetDlgItem(hwnd, ID_TXT_SEARCH), kw, 256);

    BuildProcTree();

    for (size_t i = 0; i < g_rootProcs.count; ++i) {
        DWORD rid = g_rootProcs.data[i];
        if (kw[0] == L'\0') {
            PopulateTreeViewRecursive(hTree, TVI_ROOT, rid, kw, true);
        } else {
            if (NodeContainsMatch(rid, kw)) {
                PopulateTreeViewRecursive(hTree, TVI_ROOT, rid, kw, true);
            }
        }
    }
}

void DrawInvertBorder(HWND hwndTarget) {
    if (!IsWindow(hwndTarget)) return;
    HDC hdc = GetWindowDC(hwndTarget);
    if (!hdc) return;
    RECT rc;
    GetWindowRect(hwndTarget, &rc);
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;
    int thickness = 3;
    PatBlt(hdc, 0, 0, width, thickness, DSTINVERT);
    PatBlt(hdc, 0, height - thickness, width, thickness, DSTINVERT);
    PatBlt(hdc, 0, thickness, thickness, height - 2 * thickness, DSTINVERT);
    PatBlt(hdc, width - thickness, thickness, thickness, height - 2 * thickness, DSTINVERT);
    ReleaseDC(hwndTarget, hdc);
}

WNDPROC g_OldFinderProc = NULL;
LRESULT CALLBACK FinderWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static BOOL bDragging = FALSE;
    static HWND hPrevHighlighted = NULL;
    static HCURSOR hCursorCross = NULL;
    if (!hCursorCross) hCursorCross = LoadCursor(NULL, IDC_CROSS);

    switch (msg) {
        case WM_LBUTTONDOWN:
            bDragging = TRUE;
            SetCapture(hwnd);
            SetCursor(hCursorCross);
            return 0;
            
        case WM_MOUSEMOVE:
            if (bDragging) {
                SetCursor(hCursorCross);
                POINT pt;
                GetCursorPos(&pt);
                HWND hTarget = WindowFromPoint(pt);
                if (hTarget && hTarget != hPrevHighlighted) {
                    if (hPrevHighlighted) {
                        DrawInvertBorder(hPrevHighlighted); // 恢复旧的
                    }
                    if (hTarget) {
                        DrawInvertBorder(hTarget); // 高亮新的
                    }
                    hPrevHighlighted = hTarget;
                }
            }
            break;
            
        case WM_LBUTTONUP:
            if (bDragging) {
                bDragging = FALSE;
                ReleaseCapture();
                
                if (hPrevHighlighted) {
                    DrawInvertBorder(hPrevHighlighted); // 删除最后的高亮
                    hPrevHighlighted = NULL;
                }

                POINT pt;
                GetCursorPos(&pt);
                HWND hTarget = WindowFromPoint(pt);
                if (hTarget) {
                    DWORD pid = 0;
                    GetWindowThreadProcessId(hTarget, &pid);
                    if (pid > 0) {
                        SendMessage(GetParent(hwnd), WM_APP + 2, pid, 0);
                    }
                }
                SetCursor(LoadCursor(NULL, IDC_ARROW));
            }
            return 0;
    }
    return CallWindowProcW(g_OldFinderProc, hwnd, msg, wParam, lParam);
}

#define ID_LST_MODS 301
#define ID_BTN_SEL_MOD 302

// 模块选择子窗口的回调函数
LRESULT CALLBACK ModDlgWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HWND hOwner = GetWindow(hwnd, GW_OWNER);
            if (hOwner) {
                // 让新窗口在父窗口（主界面）上方居中显示
                RECT rcOwner, rcDlg;
                GetWindowRect(hOwner, &rcOwner);
                GetWindowRect(hwnd, &rcDlg);
                int dlgWidth = rcDlg.right - rcDlg.left;
                int dlgHeight = rcDlg.bottom - rcDlg.top;
                int x = rcOwner.left + (rcOwner.right - rcOwner.left - dlgWidth) / 2;
                int y = rcOwner.top + (rcOwner.bottom - rcOwner.top - dlgHeight) / 2;
                SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOZORDER);
            }

            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            HWND hList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTBOX, L"",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | LBS_NOTIFY,
                10, 10, 420, 260, hwnd, (HMENU)ID_LST_MODS, g_hInst, NULL);
                
            CreateWindowW(L"BUTTON", L"Select Module", WS_CHILD | WS_VISIBLE,
                180, 280, 100, 30, hwnd, (HMENU)ID_BTN_SEL_MOD, NULL, NULL);

            EnumChildWindows(hwnd, [](HWND child, LPARAM font) -> BOOL {
                SendMessage(child, WM_SETFONT, font, TRUE);
                return TRUE;
            }, (LPARAM)hFont);

            wchar_t szPid[256] = {0};
            GetWindowTextW(hTxtProc, szPid, 256);
            DWORD pid = my_wtol(szPid);
            
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (hSnap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W me;
                me.dwSize = sizeof(MODULEENTRY32W);
                if (Module32FirstW(hSnap, &me)) {
                    do {
                        SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)me.szModule);
                    } while (Module32NextW(hSnap, &me));
                }
                CloseHandle(hSnap);
            } else {
                SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)L"[Error] Could not read modules (Access Denied / Invalid PID).");
            }
            break;
        }
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            int wmEvent = HIWORD(wParam);

            if (wmId == ID_LST_MODS && wmEvent == LBN_DBLCLK) {
                SendMessage(hwnd, WM_COMMAND, ID_BTN_SEL_MOD, 0);
            }
            else if (wmId == ID_BTN_SEL_MOD) {
                HWND hList = GetDlgItem(hwnd, ID_LST_MODS);
                int idx = (int)SendMessage(hList, LB_GETCURSEL, 0, 0);
                if (idx != LB_ERR) {
                    wchar_t szMod[MAX_PATH] = { 0 };
                    SendMessageW(hList, LB_GETTEXT, idx, (LPARAM)szMod);
                    if (!StartsWith(szMod, L"[Error]")) {
                        SetWindowTextW(hTxtDll, szMod);
                    }
                }
                SendMessage(hwnd, WM_CLOSE, 0, 0);
            }
            break;
        }
        case WM_CLOSE: {
            DestroyWindow(hwnd);
            break;
        }
        case WM_DESTROY: {
            HWND hOwner = GetWindow(hwnd, GW_OWNER);
            if (hOwner) {
                EnableWindow(hOwner, TRUE);
                SetForegroundWindow(hOwner);
            }
            hModDlg = NULL;
            break;
        }
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// 进程选择子窗口的回调函数
LRESULT CALLBACK ProcDlgWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // 让新窗口在父窗口（主界面）上方居中显示
            HWND hOwner = GetWindow(hwnd, GW_OWNER);
            if (hOwner) {
                RECT rcOwner, rcDlg;
                GetWindowRect(hOwner, &rcOwner);
                GetWindowRect(hwnd, &rcDlg);
                int dlgWidth = rcDlg.right - rcDlg.left;
                int dlgHeight = rcDlg.bottom - rcDlg.top;
                int x = rcOwner.left + (rcOwner.right - rcOwner.left - dlgWidth) / 2;
                int y = rcOwner.top + (rcOwner.bottom - rcOwner.top - dlgHeight) / 2;
                SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOZORDER);
            }

            // 确保加载了公共控件类
            INITCOMMONCONTROLSEX icex;
            icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
            icex.dwICC = ICC_TREEVIEW_CLASSES;
            InitCommonControlsEx(&icex);

            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            // Filter tools
            CreateWindowW(L"STATIC", L"Filter:", WS_CHILD | WS_VISIBLE | SS_RIGHT, 10, 12, 40, 20, hwnd, NULL, NULL, NULL);
            CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 60, 10, 310, 22, hwnd, (HMENU)ID_TXT_SEARCH, NULL, NULL);
            HWND hFinder = CreateWindowW(L"STATIC", L"[+ Pick Target]", WS_CHILD | WS_VISIBLE | SS_CENTER | SS_NOTIFY | WS_BORDER, 380, 10, 100, 22, hwnd, (HMENU)ID_PIC_FINDER, NULL, NULL);
            g_OldFinderProc = (WNDPROC)SetWindowLongPtrW(hFinder, GWLP_WNDPROC, (LONG_PTR)FinderWndProc);
            
            // 创建真正的 TreeView 控件替代之前的 ListBox
            HWND hTree = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEW, L"",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS | TVS_SHOWSELALWAYS,
                10, 40, 480, 310, hwnd, (HMENU)ID_LST_PROCS, g_hInst, NULL);
            
            // 创建确认按钮
            CreateWindowW(L"BUTTON", L"Select", WS_CHILD | WS_VISIBLE,
                200, 360, 100, 30, hwnd, (HMENU)ID_BTN_SEL_PROC, NULL, NULL);
                
            EnumChildWindows(hwnd, [](HWND child, LPARAM font) -> BOOL {
                SendMessage(child, WM_SETFONT, font, TRUE);
                return TRUE;
            }, (LPARAM)hFont);

            RefreshTreeView(hwnd);
            break;
        }
        case WM_APP + 2: {
            DWORD pid = (DWORD)wParam;
            if (g_procCount == 0) {
                BuildProcTree();
            }
            ProcInfo* pInfo = FindProcInfo(pid);
            if (pInfo != NULL) {
                SetWindowTextW(GetDlgItem(hwnd, ID_TXT_SEARCH), pInfo->name);
            }
            break;
        }
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            int wmEvent = HIWORD(wParam);

            if (wmId == ID_TXT_SEARCH && wmEvent == EN_CHANGE) {
                RefreshTreeView(hwnd);
            }
            else if (wmId == ID_BTN_SEL_PROC) {
                HWND hTree = GetDlgItem(hwnd, ID_LST_PROCS);
                HTREEITEM hSelected = (HTREEITEM)SendMessage(hTree, TVM_GETNEXTITEM, TVGN_CARET, 0);
                if (hSelected) {
                    TVITEMW tvi = { 0 };
                    tvi.mask = TVIF_PARAM;
                    tvi.hItem = hSelected;
                    SendMessage(hTree, TVM_GETITEM, 0, (LPARAM)&tvi);
                    
                    DWORD pid = (DWORD)tvi.lParam;
                    wchar_t szPidStr[64];
                    wsprintfW(szPidStr, L"%lu", pid);
                    SetWindowTextW(hTxtProc, szPidStr);
                }
                SendMessage(hwnd, WM_CLOSE, 0, 0);
            }
            break;
        }
        case WM_NOTIFY: {
            break;
        }
        case WM_CLOSE: {
            DestroyWindow(hwnd);
            break;
        }
        case WM_DESTROY: {
            HWND hOwner = GetWindow(hwnd, GW_OWNER);
            if (hOwner) {
                EnableWindow(hOwner, TRUE);
                SetForegroundWindow(hOwner);
            }
            hProcDlg = NULL;
            break;
        }
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}


LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // 1. Operation: 
            HWND hLblOp = CreateWindowW(L"STATIC", L"Operation:", WS_CHILD | WS_VISIBLE | SS_RIGHT, 40, 50, 100, 20, hwnd, NULL, NULL, NULL);
            HWND hRadInj = CreateWindowW(L"BUTTON", L"Inject DLL", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP, 145, 50, 80, 20, hwnd, (HMENU)ID_RAD_INJECT, NULL, NULL);
            HWND hRadFree = CreateWindowW(L"BUTTON", L"Free DLL", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON, 235, 50, 80, 20, hwnd, (HMENU)ID_RAD_FREE, NULL, NULL);
            SendMessage(hRadInj, BM_SETCHECK, BST_CHECKED, 0); // 默认选中 Inject

            // 2. Target Process: (Moved up)
            HWND hLblTarget = CreateWindowW(L"STATIC", L"Target Process:", WS_CHILD | WS_VISIBLE | SS_RIGHT, 40, 85, 100, 20, hwnd, NULL, NULL, NULL);
            hTxtProc = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 145, 85, 230, 22, hwnd, (HMENU)ID_TXT_PROC, NULL, NULL);
            CreateWindowW(L"BUTTON", L"...", WS_CHILD | WS_VISIBLE, 380, 85, 30, 22, hwnd, (HMENU)ID_BTN_PROC, NULL, NULL);

            // 3. DLL Name: (Moved up)
            HWND hLblDll = CreateWindowW(L"STATIC", L"DLL Name:", WS_CHILD | WS_VISIBLE | SS_RIGHT, 40, 120, 100, 20, hwnd, NULL, NULL, NULL);
            hTxtDll = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 145, 120, 230, 22, hwnd, (HMENU)ID_TXT_DLL, NULL, NULL);
            CreateWindowW(L"BUTTON", L"...", WS_CHILD | WS_VISIBLE, 380, 120, 30, 22, hwnd, (HMENU)ID_BTN_DLL, NULL, NULL);
            // 开启 Cue Banner 显示占位符
            SendMessageW(hTxtDll, EM_SETCUEBANNER, (WPARAM)TRUE, (LPARAM)L"<Drag & Drop your DLL here>");

            // 4. Inject Button (居中)
            CreateWindowW(L"BUTTON", L"Inject DLL", WS_CHILD | WS_VISIBLE, 190, 165, 100, 30, hwnd, (HMENU)ID_BTN_ACTION, NULL, NULL);

            // 5. Log Area (多行 Edit)
            hLog = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 30, 215, 400, 255, hwnd, (HMENU)ID_TXT_LOG, NULL, NULL);

            // Enable drag drop
            DragAcceptFiles(hwnd, TRUE);

            // 统一设置所有子窗口的字体为现代 GUI 字体 (Segoe UI)
            HFONT hModernFont = CreateFontW(-12, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS, L"Segoe UI");
            if (!hModernFont) hModernFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT); // Fallback

            EnumChildWindows(hwnd, [](HWND child, LPARAM font) -> BOOL {
                SendMessage(child, WM_SETFONT, font, TRUE);
                return TRUE;
            }, (LPARAM)hModernFont);
            
            break;
        }
        case WM_DROPFILES: {
            // 处理接收到的拖放文件
            HDROP hDrop = (HDROP)wParam;
            wchar_t filePath[MAX_PATH] = { 0 };
            
            // 获取拖拽的第一个文件的路径
            if (DragQueryFileW(hDrop, 0, filePath, MAX_PATH) > 0) {
                // 将文件路径设置到 DLL Name 的 Edit 控件中
                SetWindowTextW(hTxtDll, filePath);
                
                // 向日志写入拖拽事件记录
                wchar_t logBuf[MAX_PATH + 64];
                wsprintfW(logBuf, L"[*] File dropped: %s\r\n", filePath);
                int len = GetWindowTextLength(hLog);
                SendMessage(hLog, EM_SETSEL, len, len);
                SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)logBuf);
            }
            
            // 释放由系统分配的拖放结构内存
            DragFinish(hDrop);
            break;
        }
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            switch (wmId) {
                case ID_RAD_INJECT: {
                    if (g_currentMode == ID_RAD_FREE) {
                        wchar_t szDll[MAX_PATH] = {0};
                        GetWindowTextW(hTxtDll, szDll, MAX_PATH);
                        lstrcpyW(g_freeDllName, szDll);
                        SetWindowTextW(hTxtDll, g_injectDllPath);
                        g_currentMode = ID_RAD_INJECT;
                    }
                    SetWindowTextW(GetDlgItem(hwnd, ID_BTN_ACTION), L"Inject DLL");
                    break;
                }
                case ID_RAD_FREE: {
                    if (g_currentMode == ID_RAD_INJECT) {
                        wchar_t szDll[MAX_PATH] = {0};
                        GetWindowTextW(hTxtDll, szDll, MAX_PATH);
                        lstrcpyW(g_injectDllPath, szDll);
                        SetWindowTextW(hTxtDll, g_freeDllName);
                        g_currentMode = ID_RAD_FREE;
                    }
                    SetWindowTextW(GetDlgItem(hwnd, ID_BTN_ACTION), L"Free DLL");
                    break;
                }
                case ID_BTN_ACTION: {
                    wchar_t szPid[256] = {0};
                    GetWindowTextW(hTxtProc, szPid, 256);
                    DWORD pid = my_wtol(szPid);
                    
                    wchar_t szDll[MAX_PATH] = {0};
                    GetWindowTextW(hTxtDll, szDll, MAX_PATH);
                    
                    if (pid == 0 || szDll[0] == L'\0') {
                        MessageBoxW(hwnd, L"Please select a valid Target Process and DLL.", L"Error", MB_ICONERROR);
                        break;
                    }

                    if (SendMessage(GetDlgItem(hwnd, ID_RAD_FREE), BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        wchar_t logBuf[1024];
                        wsprintfW(logBuf, L"[*] Attempting to Free DLL: %s from PID %lu...\r\n", szDll, pid);
                        int len = GetWindowTextLength(hLog);
                        SendMessage(hLog, EM_SETSEL, len, len);
                        SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)logBuf);
                        
                        bool isDll64 = false;
                        if (!IsDll64Bit(szDll, isDll64)) {
                            wsprintfW(logBuf, L"[-] Error: Invalid DLL file or cannot determine architecture.\r\n");
                            int len = GetWindowTextLength(hLog);
                            SendMessage(hLog, EM_SETSEL, len, len);
                            SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)logBuf);
                            break;
                        }

                        bool isTarget32 = IsTargetProcess32Bit(pid);
                        if ((isTarget32 && isDll64) || (!isTarget32 && !isDll64)) {
                            wsprintfW(logBuf, L"[-] Error: Architecture Mismatch! Target Process is %ls, but DLL is %ls.\r\n", isTarget32 ? L"32-bit" : L"64-bit", isDll64 ? L"64-bit" : L"32-bit");
                            int len = GetWindowTextLength(hLog);
                            SendMessage(hLog, EM_SETSEL, len, len);
                            SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)logBuf);
                            break;
                        }
                        
                        bool success = false;
                        if (isTarget32) {
                            success = ExtractAndRun32BitInjector(pid, szDll, true);
                        } else {
                            success = FreeRemoteDLL(pid, szDll);
                        }

                        if (success) {
                            wsprintfW(logBuf, L"[+] Successfully freed DLL module!\r\n");
                        } else {
                            wsprintfW(logBuf, L"[-] Failed to free DLL module. It may not exist in the target process, or access was denied.\r\n");
                        }
                        len = GetWindowTextLength(hLog);
                        SendMessage(hLog, EM_SETSEL, len, len);
                        SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)logBuf);
                    } else {
                        wchar_t logBuf[1024];
                        wsprintfW(logBuf, L"[*] Attempting to Inject DLL: %s into PID %lu...\r\n", szDll, pid);
                        int len = GetWindowTextLength(hLog);
                        SendMessage(hLog, EM_SETSEL, len, len);
                        SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)logBuf);

                        bool isDll64 = false;
                        if (!IsDll64Bit(szDll, isDll64)) {
                            wsprintfW(logBuf, L"[-] Error: Invalid DLL file or cannot determine architecture.\r\n");
                            int len = GetWindowTextLength(hLog);
                            SendMessage(hLog, EM_SETSEL, len, len);
                            SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)logBuf);
                            break;
                        }

                        bool isTarget32 = IsTargetProcess32Bit(pid);
                        if ((isTarget32 && isDll64) || (!isTarget32 && !isDll64)) {
                            wsprintfW(logBuf, L"[-] Error: Architecture Mismatch! Target Process is %ls, but DLL is %ls.\r\n", isTarget32 ? L"32-bit" : L"64-bit", isDll64 ? L"64-bit" : L"32-bit");
                            int len = GetWindowTextLength(hLog);
                            SendMessage(hLog, EM_SETSEL, len, len);
                            SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)logBuf);
                            break;
                        }

                        bool success = false;
                        if (isTarget32) {
                            success = ExtractAndRun32BitInjector(pid, szDll, false);
                        } else {
                            // We only use CreateRemoteThread now natively
                            success = InjectRemoteDLL_CRT(pid, szDll);
                        }

                        if (success) {
                            wsprintfW(logBuf, L"[+] Successfully injected DLL module!\r\n");
                        } else {
                            wsprintfW(logBuf, L"[-] Failed to inject DLL module. Check architectures, paths and access rights.\r\n");
                        }
                        len = GetWindowTextLength(hLog);
                        SendMessage(hLog, EM_SETSEL, len, len);
                        SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)logBuf);
                    }
                    break;
                }

                case ID_BTN_PROC: {
                    if (hProcDlg == NULL) {
                        EnableWindow(hwnd, FALSE);
                        hProcDlg = CreateWindowW(
                            L"ProcListDlg", L"Select Target Process",
                            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                            CW_USEDEFAULT, CW_USEDEFAULT, 520, 440,
                            hwnd, NULL, g_hInst, NULL
                        );
                    }
                    else {
                        SetForegroundWindow(hProcDlg);
                    }
                    break;
                }
                case ID_BTN_DLL: {
                    if (SendMessage(GetDlgItem(hwnd, ID_RAD_INJECT), BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        wchar_t szFile[MAX_PATH] = { 0 };
                        OPENFILENAMEW ofn = { 0 };
                        ofn.lStructSize = sizeof(ofn);
                        ofn.hwndOwner = hwnd;
                        ofn.lpstrFile = szFile;
                        ofn.nMaxFile = MAX_PATH;
                        ofn.lpstrFilter = L"DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
                        ofn.nFilterIndex = 1;
                        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
                        if (GetOpenFileNameW(&ofn)) {
                            SetWindowTextW(hTxtDll, szFile);
                        }
                    } else {
                        wchar_t szPid[256] = {0};
                        GetWindowTextW(hTxtProc, szPid, 256);
                        if (szPid[0] == L'\0') {
                            MessageBoxW(hwnd, L"Please select a Target Process first.", L"Warning", MB_ICONWARNING);
                            break;
                        }
                        if (hModDlg == NULL) {
                            EnableWindow(hwnd, FALSE);
                            hModDlg = CreateWindowW(
                                L"ModListDlg", L"Select Loaded Module",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                                CW_USEDEFAULT, CW_USEDEFAULT, 460, 360,
                                hwnd, NULL, g_hInst, NULL
                            );
                        } else {
                            SetForegroundWindow(hModDlg);
                        }
                    }
                    break;
                }
            }
            break;
        }
        case WM_DESTROY:
            if (hProcDlg) DestroyWindow(hProcDlg);
            if (hModDlg) DestroyWindow(hModDlg);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    g_hInst = hInstance;
    
    // 注册主窗口类
    const wchar_t CLASS_NAME[] = L"TestInjectorUI";
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(1));
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW);
    RegisterClassW(&wc);

    // 注册进程选择子窗口类
    const wchar_t DLG_CLASS_NAME[] = L"ProcListDlg";
    WNDCLASSW wcDlg = {};
    wcDlg.lpfnWndProc = ProcDlgWndProc;
    wcDlg.hInstance = hInstance;
    wcDlg.lpszClassName = DLG_CLASS_NAME;
    wcDlg.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcDlg.hbrBackground = (HBRUSH)(COLOR_WINDOW);
    RegisterClassW(&wcDlg);

    const wchar_t MOD_DLG_CLASS_NAME[] = L"ModListDlg";
    WNDCLASSW wcModDlg = {};
    wcModDlg.lpfnWndProc = ModDlgWndProc;
    wcModDlg.hInstance = hInstance;
    wcModDlg.lpszClassName = MOD_DLG_CLASS_NAME;
    wcModDlg.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcModDlg.hbrBackground = (HBRUSH)(COLOR_WINDOW);
    RegisterClassW(&wcModDlg);

    // 注意：在这里添加了 WS_EX_ACCEPTFILES 扩展样式以允许接受拖拽释放的文件
    HWND hwnd = CreateWindowExW(
        WS_EX_ACCEPTFILES,
        CLASS_NAME, L"Phantom DLL Injector - Professional Edition",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 480, 540,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}

void __stdcall WinMainCRTStartup() {
    HINSTANCE hInstance = GetModuleHandleW(NULL);
    int ret = WinMain(hInstance, NULL, GetCommandLineA(), SW_SHOWDEFAULT);
    ExitProcess(ret);
}
