#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    wchar_t msg[256];
    DWORD pid = GetCurrentProcessId();
    
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Disable thread library calls for optimization
        DisableThreadLibraryCalls(hModule);
        
        #ifdef _WIN64
            wsprintfW(msg, L"=======================================\n[TestDLL 64-bit] -> INJECTED SUCCESSFULLY!\n Target PID: %lu\n=======================================\n", pid);
        #else
            wsprintfW(msg, L"=======================================\n[TestDLL 32-bit] -> INJECTED SUCCESSFULLY!\n Target PID: %lu\n=======================================\n", pid);
        #endif
        
        OutputDebugStringW(msg);
        break;
        
    case DLL_PROCESS_DETACH:
        #ifdef _WIN64
            wsprintfW(msg, L"=======================================\n[TestDLL 64-bit] -> FREED SUCCESSFULLY!\n Target PID: %lu\n=======================================\n", pid);
        #else
            wsprintfW(msg, L"=======================================\n[TestDLL 32-bit] -> FREED SUCCESSFULLY!\n Target PID: %lu\n=======================================\n", pid);
        #endif
        
        OutputDebugStringW(msg);
        break;
    }
    return TRUE;
}
