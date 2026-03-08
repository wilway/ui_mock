@echo off
echo [*] Compiling inj32.exe (32-bit)...
cmd /c build32.bat

if %errorlevel% neq 0 (
    echo [!] Failed to compile 32-bit injector.
    pause
    exit /b 1
)

echo [*] Setting up Visual Studio Environment for x64...
call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

echo [*] Compiling resources...
rc.exe /nologo resource.rc

echo [*] Compiling ui_mock.cpp...
cl.exe /nologo /O1 /GS- /W3 /D_UNICODE /DUNICODE ui_mock.cpp resource.res User32.lib Gdi32.lib Shell32.lib Advapi32.lib Kernel32.lib Comctl32.lib Comdlg32.lib Shlwapi.lib /link /NODEFAULTLIB /ENTRY:WinMainCRTStartup /SUBSYSTEM:WINDOWS

if %errorlevel% neq 0 (
    echo [!] Compilation failed.
) else (
    echo [*] Compilation successful. Output: ui_mock.exe
)

pause
