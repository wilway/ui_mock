@echo off

echo [*] Building 32-bit Test DLL...
call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
cl.exe /nologo /O1 /GS- /W3 /D_UNICODE /DUNICODE test_dll.cpp User32.lib Kernel32.lib /LD /link /NODEFAULTLIB /ENTRY:DllMain /OUT:test32.dll
if %errorlevel% neq 0 (
    echo [!] Failed to compile 32-bit DLL.
    exit /b 1
)

echo [*] Building 64-bit Test DLL...
call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /nologo /O1 /GS- /W3 /D_UNICODE /DUNICODE test_dll.cpp User32.lib Kernel32.lib /LD /link /NODEFAULTLIB /ENTRY:DllMain /OUT:test64.dll
if %errorlevel% neq 0 (
    echo [!] Failed to compile 64-bit DLL.
    exit /b 1
)

echo [*] Successfully created test32.dll and test64.dll!
