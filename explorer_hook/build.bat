@echo off
setlocal

set MODE=%1
if "%MODE%"=="" set MODE=release

echo [+] Building in %MODE% mode...

if not exist bin mkdir bin
if not exist obj\x86 mkdir obj\x86
if not exist obj\x64 mkdir obj\x64

if /I "%MODE%"=="debug" (
    set OPTS=/nologo /Od /MTd /Zi /GS- /D_DEBUG /D_UNICODE /DUNICODE /W3
    set LOPTS=/INCREMENTAL:NO /DEBUG
) else (
    set OPTS=/nologo /O2 /MT /GS- /DNDEBUG /D_UNICODE /DUNICODE /W3
    set LOPTS=/INCREMENTAL:NO /OPT:REF /OPT:ICF
)

set LIBS=User32.lib Kernel32.lib Advapi32.lib Shell32.lib Shlwapi.lib

REM ========================================================
REM [1/3] 编译 x86 组件
REM ========================================================
echo [*] Building x86...
call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x86

echo [*] Compiling inj32.exe...
cl.exe %OPTS% /Fo"obj/x86/" injector_base.cpp %LIBS% /link %LOPTS% /NODEFAULTLIB /ENTRY:wmainCRTStartup /SUBSYSTEM:WINDOWS /OUT:"bin/inj32.exe"
if %errorlevel% neq 0 exit /b 1

echo [*] Compiling monitor32.dll...
cl.exe %OPTS% /LD /Fo"obj/x86/" /I"../minhook/include" monitor_dll.cpp ../minhook/src/buffer.c ../minhook/src/hook.c ../minhook/src/trampoline.c ../minhook/src/hde/hde32.c %LIBS% /link %LOPTS% /OUT:"bin/monitor32.dll"
if %errorlevel% neq 0 exit /b 1

REM ========================================================
REM [2/3] 编译 x64 组件
REM ========================================================
echo.
echo [*] Building x64...
call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

echo [*] Compiling inj64.exe...
cl.exe %OPTS% /Fo"obj/x64/" injector_base.cpp %LIBS% /link %LOPTS% /NODEFAULTLIB /ENTRY:wmainCRTStartup /SUBSYSTEM:WINDOWS /OUT:"bin/inj64.exe"
if %errorlevel% neq 0 exit /b 1

echo [*] Compiling monitor64.dll...
cl.exe %OPTS% /LD /Fo"obj/x64/" /I"../minhook/include" monitor_dll.cpp ../minhook/src/buffer.c ../minhook/src/hook.c ../minhook/src/trampoline.c ../minhook/src/hde/hde64.c %LIBS% /link %LOPTS% /OUT:"bin/monitor64.dll"
if %errorlevel% neq 0 exit /b 1

REM ========================================================
REM [3/3] 编译 Launcher
REM ========================================================
echo.
echo [*] Building Launcher...
rc.exe /nologo /fo"obj/resource.res" resource.rc
cl.exe %OPTS% /Fo"obj/" demo.cpp obj/resource.res %LIBS% /link %LOPTS% /SUBSYSTEM:WINDOWS /OUT:"bin/demo.exe"
if %errorlevel% neq 0 exit /b 1

echo.
echo [SUCCESS] All components built successfully in bin/
pause
