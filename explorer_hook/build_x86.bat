@echo off
rem build_x86.bat - 用于编译 32 位组件
call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"

echo [*] Compiling inj32.exe...
cl.exe /nologo /O1 /GS- /W3 /D_UNICODE /DUNICODE injector_base.cpp User32.lib Kernel32.lib Shell32.lib Advapi32.lib /link /NODEFAULTLIB /ENTRY:wmainCRTStartup /SUBSYSTEM:WINDOWS /OUT:inj32.exe

echo [*] Compiling monitor32.dll...
cl.exe /nologo /O1 /LD /W3 /D_UNICODE /DUNICODE /I"../minhook/include" monitor_dll.cpp ../minhook/src/buffer.c ../minhook/src/hook.c ../minhook/src/trampoline.c ../minhook/src/hde/hde32.c User32.lib Kernel32.lib Advapi32.lib /link /INCREMENTAL:NO /OUT:monitor32.dll
