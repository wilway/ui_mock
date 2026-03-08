@echo off
call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
cl.exe /nologo /O1 /GS- /W3 /D_UNICODE /DUNICODE inj32.cpp User32.lib Kernel32.lib Shell32.lib Advapi32.lib /link /NODEFAULTLIB /ENTRY:wmainCRTStartup /SUBSYSTEM:WINDOWS /OUT:inj32.exe
