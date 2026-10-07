@echo off
setlocal
rem 32-bit (x86) toolchain
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat" >nul
if errorlevel 1 (
    echo [ERROR] vcvars32.bat failed
    exit /b 1
)
rem /MT: static CRT, no MSVCP140.dll / VCRUNTIME140.dll dependency
cl /nologo /utf-8 /std:c++17 /EHsc /O2 /W3 /MT /DUNICODE /D_UNICODE main.cpp /Fe:NanLiangQuiz.exe /link /SUBSYSTEM:WINDOWS
if errorlevel 1 (
    echo [ERROR] build failed
    exit /b 1
)
echo [OK] NanLiangQuiz.exe (x86, static CRT)
