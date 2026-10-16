@echo off
setlocal enabledelayedexpansion
echo ============================================
echo   Compiling Packet Analyzer (Java Edition)
echo ============================================

set "JAVAC_CMD=javac"
where javac >nul 2>&1
if %ERRORLEVEL% neq 0 (
    if exist "C:\Program Files\JetBrains\IntelliJ IDEA 2025.2.5\jbr\bin\javac.exe" (
        set "JAVAC_CMD=C:\Program Files\JetBrains\IntelliJ IDEA 2025.2.5\jbr\bin\javac.exe"
    )
)

if not exist bin mkdir bin

dir /s /b src\main\java\*.java > sources.txt
"%JAVAC_CMD%" -d bin @sources.txt
set COMPILE_RES=%ERRORLEVEL%
del sources.txt

if %COMPILE_RES% equ 0 (
    echo [SUCCESS] Compilation successful! Classes compiled to bin\
) else (
    echo [ERROR] Compilation failed!
    exit /b %COMPILE_RES%
)
