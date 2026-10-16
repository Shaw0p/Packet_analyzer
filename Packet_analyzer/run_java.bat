@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "JAVA_CMD=java"
if exist "C:\Program Files\JetBrains\IntelliJ IDEA 2025.2.5\jbr\bin\java.exe" (
    set "JAVA_CMD=C:\Program Files\JetBrains\IntelliJ IDEA 2025.2.5\jbr\bin\java.exe"
)

if not exist "%SCRIPT_DIR%java\bin" (
    echo Compiling Java code first...
    call "%SCRIPT_DIR%compile_java.bat"
)

"%JAVA_CMD%" -cp "%SCRIPT_DIR%java\bin" com.dpianalyzer.Main %*
