@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "ROOT_PROJECT=%SCRIPT_DIR%Packet_analyzer"

if not exist "%ROOT_PROJECT%\java\bin" (
    echo Compiling Java code...
    call "%ROOT_PROJECT%\compile_java.bat"
)

set "JAVA_CMD=java"
if exist "C:\Program Files\JetBrains\IntelliJ IDEA 2025.2.5\jbr\bin\java.exe" (
    set "JAVA_CMD=C:\Program Files\JetBrains\IntelliJ IDEA 2025.2.5\jbr\bin\java.exe"
)

pushd "%ROOT_PROJECT%"
"%JAVA_CMD%" -cp "java\bin" com.dpianalyzer.Main %*
popd
