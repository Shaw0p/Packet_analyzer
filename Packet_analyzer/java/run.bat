@echo off
setlocal
set "JAVA_CMD=java"
if exist "C:\Program Files\JetBrains\IntelliJ IDEA 2025.2.5\jbr\bin\java.exe" (
    set "JAVA_CMD=C:\Program Files\JetBrains\IntelliJ IDEA 2025.2.5\jbr\bin\java.exe"
)

if not exist bin (
    echo Bin folder not found. Compiling first...
    call compile.bat
)

"%JAVA_CMD%" -cp bin com.dpianalyzer.Main %*
